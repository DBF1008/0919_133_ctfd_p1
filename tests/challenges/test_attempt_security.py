#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from unittest.mock import Mock, patch

from CTFd.plugins.challenges.logic import (
    challenge_attempt_all,
    challenge_attempt_any,
    challenge_attempt_team,
)
from CTFd.utils import set_config
from CTFd.utils.security import ratelimit as ratelimit_module
from CTFd.utils.security.ratelimit import (
    consume_flag_submission_token,
    get_flag_submission_ratelimit_config,
)
from tests.helpers import (
    create_ctfd,
    destroy_ctfd,
    gen_challenge,
    gen_fail,
    gen_flag,
    gen_user,
    login_as_user,
    register_user,
)


def _clear_buckets():
    ratelimit_module._LOCAL_BUCKETS.clear()


def test_ratelimit_config_from_env():
    """Token bucket limit/window are configurable via environment variables"""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("FLAG_SUBMISSION_RATE_LIMIT", None)
        os.environ.pop("FLAG_SUBMISSION_RATE_WINDOW", None)
        assert get_flag_submission_ratelimit_config() == (10, 60)

    with patch.dict(
        os.environ,
        {"FLAG_SUBMISSION_RATE_LIMIT": "3", "FLAG_SUBMISSION_RATE_WINDOW": "120"},
    ):
        assert get_flag_submission_ratelimit_config() == (3, 120)

    # Invalid values fall back to defaults
    with patch.dict(
        os.environ,
        {"FLAG_SUBMISSION_RATE_LIMIT": "abc", "FLAG_SUBMISSION_RATE_WINDOW": "xyz"},
    ):
        assert get_flag_submission_ratelimit_config() == (10, 60)


def test_token_bucket_allows_limit_then_blocks():
    """Token bucket allows `limit` submissions then rejects until refill"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        env = {"FLAG_SUBMISSION_RATE_LIMIT": "3", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env):
            for _ in range(3):
                assert consume_flag_submission_token(1, 1) is True
            assert consume_flag_submission_token(1, 1) is False
            assert consume_flag_submission_token(1, 1) is False
        _clear_buckets()
    destroy_ctfd(app)


def test_token_bucket_isolated_per_user_and_challenge():
    """Buckets are independent per (account, challenge) pair"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        env = {"FLAG_SUBMISSION_RATE_LIMIT": "1", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env):
            assert consume_flag_submission_token(1, 1) is True
            # Same user, same challenge -> blocked
            assert consume_flag_submission_token(1, 1) is False
            # Different user, same challenge -> allowed
            assert consume_flag_submission_token(2, 1) is True
            # Same user, different challenge -> allowed
            assert consume_flag_submission_token(1, 2) is True
        _clear_buckets()
    destroy_ctfd(app)


def test_token_bucket_refills_over_window():
    """Tokens refill at limit/window tokens per second"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        env = {"FLAG_SUBMISSION_RATE_LIMIT": "2", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        fake_time = Mock()
        fake_time.time.return_value = 1000.0
        with patch.dict(os.environ, env), patch.object(
            ratelimit_module, "time", fake_time
        ):
            assert consume_flag_submission_token(1, 1) is True
            assert consume_flag_submission_token(1, 1) is True
            assert consume_flag_submission_token(1, 1) is False
            # Half the window passes -> one token refills
            fake_time.time.return_value = 1030.0
            assert consume_flag_submission_token(1, 1) is True
            assert consume_flag_submission_token(1, 1) is False
            # Full window from start -> bucket is capped at capacity
            fake_time.time.return_value = 1060.0
            assert consume_flag_submission_token(1, 1) is True
            assert consume_flag_submission_token(1, 1) is False
        _clear_buckets()
    destroy_ctfd(app)


def test_token_bucket_disabled_with_nonpositive_limit():
    """A non-positive limit disables rate limiting"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        env = {"FLAG_SUBMISSION_RATE_LIMIT": "0", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env):
            for _ in range(50):
                assert consume_flag_submission_token(1, 1) is True
        _clear_buckets()
    destroy_ctfd(app)


def test_token_bucket_uses_redis_when_configured():
    """When a redis client is available the Lua token bucket path is used"""
    app = create_ctfd()
    with app.app_context():
        fake_redis = Mock()
        fake_redis.eval.side_effect = [1, 0]
        env = {"FLAG_SUBMISSION_RATE_LIMIT": "5", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env), patch.object(
            ratelimit_module, "_get_redis_client", return_value=fake_redis
        ):
            assert consume_flag_submission_token(7, 9) is True
            assert consume_flag_submission_token(7, 9) is False
            assert fake_redis.eval.call_count == 2
            # Script, numkeys, key, capacity, refill_rate, now, ttl
            args = fake_redis.eval.call_args[0]
            assert args[1] == 1  # numkeys
            assert "flag_submission_bucket:7:9" in args[2]
            assert args[3] == 5  # capacity
    destroy_ctfd(app)


def test_token_bucket_falls_back_to_local_without_redis():
    """Without redis the in-process bucket is used"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        env = {"FLAG_SUBMISSION_RATE_LIMIT": "1", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env), patch.object(
            ratelimit_module, "_get_redis_client", return_value=None
        ):
            assert consume_flag_submission_token(1, 1) is True
            assert consume_flag_submission_token(1, 1) is False
        _clear_buckets()
    destroy_ctfd(app)


def test_logic_layer_enforces_max_attempts_any():
    """challenge_attempt_any rejects attempts beyond max_attempts (lockout)"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        user = gen_user(app.db, name="locked_out_user")
        chal = gen_challenge(app.db, max_attempts=2)
        flags = [gen_flag(app.db, challenge_id=chal.id, content="flag{test}")]

        with patch(
            "CTFd.plugins.challenges.logic.get_current_user", return_value=user
        ):
            gen_fail(app.db, user_id=user.id, challenge_id=chal.id)
            resp = challenge_attempt_any("wrong", chal, flags)
            assert resp.status == "incorrect"

            gen_fail(app.db, user_id=user.id, challenge_id=chal.id)
            resp = challenge_attempt_any("wrong", chal, flags)
            assert resp.status == "ratelimited"
            assert "0 tries remaining" in resp.message

            # Even the correct flag is rejected once locked out
            resp = challenge_attempt_any("flag{test}", chal, flags)
            assert resp.status == "ratelimited"
        _clear_buckets()
    destroy_ctfd(app)


def test_logic_layer_enforces_max_attempts_all():
    """challenge_attempt_all rejects attempts beyond max_attempts (lockout)"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        user = gen_user(app.db, name="locked_out_user_all")
        chal = gen_challenge(app.db, max_attempts=1, logic="all")
        flags = [gen_flag(app.db, challenge_id=chal.id, content="flag{test}")]

        with patch(
            "CTFd.plugins.challenges.logic.get_current_user", return_value=user
        ):
            resp = challenge_attempt_all("wrong", chal, flags)
            assert resp.status == "incorrect"

            gen_fail(app.db, user_id=user.id, challenge_id=chal.id)
            resp = challenge_attempt_all("wrong", chal, flags)
            assert resp.status == "ratelimited"
        _clear_buckets()
    destroy_ctfd(app)


def test_logic_layer_enforces_max_attempts_team():
    """challenge_attempt_team rejects attempts beyond max_attempts (lockout)"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        user = gen_user(app.db, name="locked_out_user_team")
        chal = gen_challenge(app.db, max_attempts=1, logic="team")
        flags = [gen_flag(app.db, challenge_id=chal.id, content="flag{test}")]

        with patch(
            "CTFd.plugins.challenges.logic.get_current_user", return_value=user
        ):
            resp = challenge_attempt_team("wrong", chal, flags)
            assert resp.status == "incorrect"

            gen_fail(app.db, user_id=user.id, challenge_id=chal.id)
            resp = challenge_attempt_team("wrong", chal, flags)
            assert resp.status == "ratelimited"
        _clear_buckets()
    destroy_ctfd(app)


def test_logic_layer_enforces_max_attempts_timeout_behavior():
    """Logic layer respects the max_attempts timeout behavior"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        set_config("max_attempts_behavior", "timeout")
        set_config("max_attempts_timeout", 300)
        user = gen_user(app.db, name="timeout_user")
        chal = gen_challenge(app.db, max_attempts=1)
        flags = [gen_flag(app.db, challenge_id=chal.id, content="flag{test}")]

        with patch(
            "CTFd.plugins.challenges.logic.get_current_user", return_value=user
        ):
            resp = challenge_attempt_any("wrong", chal, flags)
            assert resp.status == "incorrect"

            gen_fail(app.db, user_id=user.id, challenge_id=chal.id)
            resp = challenge_attempt_any("wrong", chal, flags)
            assert resp.status == "ratelimited"
            assert "Try again in" in resp.message
        _clear_buckets()
    destroy_ctfd(app)


def test_logic_layer_rate_limits_flag_submissions():
    """challenge_attempt_any is rate limited per user per challenge"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        user = gen_user(app.db, name="fast_user")
        other = gen_user(app.db, name="other_user", email="other@examplectf.com")
        chal = gen_challenge(app.db)
        other_chal = gen_challenge(app.db, name="other_chal")
        flags = [gen_flag(app.db, challenge_id=chal.id, content="flag{test}")]

        env = {"FLAG_SUBMISSION_RATE_LIMIT": "2", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env), patch(
            "CTFd.plugins.challenges.logic.get_current_user", return_value=user
        ):
            assert challenge_attempt_any("wrong", chal, flags).status == "incorrect"
            assert challenge_attempt_any("wrong", chal, flags).status == "incorrect"
            # Bucket exhausted for this user on this challenge
            resp = challenge_attempt_any("wrong", chal, flags)
            assert resp.status == "ratelimited"
            # Even a correct submission is rejected while rate limited
            resp = challenge_attempt_any("flag{test}", chal, flags)
            assert resp.status == "ratelimited"
            # A different challenge still has tokens
            assert challenge_attempt_any("wrong", other_chal, []).status == "incorrect"

        # A different user still has tokens on the original challenge
        with patch.dict(os.environ, env), patch(
            "CTFd.plugins.challenges.logic.get_current_user", return_value=other
        ):
            assert challenge_attempt_any("wrong", chal, flags).status == "incorrect"
        _clear_buckets()
    destroy_ctfd(app)


def test_api_attempt_returns_429_when_logic_layer_ratelimits():
    """The API surfaces logic-layer rate limiting as a 429 ratelimited response"""
    app = create_ctfd()
    with app.app_context():
        _clear_buckets()
        register_user(app)
        client = login_as_user(app)
        chal = gen_challenge(app.db)
        gen_flag(app.db, challenge_id=chal.id, content="flag{test}")

        env = {"FLAG_SUBMISSION_RATE_LIMIT": "2", "FLAG_SUBMISSION_RATE_WINDOW": "60"}
        with patch.dict(os.environ, env):
            for _ in range(2):
                r = client.post(
                    "/api/v1/challenges/attempt",
                    json={"challenge_id": chal.id, "submission": "wrong"},
                )
                assert r.status_code == 200
                assert r.get_json()["data"]["status"] == "incorrect"

            r = client.post(
                "/api/v1/challenges/attempt",
                json={"challenge_id": chal.id, "submission": "wrong"},
            )
            assert r.status_code == 429
            assert r.get_json()["data"]["status"] == "ratelimited"
        _clear_buckets()
    destroy_ctfd(app)

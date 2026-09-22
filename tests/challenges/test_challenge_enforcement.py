#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Tests that submission limits are enforced in the challenge logic layer.

These limits must hold even if a hypothetical new entrypoint calls the logic
functions directly instead of going through /api/v1/challenges/attempt.
"""

import pytest

from CTFd.exceptions.challenges import (
    ChallengeFlagRateLimitException,
    ChallengeMaxAttemptsException,
)
from CTFd.models import Flags, Users
from CTFd.plugins.challenges.logic import (
    challenge_attempt_all,
    challenge_attempt_any,
)
from CTFd.utils import set_config
from CTFd.utils.security import flag_rate_limit as frl
from CTFd.utils.security.auth import login_user
from tests.helpers import (
    create_ctfd,
    destroy_ctfd,
    gen_challenge,
    gen_fail,
    gen_flag,
    register_user,
)


def _login_as(app, user_id=2):
    user = Users.query.filter_by(id=user_id).first()
    login_user(user)
    return user


def test_max_attempts_lockout_enforced_in_logic_layer():
    """Calling the logic function directly must respect max_attempts."""
    app = create_ctfd()
    with app.app_context():
        register_user(app)
        chal = gen_challenge(app.db)
        chal.max_attempts = 2
        app.db.session.commit()
        gen_flag(app.db, challenge_id=chal.id, content="flag")

        user = Users.query.filter_by(id=2).first()
        gen_fail(app.db, user_id=user.id, challenge_id=chal.id)
        gen_fail(app.db, user_id=user.id, challenge_id=chal.id)

        flags = Flags.query.filter_by(challenge_id=chal.id).all()
        with app.test_request_context("/"):
            _login_as(app)
            with pytest.raises(ChallengeMaxAttemptsException) as exc:
                challenge_attempt_any("flag", chal, flags)
            assert exc.value.status_code == 403
            assert "0 tries remaining" in exc.value.message
    destroy_ctfd(app)


def test_max_attempts_timeout_enforced_in_logic_layer():
    app = create_ctfd()
    with app.app_context():
        set_config("max_attempts_behavior", "timeout")
        set_config("max_attempts_timeout", 300)

        register_user(app)
        chal = gen_challenge(app.db)
        chal.max_attempts = 1
        app.db.session.commit()
        gen_flag(app.db, challenge_id=chal.id, content="flag")

        user = Users.query.filter_by(id=2).first()
        gen_fail(app.db, user_id=user.id, challenge_id=chal.id)

        flags = Flags.query.filter_by(challenge_id=chal.id).all()
        with app.test_request_context("/"):
            _login_as(app)
            with pytest.raises(ChallengeMaxAttemptsException) as exc:
                challenge_attempt_any("flag", chal, flags)
            assert exc.value.status_code == 429
            assert "Try again" in exc.value.message
    destroy_ctfd(app)


def test_flag_rate_limit_enforced_in_logic_layer(monkeypatch):
    app = create_ctfd()
    with app.app_context():
        monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
        monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "2")
        monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "60")
        frl.reset_flag_ratelimit()

        register_user(app)
        chal = gen_challenge(app.db)
        gen_flag(app.db, challenge_id=chal.id, content="flag")
        flags = Flags.query.filter_by(challenge_id=chal.id).all()

        with app.test_request_context("/"):
            _login_as(app)
            challenge_attempt_any("wrong", chal, flags)
            challenge_attempt_any("wrong", chal, flags)
            with pytest.raises(ChallengeFlagRateLimitException) as exc:
                challenge_attempt_any("flag", chal, flags)
            assert exc.value.status_code == 429
    destroy_ctfd(app)


def test_admin_bypasses_logic_layer_limits(monkeypatch):
    app = create_ctfd()
    with app.app_context():
        monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
        monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
        monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "1")
        frl.reset_flag_ratelimit()

        chal = gen_challenge(app.db)
        chal.max_attempts = 1
        app.db.session.commit()
        gen_flag(app.db, challenge_id=chal.id, content="flag")

        admin = Users.query.filter_by(id=1).first()
        gen_fail(app.db, user_id=admin.id, challenge_id=chal.id)

        flags = Flags.query.filter_by(challenge_id=chal.id).all()
        with app.test_request_context("/?preview=true"):
            _login_as(app, user_id=1)
            response = challenge_attempt_any("flag", chal, flags)
            assert response.status == "correct"
    destroy_ctfd(app)


def test_max_attempts_enforced_in_all_logic_entrypoint():
    """The "all flags" logic function must enforce max_attempts too."""
    app = create_ctfd()
    with app.app_context():
        register_user(app)
        chal = gen_challenge(app.db)
        chal.max_attempts = 1
        app.db.session.commit()
        gen_flag(app.db, challenge_id=chal.id, content="flag")

        user = Users.query.filter_by(id=2).first()
        gen_fail(app.db, user_id=user.id, challenge_id=chal.id)

        flags = Flags.query.filter_by(challenge_id=chal.id).all()
        with app.test_request_context("/"):
            _login_as(app)
            with pytest.raises(ChallengeMaxAttemptsException):
                challenge_attempt_all("flag", chal, flags)
    destroy_ctfd(app)

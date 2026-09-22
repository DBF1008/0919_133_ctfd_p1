#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest

from CTFd.exceptions.challenges import (
    ChallengeFlagRateLimitException,
)
from CTFd.utils.security import flag_rate_limit as frl
from tests.helpers import create_ctfd, destroy_ctfd


@pytest.fixture
def app_ctx():
    app = create_ctfd()
    with app.app_context():
        frl.reset_flag_ratelimit()
        yield
    destroy_ctfd(app)


def test_token_bucket_burst_then_refill(app_ctx, monkeypatch):
    """Capacity requests are allowed; the next is rejected until refill."""
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "3")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "60")  # 1 token/sec

    for _ in range(3):
        frl.consume_flag_submission(account_id=2, challenge_id=1)

    with pytest.raises(ChallengeFlagRateLimitException) as exc:
        frl.consume_flag_submission(account_id=2, challenge_id=1)
    assert exc.value.status_code == 429
    assert exc.value.retry_after >= 1


def test_token_bucket_independent_buckets(app_ctx, monkeypatch):
    """Limits apply independently per account and per challenge."""
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "60")

    # account 2 exhausts challenge 1
    frl.consume_flag_submission(account_id=2, challenge_id=1)
    with pytest.raises(ChallengeFlagRateLimitException):
        frl.consume_flag_submission(account_id=2, challenge_id=1)

    # different challenge is unaffected
    frl.consume_flag_submission(account_id=2, challenge_id=2)

    # different account is unaffected
    frl.consume_flag_submission(account_id=3, challenge_id=1)


def test_token_bucket_refills(app_ctx, monkeypatch):
    """Tokens are replenished according to the configured rate."""
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "600")  # 10 tokens/sec

    frl.consume_flag_submission(account_id=2, challenge_id=1)
    with pytest.raises(ChallengeFlagRateLimitException):
        frl.consume_flag_submission(account_id=2, challenge_id=1)

    # Wait for more than one token to accrue
    frl.time.sleep(0.15)
    frl.consume_flag_submission(account_id=2, challenge_id=1)


def test_ratelimit_disabled_by_default(app_ctx, monkeypatch):
    """The limiter is opt-in and does nothing unless enabled."""
    monkeypatch.delenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", raising=False)
    assert frl.is_flag_ratelimit_enabled() is False
    for _ in range(100):
        frl.consume_flag_submission(account_id=2, challenge_id=1)


def test_ratelimit_explicit_disable(app_ctx, monkeypatch):
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "false")
    monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "1")
    assert frl.is_flag_ratelimit_enabled() is False
    for _ in range(10):
        frl.consume_flag_submission(account_id=2, challenge_id=1)


def test_zero_rate_disables(app_ctx, monkeypatch):
    """A non-positive refill rate disables limiting entirely."""
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "0")
    assert frl.is_flag_ratelimit_enabled() is False
    for _ in range(10):
        frl.consume_flag_submission(account_id=2, challenge_id=1)


def test_admin_is_not_rate_limited(app_ctx, monkeypatch):
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "1")

    class FakeUser:
        type = "admin"
        account_id = 1

    class FakeChallenge:
        id = 1

    for _ in range(10):
        frl.enforce_flag_submission_rate_limit(
            user=FakeUser(), challenge=FakeChallenge()
        )


def test_reset_clears_counters(app_ctx, monkeypatch):
    monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
    monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "1")

    frl.consume_flag_submission(account_id=2, challenge_id=1)
    with pytest.raises(ChallengeFlagRateLimitException):
        frl.consume_flag_submission(account_id=2, challenge_id=1)

    frl.reset_flag_ratelimit()
    frl.consume_flag_submission(account_id=2, challenge_id=1)

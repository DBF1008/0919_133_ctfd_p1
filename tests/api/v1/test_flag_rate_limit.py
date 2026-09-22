#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API integration tests for the per-account/per-challenge flag submission
token bucket.
"""

from CTFd.models import Ratelimiteds
from CTFd.utils.security import flag_rate_limit as frl
from tests.helpers import (
    create_ctfd,
    destroy_ctfd,
    gen_challenge,
    gen_flag,
    login_as_user,
    register_user,
)


def test_attempt_endpoint_token_bucket(monkeypatch):
    app = create_ctfd()
    with app.app_context():
        monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
        monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "3")
        monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "60")
        frl.reset_flag_ratelimit()

        register_user(app)
        client = login_as_user(app)
        chal = gen_challenge(app.db)
        gen_flag(app.db, challenge_id=chal.id, content="flag")

        for _ in range(3):
            r = client.post(
                "/api/v1/challenges/attempt",
                json={"challenge_id": chal.id, "submission": "wrong"},
            )
            assert r.status_code == 200

        r = client.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal.id, "submission": "flag"},
        )
        assert r.status_code == 429
        data = r.get_json()["data"]
        assert data["status"] == "ratelimited"
        assert "Try again" in data["message"]
        assert Ratelimiteds.query.count() == 1
    destroy_ctfd(app)


def test_token_bucket_isolated_per_challenge(monkeypatch):
    app = create_ctfd()
    with app.app_context():
        monkeypatch.setenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "true")
        monkeypatch.setenv("FLAG_SUBMISSIONS_BUCKET_SIZE", "1")
        monkeypatch.setenv("FLAG_SUBMISSIONS_PER_MINUTE", "60")
        frl.reset_flag_ratelimit()

        register_user(app)
        client = login_as_user(app)
        chal1 = gen_challenge(app.db, name="c1")
        chal2 = gen_challenge(app.db, name="c2")
        gen_flag(app.db, challenge_id=chal1.id, content="flag1")
        gen_flag(app.db, challenge_id=chal2.id, content="flag2")

        r = client.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal1.id, "submission": "wrong"},
        )
        assert r.status_code == 200

        r = client.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal1.id, "submission": "wrong"},
        )
        assert r.status_code == 429

        # Other challenge has its own bucket and is still available
        r = client.post(
            "/api/v1/challenges/attempt",
            json={"challenge_id": chal2.id, "submission": "wrong"},
        )
        assert r.status_code == 200
    destroy_ctfd(app)

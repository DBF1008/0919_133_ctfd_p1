"""
Per-account, per-challenge token bucket rate limiting for flag submissions.

The legacy ``ratelimit`` decorator only keys on the client IP address, so an
attacker spreading requests across machines (or simply spoofing X-Forwarded-For)
can trivially bypass it while brute forcing flags.  This module instead keys
the limit on the submitting account id and the challenge id and implements a
proper token bucket:

* ``FLAG_SUBMISSIONS_PER_MINUTE``   - bucket refill rate (tokens/minute)
* ``FLAG_SUBMISSIONS_BUCKET_SIZE``  - maximum burst (window) size in tokens
* ``FLAG_SUBMISSION_RATELIMIT_ENABLED`` - on/off switch

The limiter is disabled by default for backwards compatibility; set
``FLAG_SUBMISSION_RATELIMIT_ENABLED=true`` in the deployment environment to
enable it (``FLAG_SUBMISSIONS_PER_MINUTE=0`` always disables it).

The counters are stored in Redis (via the same connection flask-caching uses)
and the consume operation runs atomically in a Lua script, so the limit holds
for multi-worker / multi-machine deployments.  When Redis is not configured
(simple/filesystem cache, e.g. unit tests) a process-local fallback is used.
"""

import math
import os
import threading
import time

from flask import current_app

from CTFd.cache import cache
from CTFd.exceptions.challenges import ChallengeFlagRateLimitException

KEY_PREFIX = "flag_rl"

# Token bucket Lua script.
#
# KEYS[1] = bucket key
# ARGV[1] = capacity (burst size)
# ARGV[2] = refill tokens per second
# ARGV[3] = tokens requested
# ARGV[4] = current unix time (seconds, float)
#
# Returns {allowed (0/1), tokens remaining, retry_after seconds (int)}
_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'updated')
local tokens = tonumber(data[1])
local updated = tonumber(data[2])
if tokens == nil then
    tokens = capacity
end
if updated == nil then
    updated = now
end

local refill = (now - updated) * refill_rate
tokens = math.min(capacity, tokens + refill)

local allowed = 0
local retry_after = 0
if tokens >= requested then
    tokens = tokens - requested
    allowed = 1
else
    retry_after = math.ceil((requested - tokens) / refill_rate)
end

redis.call('HSET', key, 'tokens', tokens, 'updated', now)
-- Keep keys around for at most the time needed to refill an empty bucket
redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) + 1)

return {allowed, tokens, retry_after}
"""


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def is_flag_ratelimit_enabled():
    """Whether per-account/per-challenge flag rate limiting is active."""
    enabled = os.getenv("FLAG_SUBMISSION_RATELIMIT_ENABLED", "false").lower()
    if enabled not in ("1", "true", "yes", "on"):
        return False
    return get_flag_ratelimit_rate_per_second() > 0


def get_flag_ratelimit_bucket_size():
    """Maximum burst size (tokens) for the flag submission bucket."""
    size = _env_int("FLAG_SUBMISSIONS_BUCKET_SIZE", 5)
    return max(size, 1)


def get_flag_ratelimit_rate_per_second():
    """Refill rate in tokens per second (0 disables the limiter)."""
    rate_per_minute = _env_int("FLAG_SUBMISSIONS_PER_MINUTE", 10)
    if rate_per_minute <= 0:
        return 0
    return rate_per_minute / 60.0


def flag_ratelimit_key(account_id, challenge_id):
    return "{}:{}:{}".format(KEY_PREFIX, account_id, challenge_id)


# Process-local fallback state used when Redis is not configured.
# This is only correct for single-process/test deployments; multi-worker
# deployments must configure Redis. reset_flag_ratelimit() clears the state
# between test runs.
_memory_buckets = {}
_memory_lock = threading.Lock()


def reset_flag_ratelimit():
    """Clear all in-process fallback counters (used by tests)."""
    with _memory_lock:
        _memory_buckets.clear()


def _is_redis_backend():
    try:
        return current_app.config["CACHE_TYPE"] == "redis"
    except RuntimeError:
        return False


def _consume_redis(key, capacity, refill_rate, requested=1):
    redis_client = cache.cache._write_client
    prefix = getattr(cache.cache, "key_prefix", "") or ""
    script = redis_client.register_script(_TOKEN_BUCKET_LUA)
    allowed, _tokens, retry_after = script(
        keys=["{}{}".format(prefix, key)],
        args=[str(capacity), str(refill_rate), str(requested), str(time.time())],
    )
    return bool(int(allowed)), max(int(retry_after), 1)


def _consume_memory(key, capacity, refill_rate, requested=1):
    now = time.time()
    with _memory_lock:
        bucket = _memory_buckets.get(key)
        if bucket is None:
            tokens, updated = float(capacity), now
        else:
            tokens, updated = bucket

        tokens = min(float(capacity), tokens + (now - updated) * refill_rate)

        if tokens >= requested:
            _memory_buckets[key] = (tokens - requested, now)
            return True, 0

        retry_after = math.ceil((requested - tokens) / refill_rate)
        _memory_buckets[key] = (tokens, now)
        return False, max(retry_after, 1)


def consume_flag_submission(account_id, challenge_id):
    """
    Consume one token from the flag submission bucket for an account/challenge.

    :raises ChallengeFlagRateLimitException: when the bucket is empty
    """
    if is_flag_ratelimit_enabled() is False:
        return

    capacity = get_flag_ratelimit_bucket_size()
    refill_rate = get_flag_ratelimit_rate_per_second()
    if refill_rate <= 0:
        return

    key = flag_ratelimit_key(account_id, challenge_id)
    if _is_redis_backend():
        allowed, retry_after = _consume_redis(key, capacity, refill_rate)
    else:
        allowed, retry_after = _consume_memory(key, capacity, refill_rate)

    if allowed is False:
        raise ChallengeFlagRateLimitException(
            message=(
                "You're submitting flags too fast. Try again in {} seconds.".format(
                    retry_after
                )
            ),
            retry_after=retry_after,
        )


def enforce_flag_submission_rate_limit(user, challenge):
    """
    Enforce the per-account/per-challenge token bucket before evaluating a
    flag submission. Admins are never rate limited.
    """
    if user is None or getattr(user, "type", None) == "admin":
        return
    if is_flag_ratelimit_enabled() is False:
        return
    consume_flag_submission(account_id=user.account_id, challenge_id=challenge.id)

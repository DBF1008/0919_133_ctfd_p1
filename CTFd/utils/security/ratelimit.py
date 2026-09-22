"""
Per-account, per-challenge token bucket rate limiting for flag submissions.

Unlike CTFd.utils.decorators.ratelimit (which keys on IP address and can be
bypassed by distributing requests across machines), this module keys the
limiter on (account_id, challenge_id) so that flag brute-forcing is limited
regardless of how many source IPs the attacker controls.

Configuration is read from environment variables at call time:

    FLAG_SUBMISSION_RATE_LIMIT  - bucket capacity / max submissions per window
                                  (default 10, <= 0 disables limiting)
    FLAG_SUBMISSION_RATE_WINDOW - refill window in seconds; the bucket fully
                                  refills over this period (default 60)

Storage backends:

    * Redis - used automatically when CACHE_TYPE == "redis" so that the
      counters are shared across multiple workers/processes. The bucket is
      updated atomically via a Lua script.
    * In-process memory - fallback for single-process deployments without
      Redis. Note that with multiple workers and no Redis each process gets
      its own bucket.
"""

import os
import threading
import time

from flask import current_app

from CTFd.cache import cache

DEFAULT_FLAG_SUBMISSION_RATE_LIMIT = 10
DEFAULT_FLAG_SUBMISSION_RATE_WINDOW = 60

_LOCAL_BUCKETS = {}
_LOCAL_BUCKETS_LOCK = threading.Lock()

# Atomically refill and consume from a token bucket stored as a Redis hash.
# KEYS[1]: bucket key
# ARGV[1]: capacity, ARGV[2]: refill rate (tokens/sec), ARGV[3]: now, ARGV[4]: ttl
_TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
    tokens = capacity
    ts = now
end
tokens = math.min(capacity, tokens + (now - ts) * refill_rate)
local allowed = 0
if tokens >= 1 then
    tokens = tokens - 1
    allowed = 1
end
redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, ttl)
return allowed
"""


def get_flag_submission_ratelimit_config():
    """
    Read (limit, window) from the environment, falling back to defaults on
    missing or invalid values.
    """
    try:
        limit = int(
            os.environ.get(
                "FLAG_SUBMISSION_RATE_LIMIT", DEFAULT_FLAG_SUBMISSION_RATE_LIMIT
            )
        )
    except (TypeError, ValueError):
        limit = DEFAULT_FLAG_SUBMISSION_RATE_LIMIT
    try:
        window = int(
            os.environ.get(
                "FLAG_SUBMISSION_RATE_WINDOW", DEFAULT_FLAG_SUBMISSION_RATE_WINDOW
            )
        )
    except (TypeError, ValueError):
        window = DEFAULT_FLAG_SUBMISSION_RATE_WINDOW
    return limit, window


def _get_redis_client():
    try:
        if current_app.config.get("CACHE_TYPE") == "redis":
            return cache.cache._write_client
    except RuntimeError:
        # Outside of an application context
        pass
    return None


def _consume_token_redis(client, key, limit, window):
    prefix = getattr(cache.cache, "key_prefix", "") or ""
    refill_rate = float(limit) / float(window)
    now = time.time()
    # The bucket fully refills after `window` seconds of inactivity so the
    # key can safely expire shortly afterwards.
    ttl = int(window) + 1
    allowed = client.eval(
        _TOKEN_BUCKET_LUA, 1, f"{prefix}{key}", limit, refill_rate, now, ttl
    )
    return int(allowed) == 1


def _consume_token_local(key, limit, window):
    refill_rate = float(limit) / float(window)
    now = time.time()
    with _LOCAL_BUCKETS_LOCK:
        tokens, ts = _LOCAL_BUCKETS.get(key, (float(limit), now))
        tokens = min(float(limit), tokens + (now - ts) * refill_rate)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        _LOCAL_BUCKETS[key] = (tokens, now)
        # Opportunistically prune stale buckets to bound memory usage
        if len(_LOCAL_BUCKETS) > 10000:
            cutoff = now - window
            for stale_key in [k for k, v in _LOCAL_BUCKETS.items() if v[1] < cutoff]:
                del _LOCAL_BUCKETS[stale_key]
    return allowed


def consume_flag_submission_token(account_id, challenge_id):
    """
    Attempt to consume a single flag-submission token for the given account
    and challenge. Returns True if the submission is allowed to proceed and
    False if the account has exhausted its token bucket for this challenge.
    """
    limit, window = get_flag_submission_ratelimit_config()
    if limit <= 0 or window <= 0:
        return True
    key = "flag_submission_bucket:{}:{}".format(account_id, challenge_id)
    client = _get_redis_client()
    if client is not None:
        return _consume_token_redis(client, key, limit, window)
    return _consume_token_local(key, limit, window)

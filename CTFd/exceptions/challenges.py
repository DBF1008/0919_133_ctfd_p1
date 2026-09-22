class ChallengeCreateException(Exception):
    pass


class ChallengeUpdateException(Exception):
    pass


class ChallengeSolveException(Exception):
    pass


class ChallengeMaxAttemptsException(Exception):
    """
    Raised by the challenge logic layer when an account has exhausted
    the configured number of attempts for a challenge.

    Enforcing this at the logic layer ensures that attempts submitted
    through any entrypoint (not only the REST API) cannot bypass
    max_attempts.
    """

    def __init__(
        self,
        message="Not accepted. You have 0 tries remaining",
        status_code=403,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ChallengeFlagRateLimitException(Exception):
    """
    Raised by the challenge logic layer when an account exceeds the
    per-challenge token bucket flag submission rate limit.

    The counters live in Redis so that the limit is enforced correctly
    across multiple workers/machines.
    """

    def __init__(
        self,
        message="Too many flag submissions. Please slow down.",
        retry_after=1,
    ):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after
        self.status_code = 429

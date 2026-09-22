from datetime import datetime, timedelta

from CTFd.exceptions.challenges import ChallengeMaxAttemptsException
from CTFd.models import Fails, Partials
from CTFd.plugins.flags import FlagException, get_flag_class
from CTFd.utils import get_config
from CTFd.utils.config import is_teams_mode
from CTFd.utils.security.flag_rate_limit import enforce_flag_submission_rate_limit
from CTFd.utils.user import get_current_team, get_current_user


def _check_max_attempts(user, challenge):
    """
    Enforce a challenge's max_attempts at the logic layer.

    Historically this check only lived in CTFd/api/v1/challenges.py, so any
    new entrypoint that called the logic functions directly could bypass the
    attempt limit entirely. Raising here guarantees the limit holds regardless
    of which entrypoint is used.

    Admins are exempt.
    """
    if user is None or getattr(user, "type", None) == "admin":
        return

    max_tries = challenge.max_attempts
    if not max_tries or max_tries <= 0:
        return

    max_attempts_behavior = get_config("max_attempts_behavior", "lockout")
    if max_attempts_behavior == "timeout":
        max_attempts_timeout = int(get_config("max_attempts_timeout", 300))
        timeout_delta = timedelta(seconds=-max_attempts_timeout)
        recent_fails = (
            Fails.query.filter_by(account_id=user.account_id, challenge_id=challenge.id)
            .filter(Fails.date >= datetime.utcnow() + timeout_delta)
            .order_by(Fails.id.asc())
            .all()
        )
        if len(recent_fails) >= max_tries:
            retry_after = max_attempts_timeout
            if recent_fails:
                retry_after -= int(
                    (datetime.utcnow() - recent_fails[0].date).total_seconds()
                )
            raise ChallengeMaxAttemptsException(
                message="Not accepted. Try again in {} seconds".format(
                    max(int(retry_after), 0)
                ),
                status_code=429,
            )
    else:
        fails = Fails.query.filter_by(
            account_id=user.account_id, challenge_id=challenge.id
        ).count()
        if fails >= max_tries:
            raise ChallengeMaxAttemptsException(
                message="Not accepted. You have 0 tries remaining",
                status_code=403,
            )


def _enforce_attempt_limits(user, challenge):
    """
    Enforce all submission limits (max_attempts and the per-account /
    per-challenge flag token bucket) before a flag is evaluated.
    """
    _check_max_attempts(user, challenge)
    enforce_flag_submission_rate_limit(user=user, challenge=challenge)


def challenge_attempt_any(submission, challenge, flags):
    from CTFd.plugins.challenges import ChallengeResponse

    _enforce_attempt_limits(user=get_current_user(), challenge=challenge)

    for flag in flags:
        try:
            if get_flag_class(flag.type).compare(flag, submission):
                return ChallengeResponse(
                    status="correct",
                    message="Correct",
                )
        except FlagException as e:
            return ChallengeResponse(
                status="incorrect",
                message=str(e),
            )
    return ChallengeResponse(
        status="incorrect",
        message="Incorrect",
    )


def challenge_attempt_all(submission, challenge, flags):
    from CTFd.plugins.challenges import ChallengeResponse

    user = get_current_user()
    _enforce_attempt_limits(user=user, challenge=challenge)
    partials = Partials.query.filter_by(
        account_id=user.account_id, challenge_id=challenge.id
    ).all()
    provideds = [partial.provided for partial in partials]
    provideds.append(submission)

    target_flags_ids = {flag.id for flag in flags}
    compared_flag_ids = []

    for flag in flags:
        # Skip flags that we have already evaluated as captured
        if flag.id in compared_flag_ids:
            continue
        flag_class = get_flag_class(flag.type)
        for provided in provideds:
            if flag_class.compare(flag, provided):
                compared_flag_ids.append(flag.id)

    # If we have captured against all flag IDs the challenge is correct
    if target_flags_ids == set(compared_flag_ids):
        return ChallengeResponse(
            status="correct",
            message="Correct",
        )

    # If we didn't capture all flag IDs we must be missing something.
    for flag in flags:
        if get_flag_class(flag.type).compare(flag, submission):
            return ChallengeResponse(
                status="partial",
                message="Correct but more flags are required",
            )

    # Input is just wrong
    return ChallengeResponse(
        status="incorrect",
        message="Incorrect",
    )


def challenge_attempt_team(submission, challenge, flags):
    from CTFd.plugins.challenges import ChallengeResponse

    if is_teams_mode():
        user = get_current_user()
        _enforce_attempt_limits(user=user, challenge=challenge)
        team = get_current_team()
        partials = Partials.query.filter_by(
            team_id=team.id, challenge_id=challenge.id
        ).all()

        submitter_ids = {partial.user_id for partial in partials}

        # Check if the user's submission is correct
        for flag in flags:
            try:
                if get_flag_class(flag.type).compare(flag, submission):
                    submitter_ids.add(user.id)
                    break
            except FlagException as e:
                return ChallengeResponse(
                    status="incorrect",
                    message=str(e),
                )
        else:
            return ChallengeResponse(
                status="incorrect",
                message="Incorrect",
            )

        # The submission is correct so compare if we have received from all team members
        member_ids = {member.id for member in team.members}
        if member_ids == submitter_ids:
            return ChallengeResponse(
                status="correct",
                message="Correct",
            )
        else:
            # We have not received from all members
            return ChallengeResponse(
                status="partial",
                message="Correct but all team members must submit a flag",
            )
    else:
        _enforce_attempt_limits(user=get_current_user(), challenge=challenge)
        for flag in flags:
            try:
                if get_flag_class(flag.type).compare(flag, submission):
                    return ChallengeResponse(
                        status="correct",
                        message="Correct",
                    )
            except FlagException as e:
                return ChallengeResponse(
                    status="incorrect",
                    message=str(e),
                )
        return ChallengeResponse(
            status="incorrect",
            message="Incorrect",
        )

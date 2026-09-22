from datetime import timedelta

from CTFd.models import Fails, Partials
from CTFd.plugins.flags import FlagException, get_flag_class
from CTFd.utils import get_config
from CTFd.utils.config import is_teams_mode
from CTFd.utils.security.ratelimit import consume_flag_submission_token
from CTFd.utils.user import (
    get_current_team,
    get_current_user,
    get_wrong_submissions_per_delta,
)


def _attempt_security_guard(challenge):
    """
    Enforce max_attempts and per-account/per-challenge flag submission rate
    limiting at the logic layer so that no entrypoint can bypass them.

    Returns a ChallengeResponse if the attempt must be rejected, otherwise
    None and the caller should continue evaluating the submission.
    """
    from CTFd.plugins.challenges import ChallengeResponse

    user = get_current_user()
    if user is None:
        return None

    max_tries = challenge.max_attempts
    if max_tries and max_tries > 0:
        max_attempts_behavior = get_config("max_attempts_behavior", "lockout")
        if max_attempts_behavior == "timeout":
            max_attempts_timeout = int(get_config("max_attempts_timeout", 300))
            fails = len(
                get_wrong_submissions_per_delta(
                    user.account_id,
                    challenge_id=challenge.id,
                    delta=timedelta(seconds=-max_attempts_timeout),
                )
            )
            if fails >= max_tries:
                return ChallengeResponse(
                    status="ratelimited",
                    message=f"Not accepted. Try again in {max_attempts_timeout} seconds",
                )
        else:  # lockout behavior
            fails = Fails.query.filter_by(
                account_id=user.account_id, challenge_id=challenge.id
            ).count()
            if fails >= max_tries:
                return ChallengeResponse(
                    status="ratelimited",
                    message="Not accepted. You have 0 tries remaining",
                )

    if not consume_flag_submission_token(user.account_id, challenge.id):
        return ChallengeResponse(
            status="ratelimited",
            message="You're submitting flags too fast. Please try again later.",
        )

    return None


def challenge_attempt_any(submission, challenge, flags):
    from CTFd.plugins.challenges import ChallengeResponse

    guard = _attempt_security_guard(challenge)
    if guard is not None:
        return guard

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

    guard = _attempt_security_guard(challenge)
    if guard is not None:
        return guard

    user = get_current_user()
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

    guard = _attempt_security_guard(challenge)
    if guard is not None:
        return guard

    if is_teams_mode():
        user = get_current_user()
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

#!/usr/bin/env bash
#
# Runs the unit tests covering flag-submission security:
#   - per-user/per-challenge token bucket rate limiting (logic layer)
#   - max_attempts enforcement at the logic layer
#   - existing ratelimit decorator and challenge logic regression tests
#
# Usage:
#   ./test.sh            # run all of the tests below
#   ./test.sh -k redis   # pass extra args through to pytest

set -euo pipefail
cd "$(dirname "$0")"

python -m pytest \
    tests/challenges/test_attempt_security.py \
    tests/challenges/test_challenge_logic.py \
    tests/utils/test_ratelimit.py \
    -v "$@"

#!/usr/bin/env bash
#
# Manual unit test runner for the flag-submission hardening work:
#   1. per-account/per-challenge token bucket (Redis + in-memory fallback)
#   2. max_attempts enforcement moved down into the challenge logic layer
#
# Usage:
#   ./test.sh                 Run all of the relevant unit test modules
#   ./test.sh <number>        Run a single test module (see the menu below)
#   ./test.sh all             Same as running with no arguments
#   ./test.sh pytest <args>   Run pytest verbatim with any arguments
#
# Examples:
#   ./test.sh 1
#   ./test.sh pytest tests/utils/test_flag_rate_limit.py -k refill -v
#
set -euo pipefail

cd "$(dirname "$0")"

COMMON_ARGS=(
    -rf
    -p no:cacheprovider
    -W ignore::DeprecationWarning
)

TESTS=(
    "tests/utils/test_flag_rate_limit.py"
    "tests/challenges/test_challenge_enforcement.py"
    "tests/api/v1/test_flag_rate_limit.py"
    "tests/challenges/test_challenge_logic.py"
    "tests/users/test_challenges.py"
    "tests/utils/test_ratelimit.py"
)

# Prefer a project virtualenv if one exists, otherwise use the environment's
# Python/pytest.
if [[ -x ".venv/bin/pytest" ]]; then
    PYTEST=(.venv/bin/pytest)
elif [[ -x "venv/bin/pytest" ]]; then
    PYTEST=(venv/bin/pytest)
elif python3 -m pytest --version >/dev/null 2>&1; then
    PYTEST=(python3 -m pytest)
else
    PYTEST=()
fi

menu() {
    cat <<'EOF'
Available unit test modules:
  1) tests/utils/test_flag_rate_limit.py        token bucket unit tests
  2) tests/challenges/test_challenge_enforcement.py  logic-layer limits
  3) tests/api/v1/test_flag_rate_limit.py       API integration tests
  4) tests/challenges/test_challenge_logic.py   challenge logic (any/all/team)
  5) tests/users/test_challenges.py             existing max_attempts/ratelimit
  6) tests/utils/test_ratelimit.py              legacy ratelimit decorator
  a) all of the above
EOF
}

run() {
    echo ">>> ${PYTEST[*]} $*"
    if [[ ${#PYTEST[@]} -eq 0 ]]; then
        echo "pytest is not installed. Install dependencies first, e.g.:"
        echo "  python3 -m pip install -r requirements.txt"
        exit 1
    fi
    "${PYTEST[@]}" "$@"
}

case "${1:-}" in
    "")
        run "${COMMON_ARGS[@]}" "${TESTS[@]}"
        ;;
    all|a|A)
        run "${COMMON_ARGS[@]}" "${TESTS[@]}"
        ;;
    pytest)
        shift
        run "$@"
        ;;
    -h|--help|help)
        menu
        exit 0
        ;;
    [1-6])
        run "${COMMON_ARGS[@]}" "${TESTS[$(( $1 - 1 ))]}"
        ;;
    *)
        echo "Unknown option: $1"
        echo
        menu
        exit 1
        ;;
esac

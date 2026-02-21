#!/usr/bin/env bash
# retry.bash — Exponential backoff retry function

# retry <max_attempts> <command...>
# Retries a command with exponential backoff.
# Uses RETRY_INITIAL_DELAY (default 0.2s) and RETRY_MAX_DELAY (default 10s).
# Returns 0 on success, 1 if all attempts exhausted.
retry() {
    local max_attempts="${1:?usage: retry <max_attempts> <command...>}"
    shift
    # Force C locale for decimal arithmetic (sleep, awk) on non-English systems
    local LC_NUMERIC=C
    local delay="${RETRY_INITIAL_DELAY:-0.2}"
    local max_delay="${RETRY_MAX_DELAY:-10}"
    local attempt=1

    while [ "$attempt" -le "$max_attempts" ]; do
        if "$@" 2>/dev/null; then
            return 0
        fi
        if [ "$attempt" -eq "$max_attempts" ]; then
            return 1
        fi
        sleep "$delay"
        # Exponential backoff: double the delay, cap at max
        delay="$(LC_NUMERIC=C awk "BEGIN { d = $delay * 2; print (d > $max_delay) ? $max_delay : d }")"
        attempt=$((attempt + 1))
    done
    return 1
}

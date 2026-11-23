#!/usr/bin/env sh
# Run a pinned Suricata on probes.rules and record which rules it loads.
# Output: verdicts.txt, one line per probe, "<sid> loaded" or "<sid> refused";
# a probe without a sid is recorded by its line number as "line:<n>".
# Needs docker; the image is pulled on first run.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
image=${SURICATA_IMAGE:-jasonish/suricata:8.0.8}
log=$(mktemp)
trap 'rm -f "$log"' EXIT
docker run --rm -v "$here:/probes:ro" --entrypoint suricata "$image" \
    -T -S /probes/probes.rules -l /tmp >"$log" 2>&1 || true
version=$(docker run --rm --entrypoint suricata "$image" -V)
{
    echo "# $version, run by make-verdicts.sh; do not edit by hand."
    awk -v logf="$log" '
        BEGIN {
            while ((getline line < logf) > 0) {
                if (match(line, /at line [0-9]+$/)) {
                    bad[substr(line, RSTART + 8)] = 1
                }
            }
        }
        /^[[:space:]]*(#|$)/ { next }
        {
            id = "line:" NR
            if (match($0, /sid:[0-9]+;/)) id = substr($0, RSTART + 4, RLENGTH - 5)
            print id, (NR in bad ? "refused" : "loaded")
        }
    ' "$here/probes.rules"
} >"$here/verdicts.txt"

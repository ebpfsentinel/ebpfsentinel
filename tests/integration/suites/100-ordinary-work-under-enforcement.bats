#!/usr/bin/env bats
# 100-ordinary-work-under-enforcement.bats - the ordinary work of a host
# runs to its end with the mass encryption verdict and the write refusal
# both in force, and neither of them says a word.
#
# A rule that only alerts wrongly is a nuisance; a rule that refuses or
# kills wrongly is an outage. So the corpus runs here with both in force,
# each tool asserted to finish with its own exit status:
#
#   * An archive extraction, a copy, and a mirror whose second pass writes
#     each changed file beside itself and renames it over the old one.
#   * A checkout between two branches of a large tree.
#   * A package installed and then upgraded by the package manager under a
#     system directory held for it, the upgrade replacing every shipped
#     file with different compressed bytes through a rename, which is the
#     shape of an encryption run.
#   * An index rebuild, a log rotation compressing every log and deleting
#     it, a media encoder, a database compaction, a compressed backup job
#     with its oldest archive pruned, and an administrator pruning
#     hard-linked snapshots, each writing under the directory the refusal
#     counts.
#
# After the corpus no alert of either rule was raised and nothing was
# refused, while the package manager's writes under the held directory are
# counted as expected. The last test shows both were armed the whole time:
# an encryption of the same kind of tree is killed, and a writer past the
# refusal's threshold is refused.
#
# Needs the BPF LSM active at boot (`bpf` in /sys/kernel/security/lsm).

load '../lib/helpers'
load '../lib/ebpf_helpers'

DOCUMENTS=1200
DIRECTORIES=40
PACKAGE=ebpfsentinel-test-corpus

setup_file() {
    require_kernel 6 12
    require_root
    local tool
    for tool in jq python3 tar gzip zstd rsync git dpkg dpkg-deb updatedb logrotate ffmpeg sqlite3; do
        require_tool "${tool}"
    done

    if ! tr ',' '\n' </sys/kernel/security/lsm 2>/dev/null | grep -qx bpf; then
        env_skip "the BPF LSM is not active on this host (lsm=bpf at boot)"
    fi

    export PROJECT_ROOT
    PROJECT_ROOT="$(find_project_root)"
    require_ebpf_env

    if [ "${EBPF_2VM_MODE:-false}" = "true" ]; then
        env_skip "suite 100 runs its workloads on the agent's host (local lane only)"
    fi

    # Under /var/tmp rather than /tmp: /tmp is a tmpfs on many hosts, and
    # the watch marks the filesystem holding this directory.
    export DATA_DIR="/var/tmp/ebpfsentinel-test-data-corpus-$$"
    mkdir -p "${DATA_DIR}/work" "${DATA_DIR}/watched" "${DATA_DIR}/system"
    cp "$(readlink -f "$(command -v python3)")" "${DATA_DIR}/me-encrypt"
    chmod 0755 "${DATA_DIR}/me-encrypt"
    dpkg -r "${PACKAGE}" >/dev/null 2>&1 || true

    stop_ebpf_agent 2>/dev/null || true
    destroy_test_netns 2>/dev/null || true
    create_test_netns
    PREPARED_CONFIG="$(prepare_ebpf_config "${FIXTURE_DIR}/config-ebpf-corpus-in-force.yaml")"
    export PREPARED_CONFIG
    start_ebpf_agent "${PREPARED_CONFIG}"
    wait_for_ebpf_loaded 30 || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "eBPF programs not loaded (degraded mode)" >&2; return 1; }
    }
    _wait_armed || {
        stop_ebpf_agent 2>/dev/null || true
        { echo "the verdict and the refusal never both reported themselves in force" >&2; return 1; }
    }
}

teardown_file() {
    pkill -9 -x me-encrypt 2>/dev/null || true
    stop_ebpf_agent 2>/dev/null || true
    dpkg -r "${PACKAGE}" >/dev/null 2>&1 || true
    destroy_test_netns 2>/dev/null || true
    rm -rf "${DATA_DIR:-/var/tmp/ebpfsentinel-test-data-corpus-$$}"
    rm -f "${PREPARED_CONFIG:-}"
}

# ── Helpers (suite-local) ───────────────────────────────────────────

_wait_armed() {
    local attempt=0 verdict features
    while [ "${attempt}" -lt 30 ]; do
        verdict="$(api_get /api/v1/host-rules/mass-encryption 2>/dev/null)" || verdict=""
        features="$(api_get /api/v1/ebpf/kernel-features 2>/dev/null)" || features=""
        [ "$(jq -r '.enabled' <<<"${verdict}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.mode' <<<"${verdict}" 2>/dev/null)" = "enforce" ] &&
            [ "$(jq -r '.write_refusal.attached' <<<"${features}" 2>/dev/null)" = "true" ] &&
            [ "$(jq -r '.write_refusal.enforcing' <<<"${features}" 2>/dev/null)" = "true" ] && return 0
        sleep 0.5
        attempt=$((attempt + 1))
    done
    return 1
}

# _settle - give the watch time to read back what the last tool wrote.
_settle() {
    sleep 5
}

# _refusal_count <action> - the write refusal counter for <action>, 0 when
# it was never written.
_refusal_count() {
    local value
    value="$(get_metrics_value ebpfsentinel_packets_total "{interface=\"WRITE_REFUSAL_METRICS\",action=\"$1\"}")" || value=""
    echo "${value%.*}" | sed 's/^$/0/'
}

# _quiet - neither rule raised anything and nothing was refused.
_quiet() {
    _settle
    run wait_for_alert '.[] | select(.rule_id == "mass-encryption" or .rule_id == "write-refusal")' 3 1
    if [ "$status" -eq 0 ]; then
        echo "raised: ${output}" >&2
        return 1
    fi
    [ "$(_refusal_count refused)" -eq 0 ]
}

# _tree <dir> - documents carrying the heads their names promise.
_tree() {
    python3 - "$1" "${DOCUMENTS}" "${DIRECTORIES}" <<'PY'
import os, sys
root, documents, directories = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
text = ("ledger line with ordinary words in it\n" * 400).encode()
for d in range(directories):
    os.makedirs(f"{root}/d{d}", exist_ok=True)
    for name in ("README.md", "Makefile"):
        with open(f"{root}/d{d}/{name}", "wb") as f:
            f.write(text[:600])
for n in range(documents):
    with open(f"{root}/d{n % directories}/report{n}.pdf", "wb") as f:
        f.write(b"%PDF-1.7\n" + text)
PY
}

# _package <version> - a package shipping 150 compressed files under the
# held system directory, different bytes in every version.
_package() {
    local stage="${DATA_DIR}/work/pkg-$1"
    rm -rf "${stage}"
    mkdir -p "${stage}/DEBIAN" "${stage}${DATA_DIR}/system/lib"
    python3 - "${stage}${DATA_DIR}/system/lib" <<'PY'
import gzip, os, sys
for n in range(150):
    with open(os.path.join(sys.argv[1], f"module{n}.so.gz"), "wb") as f:
        f.write(gzip.compress(os.urandom(16384)))
PY
    printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: test <test@example.invalid>\nDescription: test package\n' \
        "${PACKAGE}" "$1" >"${stage}/DEBIAN/control"
    dpkg-deb --root-owner-group --build "${stage}" "${DATA_DIR}/work/${PACKAGE}_$1.deb" >/dev/null
}

# ── Tests ───────────────────────────────────────────────────────────

@test "the verdict and the refusal are both in force" {
    [ "$(api_get /api/v1/host-rules/mass-encryption | jq -r '.mode')" = "enforce" ]
    local features
    features="$(api_get /api/v1/ebpf/kernel-features)"
    [ "$(jq -r '.write_refusal.enforcing' <<<"${features}")" = "true" ]
    [ "$(jq -r '.write_refusal.expected_writers' <<<"${features}")" = "1" ]
}

@test "an archive extraction, a copy and a mirror run to their end" {
    local work="${DATA_DIR}/work"
    _tree "${work}/source"
    _settle
    run tar -C "${work}" -cf "${work}/source.tar" source
    [ "$status" -eq 0 ]
    mkdir -p "${work}/extracted"
    run tar -C "${work}/extracted" -xf "${work}/source.tar"
    [ "$status" -eq 0 ]
    run cp -a "${work}/source" "${work}/copy"
    [ "$status" -eq 0 ]
    mkdir -p "${work}/mirror"
    run rsync -a "${work}/source/" "${work}/mirror/"
    [ "$status" -eq 0 ]
    find "${work}/source" -name '*.pdf' -exec sh -c 'printf "\n%%%%EOF\n" >>"$1"' _ {} \;
    run rsync -a "${work}/source/" "${work}/mirror/"
    [ "$status" -eq 0 ]
    [ "$(find "${work}/mirror" -name '*.pdf' | wc -l)" -eq "${DOCUMENTS}" ]
    _quiet
}

@test "a checkout between two branches of a large tree runs to its end" {
    local repo="${DATA_DIR}/work/repo"
    _tree "${repo}"
    git -C "${repo}" init -q -b one
    git -C "${repo}" -c user.name=t -c user.email=t@t add -A
    git -C "${repo}" -c user.name=t -c user.email=t@t commit -qm one
    git -C "${repo}" checkout -q -b two
    find "${repo}" -path "${repo}/.git" -prune -o -name '*.pdf' -exec sh -c 'printf "\n%%%%EOF\n" >>"$1"' _ {} \;
    git -C "${repo}" -c user.name=t -c user.email=t@t commit -qam two
    _settle
    run git -C "${repo}" checkout -q one
    [ "$status" -eq 0 ]
    run git -C "${repo}" checkout -q two
    [ "$status" -eq 0 ]
    _quiet
}

@test "the package manager installs and upgrades a package under the held directory" {
    _package 1.0
    _package 2.0
    run dpkg -i "${DATA_DIR}/work/${PACKAGE}_1.0.deb"
    [ "$status" -eq 0 ]
    local before
    before="$(sha256sum "${DATA_DIR}/system/lib/module0.so.gz")"
    _settle
    run dpkg -i "${DATA_DIR}/work/${PACKAGE}_2.0.deb"
    [ "$status" -eq 0 ]
    [ "$(find "${DATA_DIR}/system/lib" -name '*.so.gz' | wc -l)" -eq 150 ]
    [ "$(sha256sum "${DATA_DIR}/system/lib/module0.so.gz")" != "${before}" ]
    _quiet
    [ "$(_refusal_count expected)" -gt 0 ]
}

@test "an index rebuild and a log rotation compressing every log run to their end" {
    local watched="${DATA_DIR}/watched"
    run updatedb -l 0 -U "${DATA_DIR}/work" -o "${watched}/locate.db"
    [ "$status" -eq 0 ]
    [ -s "${watched}/locate.db" ]
    mkdir -p "${watched}/logs"
    local n
    for n in $(seq 1 20); do
        seq 1 4000 | sed 's/^/request served in 12 ms /' >"${watched}/logs/app${n}.log"
    done
    printf '%s/logs/*.log {\n  rotate 3\n  compress\n  missingok\n}\n' "${watched}" >"${DATA_DIR}/work/logrotate.conf"
    run logrotate -f -s "${DATA_DIR}/work/logrotate.state" "${DATA_DIR}/work/logrotate.conf"
    [ "$status" -eq 0 ]
    [ "$(find "${watched}/logs" -name '*.gz' | wc -l)" -eq 20 ]
    _quiet
}

@test "a media encoder and a database compaction run to their end" {
    local watched="${DATA_DIR}/watched" n
    mkdir -p "${watched}/media"
    for n in $(seq 1 8); do
        run ffmpeg -nostdin -loglevel error -f lavfi -i "testsrc=duration=2:size=320x240:rate=25" \
            -f lavfi -i "sine=frequency=$((300 + n * 50)):duration=2" -shortest \
            "${watched}/media/clip${n}.mkv"
        [ "$status" -eq 0 ]
    done
    run sqlite3 "${watched}/app.db" \
        "CREATE TABLE t(id INTEGER PRIMARY KEY, body BLOB);
         WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 50000)
         INSERT INTO t(body) SELECT randomblob(200) FROM c;
         DELETE FROM t WHERE id % 2 = 0;
         VACUUM;"
    [ "$status" -eq 0 ]
    [ "$(sqlite3 "${watched}/app.db" 'SELECT count(*) FROM t')" -eq 25000 ]
    _quiet
}

@test "a compressed backup job and snapshot pruning run to their end" {
    local watched="${DATA_DIR}/watched" work="${DATA_DIR}/work" n
    mkdir -p "${watched}/backups" "${work}/snapshots"
    for n in 1 2 3; do
        run bash -c 'tar -C "$1" -cf - source | zstd -q -o "$2"' _ "${work}" "${watched}/backups/source-${n}.tar.zst"
        [ "$status" -eq 0 ]
    done
    rm -f "${watched}/backups/source-1.tar.zst"
    for n in 1 2 3 4 5; do
        run cp -al "${work}/source" "${work}/snapshots/daily.${n}"
        [ "$status" -eq 0 ]
    done
    run rm -rf "${work}/snapshots/daily.1" "${work}/snapshots/daily.2" "${work}/snapshots/daily.3"
    [ "$status" -eq 0 ]
    _quiet
}

@test "both were armed: an encryption is killed and a writer past the threshold is refused" {
    local victim="${DATA_DIR}/work/victim"
    _tree "${victim}"
    _settle
    run "${DATA_DIR}/me-encrypt" - "${victim}" <<'PY'
import os, sys, time
for directory, _, names in sorted(os.walk(sys.argv[1])):
    for name in sorted(names):
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        with open(path, "r+b") as f:
            f.write(os.urandom(os.path.getsize(path)))
        os.rename(path, path + ".lockd")
        time.sleep(0.01)
PY
    [ "$status" -eq 137 ]
    mkdir -p "${DATA_DIR}/watched/burst"
    run python3 - "${DATA_DIR}/watched/burst" <<'PY'
import errno, os, sys
for n in range(150):
    try:
        with open(os.path.join(sys.argv[1], f"doc{n}.txt"), "w") as f:
            f.write("payload\n")
        print("ok")
    except OSError as e:
        print(errno.errorcode[e.errno])
PY
    grep -qx EACCES <<<"${output}"
    wait_for_metric ebpfsentinel_packets_total 1 30 '{interface="WRITE_REFUSAL_METRICS",action="refused"}'
}

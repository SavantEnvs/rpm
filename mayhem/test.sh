#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Drives the CLI tools that mayhem/build.sh built with normal flags (mayhem/_build-tests) and
# asserts known-input -> known-output values. A patched rpm that exits 0 or prints nothing fails.
B="$SRC/mayhem/_build-tests"
T="$B/tools"
export RPM_CONFIGDIR="$B"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
COMMON=(--dbpath "$W/db" --define "_dbpath $W/db" --define "_fileattrsdir $SRC/fileattrs" --define "_rpmconfigdir $B" --define "_topdir $W/top" --define "_tmppath $W/tmp")
mkdir -p "$W/db" "$W/tmp" "$W/top"/{BUILD,RPMS,SRPMS,SPECS,SOURCES,BUILDROOT}

for t in rpm rpmspec rpmbuild rpmdb rpmkeys rpm2cpio; do
  [ -x "$T/$t" ] || { echo "missing $T/$t: mayhem/build.sh did not build it" >&2; emit_ctrf "rpm-cli" 0 1 0; exit 1; }
done

passed=0; failed=0
check() {  # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then passed=$((passed+1)); echo "PASS $1"
  else failed=$((failed+1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

H="$SRC/tests/data/RPMS/hello-2.0-1.x86_64.rpm"
check query-nevra "hello-2.0-1.x86_64" \
  "$("$T/rpm" "${COMMON[@]}" -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$H" 2>/dev/null)"
check query-summary "hello -- hello, world rpm" \
  "$("$T/rpm" "${COMMON[@]}" -qp --qf '%{SUMMARY}' "$H" 2>/dev/null)"
check query-files "/usr/bin/hello" \
  "$("$T/rpm" "${COMMON[@]}" -qpl "$H" 2>/dev/null | head -n1)"
check query-filecount "5" \
  "$("$T/rpm" "${COMMON[@]}" -qpl "$H" 2>/dev/null | wc -l | tr -d ' ')"
check query-fmt-array "/usr/bin/hello:-rwxr-x--x" \
  "$("$T/rpm" "${COMMON[@]}" -qp --qf '[%{FILENAMES}:%{FILEMODES:perms}\n]' "$H" 2>/dev/null | head -n1)"
check expr-int "3" "$("$T/rpm" --eval '%[1+2]' 2>/dev/null)"
check expr-ternary "yes" "$("$T/rpm" --eval '%[2>1 ? "yes" : "no"]' 2>/dev/null)"
check vercmp-lt "-1" "$("$T/rpm" --eval '%{lua:print(rpm.vercmp("1.0","1.1"))}' 2>/dev/null)"
check vercmp-gt "1" "$("$T/rpm" --eval '%{lua:print(rpm.vercmp("2.0","1.9"))}' 2>/dev/null)"
check vercmp-eq "0" "$("$T/rpm" --eval '%{lua:print(rpm.vercmp("1.0","1.0"))}' 2>/dev/null)"
check vercmp-tilde "-1" "$("$T/rpm" --eval '%{lua:print(rpm.vercmp("1.0~rc1","1.0"))}' 2>/dev/null)"

cat > "$W/top/SPECS/probe.spec" <<'SPEC'
Name: probe
Version: 1.2.3
Release: 4
Summary: oracle probe package
License: MIT
BuildArch: noarch

%description
Probe package for the mayhem oracle.

%install
mkdir -p %{buildroot}/usr/share/probe
echo "probe-payload" > %{buildroot}/usr/share/probe/data.txt

%files
/usr/share/probe/data.txt
SPEC

check spec-query "probe-1.2.3-4.noarch" \
  "$("$T/rpmspec" "${COMMON[@]}" -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$W/top/SPECS/probe.spec" 2>/dev/null)"
"$T/rpmbuild" "${COMMON[@]}" -bb "$W/top/SPECS/probe.spec" >"$W/build.log" 2>&1 || { echo "rpmbuild failed"; tail -20 "$W/build.log"; }
P="$W/top/RPMS/noarch/probe-1.2.3-4.noarch.rpm"
check build-exists "yes" "$([ -f "$P" ] && echo yes || echo no)"
check built-nevra "probe-1.2.3-4.noarch" \
  "$("$T/rpm" "${COMMON[@]}" -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$P" 2>/dev/null)"
check built-files "/usr/share/probe/data.txt" "$("$T/rpm" "${COMMON[@]}" -qpl "$P" 2>/dev/null)"
check built-filesize "14" "$("$T/rpm" "${COMMON[@]}" -qp --qf '[%{LONGFILESIZES}]' "$P" 2>/dev/null)"
check built-cpio-list "./usr/share/probe/data.txt" \
  "$("$T/rpm2cpio" "$P" 2>/dev/null | bsdtar -tf - 2>/dev/null)"
check built-cpio-payload "probe-payload" \
  "$("$T/rpm2cpio" "$P" 2>/dev/null | bsdtar -xOf - ./usr/share/probe/data.txt 2>/dev/null)"

emit_ctrf "rpm-cli" "$passed" "$failed" 0

#!/usr/bin/env bash
#
# Builds rpm twice from the same tree (all dependencies are apt -dev packages installed by the
# Dockerfile, so a re-run needs no network):
#   mayhem/_build        sanitized + coverage-instrumented libraries, linked into the fuzz harnesses
#   mayhem/_build-tests  normal flags, the CLI tools that mayhem/test.sh drives
# Both directories are gitignored (mayhem/.gitignore) so `git clean -ffdX` removes them.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# A re-run under a different compiler spelling (the ccache pre-fill wrapper) makes cmake discard its
# cache and drop the -D options with it, so always configure from scratch; ccache keeps that cheap.
rm -rf mayhem/_build mayhem/_build-tests

# Everything optional (python, plugins and their libraries, NLS, OpenMP, the Sequoia OpenPGP
# backend, which needs a Rust toolchain and crates) is off; the OpenPGP backend is the dummy one.
CMAKE_COMMON=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  -DENABLE_PYTHON=OFF -DENABLE_PLUGINS=OFF -DENABLE_NLS=OFF -DENABLE_OPENMP=OFF
  -DENABLE_TESTSUITE=OFF -DWITH_SEQUOIA=OFF -DWITH_SELINUX=OFF -DWITH_AUDIT=OFF
  -DWITH_DBUS=OFF -DWITH_FAPOLICYD=OFF -DWITH_CAP=OFF -DWITH_ACL=OFF -DWITH_READLINE=OFF
  -DWITH_LIBDW=OFF -DWITH_LIBELF=OFF -DWITH_ICONV=OFF
)

# 1) Sanitized build; fuzzer-no-link adds the coverage instrumentation the fuzzer reads from the
#    shared libraries (skipped when the sanitizers are switched off).
COV=""
[ -n "$SANITIZER_FLAGS" ] && COV="-fsanitize=fuzzer-no-link"
FUZZ_C_FLAGS="$SANITIZER_FLAGS $COV $DEBUG_FLAGS -O1"
cmake -B mayhem/_build "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$FUZZ_C_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_C_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$SANITIZER_FLAGS"
cmake --build mayhem/_build -j"$MAYHEM_JOBS" --target librpm librpmio

# 2) Harnesses, each linked with the fuzzing engine and with the run-once standalone driver.
B="$SRC/mayhem/_build"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o /tmp/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
LINK=(-L"$B/lib" -L"$B/rpmio" -lrpm -lrpmio -Wl,-rpath,"$B/lib" -Wl,-rpath,"$B/rpmio")
for h in fuzz_package fuzz_header fuzz_version fuzz_expression fuzz_queryformat fuzz_ndb; do
  src="mayhem/$h.cc"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -std=c++17 -I"$SRC/include" "$src" /tmp/lsan_off.o \
      $LIB_FUZZING_ENGINE "${LINK[@]}" -o "/mayhem/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -std=c++17 -I"$SRC/include" "$src" /tmp/standalone_main.o /tmp/lsan_off.o \
      "${LINK[@]}" -o "/mayhem/$h-standalone"
done

# 3) Normal-flags build of the CLI tools for the test oracle.
cmake -B mayhem/_build-tests "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build mayhem/_build-tests -j"$MAYHEM_JOBS" --target rpm rpmspec rpmdb rpmkeys rpm2archive rpm2cpio rpmbuild

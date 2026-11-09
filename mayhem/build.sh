#!/usr/bin/env bash
#
# mayhem/build.sh — build libmodsecurity with sanitizers + one libFuzzer harness per fuzz target
# (and a -standalone reproducer for each), then build the upstream unit/regression test runners
# with the project's normal flags so mayhem/test.sh only has to run them.
#
# Runs in the commit image as `mayhem` in /mayhem. Needs no network: every dependency is an apt
# -dev package installed by mayhem/Dockerfile, and the submodules (libinjection, mbedtls,
# secrules-language-tests) are already in the checkout.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`): an explicit EMPTY SANITIZER_FLAGS builds without sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

# Coverage instrumentation for the project and harness TUs, even when SANITIZER_FLAGS is empty.
SANCOV="-fsanitize=fuzzer-no-link"

cd "$SRC"
FUZZ_BUILD="$SRC/mayhem/build-fuzz"
TEST_BUILD="$SRC/mayhem/build-tests"
# upstream's out-of-tree test/ rules look for headers/ in the build dir; point them at the source tree.
INC_HEADERS="-I$SRC/headers"

# 0) autotools bootstrap (configure and the Makefile.in files are gitignored, so regenerate them).
sh ./build.sh >/dev/null

# 1) The project itself, with sanitizers + DWARF 3.
mkdir -p "$FUZZ_BUILD"
(
  cd "$FUZZ_BUILD"
  CFLAGS="$SANITIZER_FLAGS $SANCOV -O1 $DEBUG_FLAGS" CXXFLAGS="$SANITIZER_FLAGS $SANCOV -O1 $DEBUG_FLAGS" \
  LDFLAGS="$SANITIZER_FLAGS" CPPFLAGS="$INC_HEADERS" \
    ../../configure --disable-shared --enable-static --with-pcre2 \
      --without-curl --without-geoip --without-lmdb --disable-examples >configure.log 2>&1 \
    || { tail -50 configure.log; exit 1; }
  make -j"$MAYHEM_JOBS" -C others
  make -j"$MAYHEM_JOBS" -C src
)

# Compile/link flags the project's own test programs use, so the harnesses match the library's ABI
# (WITH_* defines change class layouts).
mkvar() { make -s -C "$FUZZ_BUILD/test" -f Makefile -f <(echo 'print-%: ; @echo $($*)') "print-$1"; }
CPPFLAGS_PROJECT="$(mkvar unit_tests_CPPFLAGS | tr ' ' '\n' | grep -v -e '^-I\.\./' -e '^-Icommon$' -e '^-g$' | tr '\n' ' ') -I$SRC -I$SRC/others $INC_HEADERS -I$FUZZ_BUILD/src"
LDADD_PROJECT="$(mkvar unit_tests_LDADD) -lpthread -lm"
LIBS="$FUZZ_BUILD/src/.libs/libmodsecurity.a $FUZZ_BUILD/others/.libs/libinjection.a $FUZZ_BUILD/others/.libs/libmbedtls.a"
OBJ="$FUZZ_BUILD/harness-obj"; mkdir -p "$OBJ"

# 2) Harnesses: LLVMFuzzer entry linked with libFuzzer, and again with the run-once driver.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for h in fuzz_operators; do
  $CXX -std=c++17 $SANITIZER_FLAGS $SANCOV -O1 $DEBUG_FLAGS -DHAVE_CONFIG_H $CPPFLAGS_PROJECT \
    -c "$SRC/mayhem/$h.cc" -o "$OBJ/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$h.o" "$OBJ/lsan_off.o" \
    $LIBS $LDADD_PROJECT -o "$SRC/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/$h.o" "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" \
    $LIBS $LDADD_PROJECT -o "$SRC/$h-standalone"
done

# 3) Upstream's unit + regression test runners, built with NORMAL flags in a separate tree.
mkdir -p "$TEST_BUILD"
(
  cd "$TEST_BUILD"
  env -u CFLAGS -u CXXFLAGS -u LDFLAGS CPPFLAGS="$INC_HEADERS $COVERAGE_FLAGS" \
    CFLAGS="$COVERAGE_FLAGS" CXXFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
    ../../configure --disable-shared --enable-static --with-pcre2 --with-lmdb \
      --disable-examples >configure.log 2>&1 || { tail -50 configure.log; exit 1; }
  make -j"$MAYHEM_JOBS" -C others
  make -j"$MAYHEM_JOBS" -C src
  make -j"$MAYHEM_JOBS" -C test unit_tests regression_tests
)

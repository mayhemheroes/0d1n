#!/usr/bin/env bash
# 0d1n/mayhem/build.sh — sanitized libFuzzer harness for deadspace() + standalone reproducer.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

DIR=src/
DIR_HEADERS=src/headers/
CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -W -Wall -Wextra -Wformat-security -Wno-maybe-uninitialized -O2 \
  -fstack-protector-all -pie -fPIE -I${DIR_HEADERS}"
LDFLAGS="-lcurl -lpthread -Wl,-z,relro,-z,now"

build_objs() {
  rm -f ./*.o
  for f in "$DIR"*.c; do
    $CC $CFLAGS -c "$f" -o "$(basename "$f" .c).o"
  done
  rm -f 0d1n.o
}

if [ ! -x /mayhem/deadspace ] || [ ! -x /mayhem/deadspace-standalone ]; then
  build_objs
  OBJS=(./*.o)

  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_deadspace.cpp" \
    "${OBJS[@]}" \
    $LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -o /mayhem/deadspace

  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_deadspace.cpp" \
    /tmp/standalone_main.o \
    "${OBJS[@]}" \
    $LDFLAGS \
    -o /mayhem/deadspace-standalone
fi

echo "build.sh complete"

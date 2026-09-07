#!/bin/sh
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$task_root"
mkdir -p build/rn-tests
"${CXX:-c++}" -std=c++20 -I native/src/main/cpp -I native/src/main/cpp/vendor/duck \
  native/tests/duck_policy_test.cpp \
  native/src/main/cpp/vendor/duck/memory/common/maps_reader.cpp \
  native/src/main/cpp/vendor/duck/memory/detectors/fd_detector.cpp \
  -o build/rn-tests/duck_policy_test
build/rn-tests/duck_policy_test

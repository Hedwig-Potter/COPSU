#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VCPKG_ROOT="/home/jrj/code/vcpkg"

usage() {
  cat <<'EOF'
用法: scripts/configure.sh [--type Release|Debug|RelWithDebInfo|MinSizeRel]
示例: scripts/configure.sh --type Release

不指定 --type 时默认使用 CMake 默认的 Debug。
EOF
  exit 0
}

BUILD_DIR="$ROOT/build"
BUILD_TYPE=""

while (($#)); do
  case "$1" in
    --type)
      if (($# < 2)); then
        echo "--type 需要一个参数" >&2
        exit 1
      fi
      BUILD_TYPE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "未知参数: $1" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$BUILD_DIR"

cmake_args=(
  -S "$ROOT/src"
  -B "$BUILD_DIR"
  -GNinja
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
  -DSEAL_DIR="$VCPKG_ROOT/installed/x64-linux/share/seal"
  -DMicrosoft.GSL_DIR="$VCPKG_ROOT/installed/x64-linux/share/Microsoft.GSL"
  -Dzstd_DIR="$VCPKG_ROOT/installed/x64-linux/share/zstd"
)

if [ -n "$BUILD_TYPE" ]; then
  cmake_args+=( -DCMAKE_BUILD_TYPE="$BUILD_TYPE" )
fi

cmake "${cmake_args[@]}"

echo "CMake configure finished. compile_commands.json is at $BUILD_DIR/compile_commands.json"

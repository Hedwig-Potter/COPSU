#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/build.sh [--type Release|Debug|RelWithDebInfo|MinSizeRel]
Example: scripts/build.sh --type Release

If --type is not specified, defaults to the settings from the configure stage.
EOF
	exit 0
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build"

BUILD_TYPE=""

while (($#)); do
	case "$1" in
		--type)
			if (($# < 2)); then
				echo "--type requires an argument" >&2
				exit 1
			fi
			BUILD_TYPE="$2"
			shift 2
			;;
		--help|-h)
			usage
			;;
		*)
			echo "Unknown parameter: $1" >&2
			exit 1
			;;
	esac
done

if [ ! -d "$BUILD_DIR" ]; then
	echo "Build directory not found. Run scripts/configure.sh first." >&2
	exit 1
fi

cd "$BUILD_DIR"

if [ -n "$BUILD_TYPE" ]; then
	cmake --build . --config "$BUILD_TYPE"
else
	cmake --build .
fi

#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
./securelinux-ng.sh --version &&
./securelinux-ng.sh --help >/dev/null &&
./securelinux-ng.sh --check --profile baseline >/dev/null &&
./securelinux-ng.sh --apply --dry-run --profile baseline >/dev/null &&
./securelinux-ng.sh --report --profile baseline >/dev/null

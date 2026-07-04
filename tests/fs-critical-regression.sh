#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")

apply_start = text.index("apply_fs_critical_file_one() {")
apply_end = text.index(
    "\napply_fs_critical_files_module() {",
    apply_start,
)
apply_block = text[apply_start:apply_end]

errors = []

required = (
    '/etc/passwd|/etc/group) echo "644" ;;',
    '/etc/shadow) echo "go-rwx" ;;',
    'chmod 644 -- "$target"',
    'chmod go-rwx -- "$target"',
    'fs_mode_compliant "$target" "$actual_mode"',
)

for marker in required:
    if marker not in text:
        errors.append(f"FS_CRITICAL_MARKER_MISSING={marker}")

if 'chown ' in apply_block:
    errors.append("FS_CRITICAL_CHOWN_PRESENT")

if '/etc/shadow) echo "600" ;;' in text:
    errors.append("SHADOW_EXACT_MODE_600_PRESENT")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=FS_CRITICAL_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

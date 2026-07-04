#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")

start = text.index("restore_empty_passwords_module() {")
end = text.index("\nrestore_runtime_paths_module() {", start)
block = text[start:end]

errors = []

if 'restore_lookup_backup "/etc/shadow"' in block:
    errors.append("GENERIC_SHADOW_BACKUP_LOOKUP_PRESENT")

if "empty-password-users-" not in block:
    errors.append("EMPTY_PASSWORD_BACKUP_FILTER_MISSING")

if 'data.get("backups", [])' not in block:
    errors.append("MANIFEST_BACKUP_SCAN_MISSING")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=EMPTY_PASSWORD_RESTORE_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

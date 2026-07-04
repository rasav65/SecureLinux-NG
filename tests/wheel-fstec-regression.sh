#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")

start = text.index("apply_pam_wheel_module() {")
end = text.index("\nrequire_cmds() {", start)
block = text[start:end]

errors = []

if 'pam_wheel не применяется: задайте WHEEL_USERS' in block:
    errors.append("EMPTY_WHEEL_USERS_SILENT_SKIP_PRESENT")

if 'WHEEL_USERS must contain at least one administrator' in block:
    errors.append("OBSOLETE_EMPTY_WHEEL_USERS_ERROR_PRESENT")

required_auto_detection = (
    '[[ -n "${SUDO_USER:-}" ]]',
    '[[ "$SUDO_USER" != "root" ]]',
    'pam_wheel_user_is_existing_admin "$SUDO_USER"',
    'WHEEL_USERS="$SUDO_USER"',
    'users=("$SUDO_USER")',
    'administrator auto-detection failed; set WHEEL_USERS explicitly',
)

for required in required_auto_detection:
    if required not in block:
        errors.append(f"AUTO_DETECTION_MISSING={required}")

configured_index = block.find(
    'mapfile -t users < <(configured_wheel_users)'
)
sudo_user_index = block.find('[[ -n "${SUDO_USER:-}" ]]')

if configured_index < 0 or sudo_user_index < 0:
    errors.append("WHEEL_PRIORITY_CHECK_UNAVAILABLE")
elif configured_index > sudo_user_index:
    errors.append("EXPLICIT_WHEEL_USERS_PRIORITY_LOST")

if 'gpasswd -a root wheel' not in block:
    errors.append("ROOT_WHEEL_MEMBERSHIP_MISSING")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=WHEEL_FSTEC_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

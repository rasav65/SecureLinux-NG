#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/securelinux-ng.sh" <<'PYTEST'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


checks = {
    "WHEEL_USERS_DEFAULT":
        text.count('WHEEL_USERS=""') == 1,

    "WHEEL_USERS_PARSER":
        text.count("WHEEL_USERS)") == 1,

    "WHEEL_MANIFEST_FIELD":
        '"added_group_memberships": []' in text,

    "WHEEL_RECORD_FUNCTION":
        "record_manifest_added_group_membership()" in text,

    "WHEEL_RESTORE_FUNCTION":
        "restore_added_group_members()" in text,

    "WHEEL_NONEMPTY_CHECK":
        "pam_wheel_has_members()" in text,

    "WHEEL_ADMIN_VALIDATION":
        "pam_wheel_user_is_existing_admin()" in text,

    "WHEEL_EMPTY_RISK":
        "wheel group is empty — su is unavailable to non-root users"
        in text,

    "AGING_MANIFEST_FIELD":
        '"password_aging_snapshots": []' in text,

    "AGING_RECORD_FUNCTION":
        "record_manifest_password_aging_snapshot()" in text,

    "AGING_RESTORE_FUNCTION":
        "restore_password_aging_snapshots()" in text,

    "AGING_RECORD_CALL":
        'record_manifest_password_aging_snapshot "$account"'
        in text,

    "AGING_RESTORE_CALL":
        "    restore_password_aging_snapshots" in text,

    "AGING_DEDUPLICATION":
        'item.get("user") == account' in text,

    "AGING_RESTORE_LAST_CHANGE":
        '-d "$last_change"' in text,

    "AGING_RESTORE_MIN":
        '-m "$min_days"' in text,

    "AGING_RESTORE_MAX":
        '-M "$max_days"' in text,

    "AGING_RESTORE_WARN":
        '-W "$warn_days"' in text,

    "AGING_RESTORE_INACTIVE":
        '-I "$inactive_days"' in text,

    "AGING_RESTORE_EXPIRE":
        '-E "$expire_date"' in text,
}

for name, result in checks.items():
    print(f"{name}={result}")
    require(result, name)

snapshot_position = text.find(
    'record_manifest_password_aging_snapshot "$account"'
)
chage_position = text.find(
    'chage -m "$PASS_MIN_DAYS"',
    snapshot_position,
)

require(
    snapshot_position >= 0
    and chage_position > snapshot_position,
    "AGING_SNAPSHOT_NOT_BEFORE_CHAGE",
)

wheel_add_position = text.find(
    'gpasswd -a "$user_name" wheel'
)
pam_write_position = text.find(
    'python3 - "$PAM_SU_FILE"',
    wheel_add_position,
)

require(
    wheel_add_position >= 0
    and pam_write_position > wheel_add_position,
    "PAM_WHEEL_WRITTEN_BEFORE_MEMBER_ADD",
)

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=WHEEL_AGING_REGRESSION_OK")
PYTEST

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

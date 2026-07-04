#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/securelinux-ng.sh" <<'PYTEST'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

def function_text(name):
    matches = list(
        re.finditer(
            r"(?m)^([A-Za-z0-9_]+)\(\) \{$",
            source,
        )
    )

    for index, match in enumerate(matches):
        if match.group(1) != name:
            continue

        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(source)
        )
        return source[match.start():end]

    errors.append(f"FUNCTION_NOT_FOUND:{name}")
    return ""

def require_order(text, markers, message):
    cursor = 0

    for marker in markers:
        position = text.find(marker, cursor)
        if position < 0:
            errors.append(f"{message}:MISSING:{marker}")
            return
        cursor = position + len(marker)

forbidden = (
    'cp -a "$fstab" "$bak"',
    'cp -a "$PWQUALITY_CONF" "$pwquality_backup_before_dependencies"',
    'cp -a "$pwhistory_file" "$bak_ph"',
    'cp -a "$LOGIN_DEFS" "$bak2"',
)

for marker in forbidden:
    require(
        marker not in source,
        f"UNCHECKED_BACKUP_REMAINS:{marker}",
    )

mount = function_text("apply_mount_hardening_module")
require_order(
    mount,
    (
        'backup_file_checked "$fstab" "$bak" "mount hardening fstab"',
        'add_skipped "mount hardening apply skipped: fstab backup failed"',
        "return 0",
        'record_manifest_backup "$fstab" "$bak"',
        'python3 - "$fstab"',
    ),
    "MOUNT_HARDENING_BACKUP_GUARD_BROKEN",
)

tmp_tmpfs = function_text("apply_tmp_tmpfs_module")
require_order(
    tmp_tmpfs,
    (
        'backup_file_checked "$fstab" "$bak" "/tmp tmpfs fstab"',
        'add_skipped "/tmp tmpfs apply skipped: fstab backup failed"',
        "return 0",
        'record_manifest_backup "$fstab" "$bak"',
        'python3 - "$fstab"',
    ),
    "TMP_TMPFS_BACKUP_GUARD_BROKEN",
)

password = function_text("apply_password_policy_module")

require_order(
    password,
    (
        '"CORP-PASSWORD pwquality.conf pre-install"',
        'add_error "CORP-PASSWORD зависимости не устанавливались: backup pwquality.conf failed"',
        "return 1",
        'record_manifest_backup',
        'log "[i]     pwquality/Cracklib:',
    ),
    "PWQUALITY_PREINSTALL_BACKUP_GUARD_BROKEN",
)

require_order(
    password,
    (
        '"CORP-PASSWORD common-password"',
        'add_error "CORP-PASSWORD common-password не изменён: backup failed"',
        "return 1",
        'record_manifest_backup "$pwhistory_file" "$bak_ph"',
        'normalize_common_password_stack',
    ),
    "COMMON_PASSWORD_BACKUP_GUARD_BROKEN",
)

require_order(
    password,
    (
        '"CORP-PASSWORD login.defs"',
        'add_error "CORP-PASSWORD login.defs не изменён: backup failed"',
        "return 1",
        'record_manifest_backup "$LOGIN_DEFS" "$bak2"',
        'python3 - "$LOGIN_DEFS"',
    ),
    "LOGIN_DEFS_BACKUP_GUARD_BROKEN",
)

if errors:
    for error in errors:
        print(error)
    raise SystemExit(1)

print("RESULT=BACKUP_FAILURE_REGRESSION_OK")
PYTEST

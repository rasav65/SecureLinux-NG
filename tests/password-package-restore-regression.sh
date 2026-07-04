#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(
    encoding="utf-8"
)

checks = {
    "MANIFEST_FIELD":
        '"installed_packages": []' in text,

    "RECORD_FUNCTION":
        "record_manifest_installed_package() {" in text,

    "SNAPSHOT_FUNCTION":
        "snapshot_installed_packages() {" in text,

    "DIFF_FUNCTION":
        "record_newly_installed_packages() {" in text,

    "RESTORE_FUNCTION":
        "restore_installed_packages() {" in text,

    "PASSWORD_RECORD_CALL":
        'record_newly_installed_packages "password-policy"' in text,

    "PASSWORD_RESTORE_CALL":
        'restore_installed_packages "password-policy"' in text,

    "PWQUALITY_PREINSTALL_STATE":
        "pwquality_existed_before_dependencies" in text,

    "PWQUALITY_PREINSTALL_BACKUP":
        "pwquality_backup_before_dependencies" in text,

    "PWQUALITY_CREATED_FILE_TRACKING":
        (
            'record_manifest_created_file "$PWQUALITY_CONF"'
            in text
            and "pwquality_existed_before_dependencies == 0"
            in text
        ),
}

for name, result in checks.items():
    print(f"{name}={result}")

if not all(checks.values()):
    raise SystemExit(1)

restore_start = text.index(
    "restore_installed_packages() {"
)
restore_end = text.index(
    "\nruntime_paths_scan() {",
    restore_start,
)

restore_block = text[restore_start:restore_end]

if "apt-get purge" not in restore_block:
    print("RESTORE_PURGE=False")
    raise SystemExit(1)

print("RESTORE_PURGE=True")
print("RESULT=PASSWORD_PACKAGE_RESTORE_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

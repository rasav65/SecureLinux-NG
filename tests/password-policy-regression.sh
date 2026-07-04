#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/securelinux-ng.sh" <<'PYTEST'
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

script = Path(sys.argv[1])
text = script.read_text(encoding="utf-8")
errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

require(
    "ENABLE_CORPORATE_PASSWORD_POLICY=0" in text,
    "DEFAULT_POLICY_NOT_DISABLED",
)
require(
    "ENABLE_CORPORATE_PASSWORD_POLICY)" in text,
    "CONFIG_FLAG_NOT_PARSED",
)
require(
    "even_deny_root" not in text,
    "FAILLOCK_ROOT_LOCKOUT_OPTION_PRESENT",
)
require(
    "/etc/pam.d/common-auth" in text
    and "/etc/pam.d/common-account" in text,
    "FAILLOCK_COMMON_PAM_PATHS_MISSING",
)
require(
    "pam_faillock.so preauth" in text
    and "pam_faillock.so authfail" in text
    and "account" in text,
    "FAILLOCK_PAM_STACK_IMPLEMENTATION_MISSING",
)
require(
    "/lib/*-linux-gnu/security/pam_faillock.so" in text
    and "/usr/lib/*-linux-gnu/security/pam_faillock.so" in text
    and "pam_faillock_found" in text,
    "FAILLOCK_MULTIARCH_MODULE_SEARCH_MISSING",
)
require(
    'restore_file_from_manifest "$PAM_COMMON_AUTH_FILE"' in text
    and 'restore_file_from_manifest "$PAM_COMMON_ACCOUNT_FILE"' in text,
    "FAILLOCK_COMMON_PAM_RESTORE_MISSING",
)
require(
    "corporate_password_policy_enabled()" in text,
    "POLICY_GATE_HELPER_MISSING",
)

for function in (
    "check_faillock_module",
    "apply_faillock_module",
):
    marker = f"{function}() {{"
    start = text.find(marker)
    require(start >= 0, f"{function.upper()}_NOT_FOUND")
    require(
        start >= 0
        and "corporate_password_policy_enabled"
        in text[start:start + 500],
        f"{function.upper()}_NOT_GATED",
    )

require(
    "ФСТЭК 2.1.x" not in text
    and "политика паролей ФСТЭК" not in text,
    "CORPORATE_POLICY_FALSELY_MARKED_AS_FSTEC",
)

require(
    '"item": "2.1", "status": "partial", '
    '"restore": "managed-file", "module": "pam_faillock"'
    not in text,
    "FAILLOCK_STILL_REGISTERED_AS_FSTEC_2_1",
)
require(
    '"item": "2.1", "status": "partial", '
    '"restore": "managed-file+runtime-state", '
    '"module": "password_policy"'
    not in text,
    "PASSWORD_POLICY_STILL_REGISTERED_AS_FSTEC_2_1",
)
require(
    '"item": "corporate_faillock"' in text
    and '"item": "corporate_password_policy"' in text,
    "CORPORATE_REGISTRY_ITEMS_MISSING",
)
require(
    "2.1 pam_faillock" not in text
    and "2.1 pwquality" not in text
    and "4.1 chage" not in text,
    "CORPORATE_MESSAGES_STILL_USE_STANDARD_NUMBERS",
)
require(
    "PAM_ACTIVE_DICTIONARY_BROKEN" in text,
    "PAM_DICTIONARY_DIAGNOSTIC_MISSING",
)
require(
    "LOCKED_ROOT_PASSWORD_EXPIRES" in text,
    "LOCKED_ROOT_AGING_DIAGNOSTIC_MISSING",
)
require(
    "SECURELINUX_NG_PASSWD_FILE" in text
    and "SECURELINUX_NG_SHADOW_FILE" in text,
    "ACCOUNT_TEST_PATHS_MISSING",
)

apply_match = re.search(
    r"apply_password_policy_module\(\)\s*\{(.*?)\n\}",
    text,
    re.S,
)
if not apply_match:
    errors.append("APPLY_FUNCTION_NOT_FOUND")
else:
    block = apply_match.group(1)

    require(
        "corporate_password_policy_enabled" in block,
        "APPLY_POLICY_NOT_GATED",
    )
    require(
        "pkg_installed libpam-pwquality ||" not in block,
        "DEFECTIVE_PACKAGE_SHORT_CIRCUIT_PRESENT",
    )
    for package in ("libpam-pwquality", "cracklib-runtime", "wamerican"):
        require(package in block, f"REQUIRED_PACKAGE_MISSING:{package}")

    update_pos = block.find("update-cracklib")
    mutation_positions = [
        pos for pos in (
            block.find('python3 - "$PWQUALITY_CONF"'),
            block.find("normalize_common_password_stack"),
            block.find('python3 - "$LOGIN_DEFS"'),
        )
        if pos >= 0
    ]
    require(update_pos >= 0, "UPDATE_CRACKLIB_MISSING")
    require(
        update_pos >= 0
        and mutation_positions
        and update_pos < min(mutation_positions),
        "CRACKLIB_NOT_VERIFIED_BEFORE_CONFIGURATION_CHANGE",
    )
    require(
        "'ENCRYPT_METHOD':" not in block,
        "NON_FSTEC_ENCRYPT_METHOD_FORCED",
    )

    dry_run_match = re.search(
        r"if \(\( DRY_RUN == 1 \)\); then(.*?)\n    fi",
        block,
        re.S,
    )
    require(
        dry_run_match is not None,
        "PASSWORD_POLICY_DRY_RUN_BLOCK_MISSING",
    )
    require(
        dry_run_match is not None
        and 'apply_password_policy_existing_accounts "$max_days"'
        in dry_run_match.group(1),
        "PASSWORD_POLICY_DRY_RUN_OMITS_CHAGE_PLAN",
    )

account_match = re.search(
    r"list_password_policy_target_accounts\(\)\s*\{.*?"
    r"<<'PYJSON'\n(.*?)\nPYJSON",
    text,
    re.S,
)

if not account_match:
    errors.append("ACCOUNT_SELECTOR_NOT_FOUND")
elif (
    "SECURELINUX_NG_PASSWD_FILE" in text
    and "SECURELINUX_NG_SHADOW_FILE" in text
):
    selector = account_match.group(1)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        passwd = tmp / "passwd"
        shadow = tmp / "shadow"

        passwd.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
            "locked:x:1001:1001:Locked:/home/locked:/bin/bash\n"
            "service:x:1002:1002:Service:/srv/service:/usr/sbin/nologin\n"
            "empty:x:1003:1003:Empty:/home/empty:/bin/bash\n",
            encoding="utf-8",
        )
        shadow.write_text(
            "root:*:19769:0:99999:7:::\n"
            "admin:$y$active:20000:0:90:14:::\n"
            "locked:!$y$locked:20000:0:90:14:::\n"
            "service:$y$service:20000:0:90:14:::\n"
            "empty::20000:0:90:14:::\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["SECURELINUX_NG_PASSWD_FILE"] = str(passwd)
        env["SECURELINUX_NG_SHADOW_FILE"] = str(shadow)

        result = subprocess.run(
            ["python3", "-", "1000"],
            input=selector,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        require(
            result.returncode == 0,
            f"ACCOUNT_SELECTOR_FAILED:{result.stderr.strip()}",
        )
        require(
            result.stdout.splitlines() == ["admin"],
            "LOCKED_OR_SERVICE_ACCOUNT_SELECTED:"
            + repr(result.stdout.splitlines()),
        )


with tempfile.TemporaryDirectory() as tmp_name:
    tmp = Path(tmp_name)

    pam_file = tmp / "common-password"
    pwquality_file = tmp / "pwquality.conf"
    pwquality_dir = tmp / "pwquality.conf.d"
    cracklib_dir = tmp / "cracklib"
    cracklib_check = Path("/bin/cat")
    shadow_file = tmp / "shadow"
    config_file = tmp / "config.conf"

    pwquality_dir.mkdir()
    cracklib_dir.mkdir()

    pam_file.write_text(
        "password requisite pam_pwquality.so retry=3\n",
        encoding="utf-8",
    )
    pwquality_file.write_text("", encoding="utf-8")

    config_file.write_text(
        "PROFILE=baseline\n"
        "ENABLE_CORPORATE_PASSWORD_POLICY=0\n"
        f"STATE_DIR={tmp / 'state'}\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.update({
        "SECURELINUX_NG_COMMON_PASSWORD_FILE": str(pam_file),
        "SECURELINUX_NG_PWQUALITY_CONF_FILE": str(pwquality_file),
        "SECURELINUX_NG_PWQUALITY_CONF_DIR": str(pwquality_dir),
        "SECURELINUX_NG_CRACKLIB_DIR": str(cracklib_dir),
        "SECURELINUX_NG_CRACKLIB_CHECK": str(cracklib_check),
        "SECURELINUX_NG_SHADOW_FILE": str(shadow_file),
    })

    # Аварийный сценарий:
    # pam_pwquality активен, словарей нет, root заблокирован,
    # но имеет конечный срок действия пароля.
    shadow_file.write_text(
        "root:!:20000:0:90:14:::\n",
        encoding="utf-8",
    )

    broken = subprocess.run(
        [str(script), "--check", "--config", str(config_file)],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    broken_output = broken.stdout + broken.stderr

    require(
        "PAM_ACTIVE_DICTIONARY_BROKEN" in broken_output,
        "BROKEN_CRACKLIB_NOT_DETECTED",
    )
    require(
        "LOCKED_ROOT_PASSWORD_EXPIRES" in broken_output,
        "LOCKED_ROOT_FINITE_AGING_NOT_DETECTED",
    )

    # Безопасный сценарий:
    # словари присутствуют, root заблокирован бессрочно.
    for suffix in ("pwd", "pwi", "hwm"):
        (cracklib_dir / f"cracklib_dict.{suffix}").write_text(
            "test\n",
            encoding="utf-8",
        )

    shadow_file.write_text(
        "root:!:20000:0:99999:14:::\n",
        encoding="utf-8",
    )

    safe = subprocess.run(
        [str(script), "--check", "--config", str(config_file)],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    safe_output = safe.stdout + safe.stderr

    require(
        "PAM_ACTIVE_DICTIONARY_BROKEN" not in safe_output,
        "VALID_CRACKLIB_REPORTED_BROKEN",
    )
    require(
        "LOCKED_ROOT_PASSWORD_EXPIRES" not in safe_output,
        "LOCKED_ROOT_UNLIMITED_REPORTED_FINITE",
    )
    require(
        "словарный backend работоспособен" in safe_output,
        "VALID_CRACKLIB_SAFE_RESULT_MISSING",
    )
    require(
        "пароль заблокирован и не имеет конечного срока" in safe_output,
        "LOCKED_ROOT_UNLIMITED_SAFE_RESULT_MISSING",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=PASSWORD_POLICY_REGRESSION_OK")
PYTEST

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

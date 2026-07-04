#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
import re
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")
errors = []


def function_block(name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n"
        rf"(.*?)(?=^[a-zA-Z0-9_]+\(\) \{{\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        errors.append(f"FUNCTION_MISSING={name}")
        return ""
    return match.group(1)


checks = {
    "apply_runtime_paths_module": ('*"file_go_w"*',),
    "apply_cron_command_paths_module": ('*"file_go_w"*',),
    "apply_standard_system_paths_module": ('*"file_go_w"*',),
    "apply_sudo_command_paths_module": (
        '*"file_go_w"*',
        '*"owner_not_root"*',
    ),
}

for name, required_reasons in checks.items():
    block = function_block(name)
    if not block:
        continue

    parent_match = re.search(
        r'if \[\[ "\$reason" == \*"parent_go_w:"\* \]\]; then'
        r'(.*?)'
        r'\n[ \t]*fi',
        block,
        flags=re.DOTALL,
    )

    if not parent_match:
        errors.append(f"PARENT_BRANCH_MISSING={name}")
    elif "continue" in parent_match.group(1):
        errors.append(f"PARENT_WARNING_SKIPS_FILE={name}")

    for marker in required_reasons:
        if marker not in block:
            errors.append(
                f"FILE_REASON_GUARD_MISSING={name}:{marker}"
            )

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=RUNTIME_PATHS_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

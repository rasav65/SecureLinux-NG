#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")

start = text.index("apply_sysctl_attack_surface_module() {")
end = text.index(
    "\nrestore_sysctl_attack_surface_module() {",
    start,
)
block = text[start:end]

errors = []

if "preserve_stricter_sysctl_values" not in block:
    errors.append("APPLY_HELPER_CALL_MISSING")

helper_start = text.find("preserve_stricter_sysctl_values() {")
if helper_start == -1:
    errors.append("HELPER_MISSING")
else:
    helper_end = text.find("\n}", helper_start)
    helper = text[helper_start:helper_end]

    for key in (
        "kernel.perf_event_paranoid",
        "kernel.unprivileged_bpf_disabled",
        "vm.mmap_min_addr",
    ):
        if key not in helper:
            errors.append(f"HELPER_KEY_MISSING={key}")

expected_check = """    if key in (
        "kernel.perf_event_paranoid",
        "vm.mmap_min_addr",
        "kernel.unprivileged_bpf_disabled",
    ):
"""

if expected_check not in text:
    errors.append("STRICTER_CHECK_SEMANTICS_MISSING")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=SYSCTL_STRICTER_VALUES_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

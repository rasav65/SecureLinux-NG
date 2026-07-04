#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
import re
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")
errors = []

if "ENABLE_ADDITIONAL_MEASURES=0" not in text:
    errors.append("ADDITIONAL_MEASURES_DEFAULT_OFF_MISSING")

if "additional_measures_enabled() {" not in text:
    errors.append("ADDITIONAL_MEASURES_HELPER_MISSING")

if "ENABLE_ADDITIONAL_MEASURES)" not in text:
    errors.append("ADDITIONAL_MEASURES_CONFIG_PARSER_MISSING")

cli_checks = {
    "ADDITIONAL_MEASURES_CLI_MARKER_DEFAULT_MISSING":
        "_ADDITIONAL_MEASURES_SET_BY_CLI=0",
    "ADDITIONAL_MEASURES_USAGE_APPLY_MISSING":
        "./securelinux-ng.sh --apply [--dry-run] [--enable-additional-measures]",
    "ADDITIONAL_MEASURES_USAGE_OPTION_MISSING":
        "--enable-additional-measures",
    "ADDITIONAL_MEASURES_CLI_ENABLE_MISSING":
        "ENABLE_ADDITIONAL_MEASURES=1",
    "ADDITIONAL_MEASURES_CLI_MARKER_SET_MISSING":
        "_ADDITIONAL_MEASURES_SET_BY_CLI=1",
    "ADDITIONAL_MEASURES_MODE_VALIDATION_MISSING":
        'die "--enable-additional-measures допустим только вместе с --apply"',
    "ADDITIONAL_MEASURES_UNKNOWN_ARGUMENT_GUARD_MISSING":
        'die "Неизвестный аргумент: $1"',
}

for error, marker in cli_checks.items():
    if marker not in text:
        errors.append(error)

parse_start = text.index("parse_args() {")
parse_end = text.index("\nvalidate_args() {", parse_start)
parse_block = text[parse_start:parse_end]

cli_case = re.search(
    r'--enable-additional-measures\)\n'
    r'\s*ENABLE_ADDITIONAL_MEASURES=1\n'
    r'\s*_ADDITIONAL_MEASURES_SET_BY_CLI=1\n'
    r'\s*;;',
    parse_block,
)

if not cli_case:
    errors.append("ADDITIONAL_MEASURES_CLI_PARSER_INVALID")

validate_start = text.index("validate_args() {")
validate_end = text.index("\nvalidate_args_post_config() {", validate_start)
validate_block = text[validate_start:validate_end]

if not re.search(
    r'if \(\( _ADDITIONAL_MEASURES_SET_BY_CLI == 1 \)\) '
    r'&& \[\[ "\$MODE" != "apply" \]\]; then\n'
    r'\s*die "--enable-additional-measures допустим только вместе с --apply"',
    validate_block,
):
    errors.append("ADDITIONAL_MEASURES_MODE_VALIDATION_INVALID")

config_start = text.index("load_config() {")
config_end = text.index("\nrestore_manifest_has_path() {", config_start)
config_block = text[config_start:config_end]

config_guard_checks = (
    "(( _ADDITIONAL_MEASURES_SET_BY_CLI == 0 )) && ENABLE_ADDITIONAL_MEASURES=1",
    "(( _ADDITIONAL_MEASURES_SET_BY_CLI == 0 )) && ENABLE_ADDITIONAL_MEASURES=0",
)

for marker in config_guard_checks:
    if marker not in config_block:
        errors.append(f"ADDITIONAL_MEASURES_CONFIG_PRIORITY_MISSING={marker}")

start = text.index("run_apply_mode() {")
end = text.index("\nrun_restore_mode() {", start)
apply_block = text[start:end]

gate = re.search(
    r'if additional_measures_enabled; then\n'
    r'(.*?)'
    r'\n[ \t]*fi',
    apply_block,
    flags=re.DOTALL,
)

extra_apply_modules = (
    "apply_ssh_hardening_module",
    "apply_account_audit_module",
    "apply_apparmor_module",
    "apply_aide_module",
    "apply_fail2ban_module",
    "apply_rkhunter_module",
    "apply_kernel_modules_module",
    "apply_mount_hardening_module",
    "apply_tmp_tmpfs_module",
    "apply_ufw_module",
    "apply_auditd_module",
    "apply_rsyslog_module",
    "apply_chrony_module",
    "apply_unattended_upgrades_module",
    "apply_apport_module",
    "apply_coredump_module",
    "apply_sysctl_network_module",
)

if not gate:
    errors.append("ADDITIONAL_MEASURES_APPLY_GATE_MISSING")
else:
    gate_block = gate.group(1)

    for module in extra_apply_modules:
        if module not in gate_block:
            errors.append(
                f"ADDITIONAL_APPLY_NOT_GATED={module}"
            )

manifest_checks = (
    '"additional_measures_enabled":',
    '"$ENABLE_ADDITIONAL_MEASURES"',
)

for marker in manifest_checks:
    if marker not in text:
        errors.append(f"MANIFEST_FLAG_MISSING={marker}")

restore_start = text.index("run_restore_mode() {")
restore_end = text.index("\nrun_report_mode() {", restore_start)
restore_block = text[restore_start:restore_end]

if "restore_additional_measures" not in restore_block:
    errors.append("RESTORE_FLAG_LOAD_MISSING")

restore_gates = re.findall(
    r'if \(\( restore_additional_measures == 1 \)\); then\n'
    r'(.*?)'
    r'\n[ \t]*fi',
    restore_block,
    flags=re.DOTALL,
)

extra_restore_modules = (
    "restore_ssh_hardening_module",
    "restore_account_audit_module",
    "restore_apparmor_module",
    "restore_aide_module",
    "restore_fail2ban_module",
    "restore_rkhunter_module",
    "restore_kernel_modules_module",
    "restore_mount_hardening_module",
    "restore_tmp_tmpfs_module",
    "restore_ufw_module",
    "restore_auditd_module",
    "restore_sysctl_network_module",
    "restore_rsyslog_module",
    "restore_chrony_module",
    "restore_unattended_upgrades_module",
    "restore_apport_module",
    "restore_coredump_module",
)

if not restore_gates:
    errors.append("ADDITIONAL_MEASURES_RESTORE_GATE_MISSING")
else:
    gate_block = "\n".join(restore_gates)
    for module in extra_restore_modules:
        if module not in gate_block:
            errors.append(f"ADDITIONAL_RESTORE_NOT_GATED={module}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=ADDITIONAL_MEASURES_OPTIN_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

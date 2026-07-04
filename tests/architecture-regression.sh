#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/securelinux-ng.sh" "$ROOT/docs/architecture.md" <<'PYTEST'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
docs = Path(sys.argv[2]).read_text(encoding="utf-8")
errors = []
fence = chr(96) * 3


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
            errors.append(
                f"{message}:MISSING_OR_OUT_OF_ORDER:{marker}"
            )
            return
        cursor = position + len(marker)


required_headings = (
    "## Общая схема выполнения",
    "## Карта модулей усиления безопасности",
    "## Поток apply, manifest и restore",
)

for heading in required_headings:
    require(
        docs.count(heading) == 1,
        f"ARCHITECTURE_HEADING_INVALID:{heading}",
    )

require(
    docs.count(fence + "mermaid") == 3,
    "MERMAID_BLOCK_COUNT_INVALID",
)
require(
    docs.count("flowchart TB") == 3,
    "MERMAID_FLOWCHART_COUNT_INVALID",
)
require(
    "UFW_ALLOW_FROM_" not in docs,
    "STALE_UFW_ALLOW_FROM_REFERENCE",
)

required_doc_markers = (
    "parse_args()",
    "require_cmds()",
    "validate_args()",
    "load_config()",
    "validate_args_post_config()",
    "validate_execution_context()",
    "finalize_paths()",
    "run_check_mode()",
    "run_apply_mode()",
    "run_restore_mode()",
    "run_report_mode()",
    "run_preflight()",
    "check_memory_requirements()",
    "ensure_state_dir()",
    "acquire_run_lock()",
    "manifest_init()",
    "resolve_restore_manifest()",
    "backup_file_checked()",
    "additional_measures_enabled",
    "ENABLE_CORPORATE_PASSWORD_POLICY = 1?",
    "kernel.modules_disabled (временно SKIP)",
    "added_group_memberships",
    "password_aging_snapshots",
    "apply_report",
    "последний manifest-*.json",
    "manifest.json",
)

for marker in required_doc_markers:
    require(
        marker in docs,
        f"ARCHITECTURE_MARKER_MISSING:{marker}",
    )

main = function_text("main")
require_order(
    main,
    (
        'parse_args "$@"',
        "require_cmds",
        "validate_args",
        "load_config",
        "validate_args_post_config",
        "validate_execution_context",
        "finalize_paths",
        'case "$MODE" in',
    ),
    "MAIN_PIPELINE_CHANGED",
)

for marker in (
    "check) run_check_mode ;;",
    "apply) run_apply_mode ;;",
    "restore) run_restore_mode ;;",
    "report) run_report_mode ;;",
):
    require(marker in main, f"MAIN_DISPATCH_CHANGED:{marker}")

check = function_text("run_check_mode")
require_order(
    check,
    (
        "run_preflight",
        "check_empty_passwords_module",
        "check_ssh_root_login_module",
        "if additional_measures_enabled; then",
        "check_pam_wheel_module",
        "write_report",
        "print_report_stdout",
    ),
    "CHECK_FLOW_CHANGED",
)

apply = function_text("run_apply_mode")
require_order(
    apply,
    (
        "run_preflight",
        "check_memory_requirements",
        "ensure_state_dir",
        "acquire_run_lock",
        "manifest_init",
        "apply_empty_passwords_module",
        "if additional_measures_enabled; then",
        "apply_pam_wheel_module",
        "apply_faillock_module",
        "apply_password_policy_module",
        "write_report",
        "print_report_stdout",
    ),
    "APPLY_FLOW_CHANGED",
)

restore = function_text("run_restore_mode")
require_order(
    restore,
    (
        "run_preflight",
        "resolve_restore_manifest",
        "ensure_state_dir",
        "acquire_run_lock",
        'data.get("additional_measures_enabled", True)',
        "restore_ssh_root_login_module",
        "if (( restore_additional_measures == 1 )); then",
        "restore_pam_wheel_module",
        "write_report",
        "print_report_stdout",
    ),
    "RESTORE_FLOW_CHANGED",
)

report = function_text("run_report_mode")
require_order(
    report,
    (
        "run_preflight",
        "ensure_state_dir",
        "write_report",
        "print_report_stdout",
    ),
    "REPORT_FLOW_CHANGED",
)

for function_name in (
    "check_faillock_module",
    "apply_faillock_module",
    "check_password_policy_module",
    "apply_password_policy_module",
):
    function = function_text(function_name)
    require(
        "corporate_password_policy_enabled" in function,
        f"CORPORATE_POLICY_GATE_CHANGED:{function_name}",
    )

resolve = function_text("resolve_restore_manifest")
require_order(
    resolve,
    (
        'if [[ -n "$RESTORE_MANIFEST" ]]',
        'base.glob("manifest-*.json")',
        'base / "manifest.json"',
    ),
    "RESTORE_MANIFEST_SELECTION_CHANGED",
)

for marker in (
    "backup_file_checked() {",
    "manifest_init() {",
    "corporate_password_policy_enabled() {",
    "os.replace(tmp_path, str(path))",
    '"additional_measures_enabled":',
    '"added_group_memberships":',
    '"password_aging_snapshots":',
    '"apply_report":',
):
    require(
        marker in source,
        f"ARCHITECTURE_SOURCE_MARKER_MISSING:{marker}",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=ARCHITECTURE_REGRESSION_OK")
PYTEST

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

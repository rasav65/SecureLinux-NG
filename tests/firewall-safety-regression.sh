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
    pattern = re.compile(
        rf"(?ms)^{re.escape(name)}\(\) \{{.*?(?=^[A-Za-z0-9_]+\(\) \{{|\Z)"
    )
    match = pattern.search(source)
    if not match:
        errors.append(f"FUNCTION_NOT_FOUND:{name}")
        return ""
    return match.group(0)

require(
    "ufw --force reset" not in source,
    "UFW_DESTRUCTIVE_RESET_REMAINS",
)

ufw = function_text("apply_ufw_module")
require(
    'ufw show added' in ufw
    and "inactive ufw has preconfigured rules" in ufw
    and "automatic enable skipped" in ufw
    and "return 1" in ufw,
    "INACTIVE_UFW_RULE_PROTECTION_MISSING",
)

validator = function_text("valid_tcp_port")
require(
    '[[ "$value" =~ ^[0-9]+$ ]]' in validator
    and '10#$value >= 1' in validator
    and '10#$value <= 65535' in validator,
    "TCP_PORT_VALIDATION_MISSING",
)

resolver = function_text("resolve_ssh_port")
require(
    'valid_tcp_port "$fallback"' in resolver
    and 'valid_tcp_port "$detected"' in resolver
    and 'SSH_PORT_RESOLVED="$fallback"' in resolver,
    "SSH_PORT_RESOLVER_INCOMPLETE",
)

fail2ban = function_text("apply_fail2ban_module")
require(
    'resolve_ssh_port "$ssh_port"' in fail2ban
    and 'ssh_port="$SSH_PORT_RESOLVED"' in fail2ban,
    "FAIL2BAN_PORT_VALIDATION_MISSING",
)

require(
    'resolve_ssh_port "$ssh_port"' in ufw
    and 'ssh_port="$SSH_PORT_RESOLVED"' in ufw,
    "UFW_PORT_VALIDATION_MISSING",
)

if errors:
    for error in errors:
        print(error)
    raise SystemExit(1)

print("RESULT=FIREWALL_SAFETY_REGRESSION_OK")
PYTEST

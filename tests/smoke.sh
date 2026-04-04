#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

TMP_STATE_DIR="$(pwd)/.tmp-test-state"
TMP_FIXTURE_DIR="$(pwd)/.tmp-smoke-fixture"
TMP_CONFIG="$(pwd)/.tmp-smoke.conf"
TMP_MANIFEST="$(pwd)/.tmp-restore-manifest.json"
TMP_REPORT="$(pwd)/.tmp-smoke-report.json"

rm -rf "$TMP_STATE_DIR" "$TMP_FIXTURE_DIR"
mkdir -p   "$TMP_FIXTURE_DIR/home/user1"   "$TMP_FIXTURE_DIR/cron/crontabs"   "$TMP_FIXTURE_DIR/proc/123"   "$TMP_FIXTURE_DIR/roots/bin"   "$TMP_FIXTURE_DIR/roots/lib"

: > "$TMP_FIXTURE_DIR/home/user1/.bashrc"
: > "$TMP_FIXTURE_DIR/cron/crontabs/user1"
: > "$TMP_FIXTURE_DIR/roots/bin/runtime-bin"
: > "$TMP_FIXTURE_DIR/roots/lib/libsample.so"
chmod 700 "$TMP_FIXTURE_DIR/home/user1"
chmod 600 "$TMP_FIXTURE_DIR/home/user1/.bashrc" "$TMP_FIXTURE_DIR/cron/crontabs/user1"
chmod 755 "$TMP_FIXTURE_DIR/roots/bin/runtime-bin" "$TMP_FIXTURE_DIR/roots/lib/libsample.so"
ln -s "$TMP_FIXTURE_DIR/roots/bin/runtime-bin" "$TMP_FIXTURE_DIR/proc/123/exe"

export SECURELINUX_NG_RUNTIME_PROC_ROOT="$TMP_FIXTURE_DIR/proc"
export SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS=0
export SECURELINUX_NG_HOME_BASE_DIR="$TMP_FIXTURE_DIR/home"
export SECURELINUX_NG_USER_CRON_DIRS="$TMP_FIXTURE_DIR/cron:$TMP_FIXTURE_DIR/cron/crontabs"
export SECURELINUX_NG_STANDARD_SYSTEM_PATHS="$TMP_FIXTURE_DIR/roots/bin:$TMP_FIXTURE_DIR/roots/lib"
export SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_ENV_PATH=0
export SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_KERNEL_MODULES=0
export SECURELINUX_NG_SUID_SGID_PATHS="$TMP_FIXTURE_DIR/roots/bin:$TMP_FIXTURE_DIR/roots/lib"

run_unprivileged() {
    if [ "$(id -u)" -eq 0 ]; then
        su -s /bin/sh nobody -c "$*"
    else
        "$@"
    fi
}

cat > "$TMP_CONFIG" <<EOF
PROFILE=baseline
STATE_DIR=$TMP_STATE_DIR
REPORT_FILE=$TMP_REPORT
EOF

cat > "$TMP_MANIFEST" <<EOF
{
  "version": "16.2.3",
  "profile": "baseline",
  "mode": "apply",
  "timestamp": "2026-03-14T00:00:00",
  "backups": [],
  "created_files": [],
  "created_groups": [],
  "modified_files": [],
  "systemd_units": [],
  "sysctl_configs": [],
  "grub_backups": [],
  "apply_report": [],
  "warnings": [],
  "irreversible_changes": []
}
EOF

./securelinux-ng.sh --version &&
./securelinux-ng.sh --help >/dev/null &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --report --config "$TMP_CONFIG" >/dev/null &&
run_unprivileged ./securelinux-ng.sh --apply --config "$TMP_CONFIG" 2>&1 | grep -q -- "--apply без --dry-run требует root" &&
run_unprivileged ./securelinux-ng.sh --restore --manifest "$TMP_MANIFEST" --config "$TMP_CONFIG" 2>&1 | grep -q -- "--restore требует root" &&
run_unprivileged ./securelinux-ng.sh --restore --config "$TMP_CONFIG" 2>&1 | grep -q -- "--restore требует root" &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'позиций в реестре: 60' &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'статус partial' &&

python3 - "$TMP_REPORT" <<'PYCHECK'
import json, pathlib, sys

report = pathlib.Path(sys.argv[1])
data = json.loads(report.read_text(encoding="utf-8"))

items = {entry["item"] for entry in data.get("fstec_items", [])}

# Обязательные ФСТЭК-пункты
required_fstec = {
    "2.1.1", "2.1.2",
    "2.2.1", "2.2.2",
    "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6", "2.3.7", "2.3.8", "2.3.9",
    "2.3.10", "2.3.11",
    "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8",
    "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.6", "2.5.7", "2.5.8", "2.5.9", "2.5.10", "2.5.11",
    "2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.6.5", "2.6.6",
}
missing = sorted(required_fstec - items)
if missing:
    raise SystemExit("Missing FSTEC items: " + ", ".join(missing))

summary = data.get("fstec_summary", {})
implemented = summary.get("implemented_items", 0)
if implemented < 55:
    raise SystemExit(f"implemented_items={implemented} < 51")

done = summary.get("done", 0)
if done < 33:
    raise SystemExit(f"done={done} < 33")

# Проверяем наличие новых модулей
extra_required = {"2.1", "audit", "firewall", "mount", "fail2ban", "aide", "apparmor", "account_audit", "kernel_modules"}
missing_extra = sorted(extra_required - items)
if missing_extra:
    raise SystemExit("Missing extra modules: " + ", ".join(missing_extra))

print(f"OK: implemented={implemented} done={done}")
PYCHECK

rc=$?
rm -f "$TMP_CONFIG" "$TMP_MANIFEST" "$TMP_REPORT"
unset SECURELINUX_NG_RUNTIME_PROC_ROOT SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS SECURELINUX_NG_HOME_BASE_DIR SECURELINUX_NG_USER_CRON_DIRS SECURELINUX_NG_STANDARD_SYSTEM_PATHS SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_ENV_PATH SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_KERNEL_MODULES SECURELINUX_NG_SUID_SGID_PATHS
rm -rf "$TMP_STATE_DIR" "$TMP_FIXTURE_DIR"
exit $rc

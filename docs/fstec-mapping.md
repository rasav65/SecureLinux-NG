# Карта соответствия ФСТЭК — SecureLinux-NG

## Правила статусов

Допустимые статусы:
- `not started`
- `partial`
- `done`
- `not applicable`

Правило проекта:
- ничего не считать реализованным по ФСТЭК, пока нет:
  - кода;
  - проверки результата;
  - отражения в report / mapping.

## Framework prerequisites (не засчитываются как реализация пунктов ФСТЭК)

| Компонент | Статус | Код/блок | Комментарий |
|---|---|---|---|
| CLI framework | done | `securelinux-ng.sh` | Есть режимы `--check`, `--apply`, `--restore`, `--report`, `--dry-run`, `--profile`, `--config`, `--manifest` |
| Config loading | done | `load_config()` | Есть базовая загрузка внешнего config |
| Preflight skeleton | done | `run_preflight()` | Есть начальное определение среды и policy-gates |
| Manifest skeleton | done | `manifest_init()` | Есть JSON-структура manifest |
| Report skeleton | done | `write_report()` / `print_report_stdout()` | Есть JSON report и stdout summary |
| Dry-run framework | done | `--apply --dry-run` | Есть dry-run без изменения системы |
| Syntax / smoke tests | done | `tests/syntax.sh`, `tests/smoke.sh` | Есть минимальная проверка framework |
| Backup integrity | done | `backup_file_checked()` | Проверка успеха cp перед перезаписью конфигов (16.2.8+) |
| Concurrent protection | done | `acquire_run_lock()` | flock-защита от параллельного apply/restore (16.2.8+) |
| Atomic manifest | done | `record_manifest_*()` | Атомарная запись JSON через temp+replace (16.2.8+) |

## 2.1. Настройка авторизации

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.1.1. Не допускать пустые пароли / обеспечить пароль или блокировку по паролю | done | `check_empty_passwords_module()` / `apply_empty_passwords_module()` | `--check`, `--apply`, анализ `/etc/shadow`, backup `/etc/shadow` | Реализован модуль блокировки учётных записей с пустым password field через замену на `!` |
| 2.1.2. Отключить вход root по SSH (`PermitRootLogin no`) | done | `check_ssh_root_login_module()` / `apply_ssh_root_login_module()` | `--check`, `--apply`, `sshd -t`, наличие `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf` | Реализован первый SSH-модуль через drop-in; добавлен базовый restore managed file |

## 2.2. Ограничение механизмов получения привилегий

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.2.1. Ограничить `su` через `pam_wheel.so use_uid` и группу `wheel` | done | `check_pam_wheel_module()` / `apply_pam_wheel_module()` | `--check`, `--apply`, наличие группы `wheel`, активное правило в `/etc/pam.d/su` | Реализован первый PAM / `su`-модуль; добавлен базовый restore `/etc/pam.d/su` и группы `wheel` |
| 2.2.2. Ограничить пользователей/команды в `sudoers` | done | `check_sudo_policy_module()` / `apply_sudo_policy_module()` | `--check`, `--apply`, `visudo -cf`, наличие `/etc/sudoers.d/60-securelinux-ng-policy` | Реализована базовая sudo policy model для `%wheel`; добавлен базовый restore managed sudoers drop-in |

## Дополнительные меры (не в разделах 2.x ФСТЭК, но рекомендованы)

| Мера | Статус | Код/блок | Профиль | Комментарий |
|---|---|---|---|---|
| SSH hardening (Ciphers/MACs/KexAlgorithms/параметры) | done | `check_ssh_hardening_module()` / `apply_ssh_hardening_module()` | baseline/strict | Drop-in `61-securelinux-ng-ssh-hardening.conf`; strict добавляет Ciphers/MACs/KexAlgorithms |
| PAM faillock (блокировка УЗ) | done | `check_faillock_module()` / `apply_faillock_module()` | strict/paranoid | `/etc/security/faillock.conf`; strict+: deny=5 unlock=900 |
| Password policy (pwquality + login.defs + chage для существующих локальных УЗ) | done | `check_password_policy_module()` / `apply_password_policy_module()` | baseline/strict/paranoid | pwquality.conf minlen=15/16; login.defs PASS_MAX_DAYS=90/60/45; `common-password` нормализуется в порядок `pam_pwquality -> pam_pwhistory -> pam_unix`; aging применяется через `chage`; restore файловый, но runtime-state после `chage` не откатывается автоматически |
| auditd baseline rules | done | `check_auditd_module()` / `apply_auditd_module()` | все | identity, sudo, sshd, modules, privileged |
| UFW firewall (default deny incoming, allow SSH) | done | `check_ufw_module()` / `apply_ufw_module()` | все | restore: ufw disable |
| /tmp tmpfs (nosuid,nodev,noexec) | done | `check_tmp_tmpfs_module()` / `apply_tmp_tmpfs_module()` | paranoid | fstab + remount |
| mount hardening (/dev/shm, /var/tmp) | done | `check_mount_hardening_module()` / `apply_mount_hardening_module()` | paranoid | fstab + remount; оба монтируются как отдельные `tmpfs` (nosuid,nodev,noexec) |
| kernel module blacklist | done | `check_kernel_modules_module()` / `apply_kernel_modules_module()` | все | /etc/modprobe.d/60-securelinux-ng-blacklist.conf |
| fail2ban SSH jail | done | `check_fail2ban_module()` / `apply_fail2ban_module()` | paranoid | /etc/fail2ban/jail.local |
| AIDE integrity monitoring | done | `check_aide_module()` / `apply_aide_module()` | strict+ | aide --init |
| AppArmor enforce | done | `check_apparmor_module()` / `apply_apparmor_module()` | strict+ | aa-enforce |
| account audit report | done | `check_account_audit_module()` / `apply_account_audit_module()` | все | `/var/log/securelinux-ng/account_audit.txt` |
| auditd extended rules | done | `apply_auditd_module()` | strict+ | tmp exec, cron, network, systemd, finit_module |

## 2.3. Настройка прав доступа к объектам файловой системы

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.3.1. Корректные права для `/etc/passwd`, `/etc/group`, `/etc/shadow` | done | `check_fs_critical_files_module()` / `apply_fs_critical_files_module()` | `--check`, `--apply`, `stat`, проверка mode/owner/group | Реализован первый FS-permissions-модуль; добавлен metadata restore по машиночитаемому snapshot `MODE/UID/GID` |
| 2.3.2. Корректные права для исполняемых файлов и библиотек запущенных процессов | done | `check_runtime_paths_module()` / `apply_runtime_paths_module()` | `--check`, сканирование `/proc/*/exe` и `/proc/*/maps`, проверка `go-w` на файлах и родительских директориях | Реализован detect-only модуль; автоматический chmod для runtime paths пока policy-gated |
| 2.3.3. Корректные права для файлов/команд из cron | done | `check_cron_command_paths_module()` / `apply_cron_command_paths_module()` | `--check`, анализ `/etc/crontab` и `/etc/cron.d/*`, проверка `go-w` на файлах и родительских директориях | Реализован detect-only модуль аудита cron command paths; автоматический chmod/chown пока policy-gated |
| 2.3.4. Корректные права/владельцы для файлов, выполняемых через sudo | done | `check_sudo_command_paths_module()` / `apply_sudo_command_paths_module()` | `--check`, анализ `/etc/sudoers` и `/etc/sudoers.d/*`, проверка `go-w` на файлах и родительских директориях | Реализован detect-only модуль; автоматический chmod для sudo command paths пока policy-gated |
| 2.3.5. Корректные права для стартовых скриптов и `.service` | done | `check_systemd_unit_targets_module()` / `apply_systemd_unit_targets_module()` | `--check`, `--apply`, `stat`, проверка mode/owner/group | Реализован начальный systemd ownership/perms-модуль для targets в `/etc/systemd/system`; добавлен metadata restore по машиночитаемому snapshot `MODE/UID/GID` |
| 2.3.6. Корректные права для системных файлов заданий cron | done | `check_cron_targets_module()` / `apply_cron_targets_module()` | `--check`, `--apply`, `stat`, проверка mode/owner/group для `/etc/crontab`, `/etc/cron.*` | Реализован модуль прав для системных cron targets; metadata restore по машиночитаемому snapshot `MODE/UID/GID` |
| 2.3.7. Установить корректные права доступа к заданиям cron пользователей | done | `check_user_cron_permissions_module()` / `apply_user_cron_permissions_module()` | `--check`, `--apply`, анализ `/var/spool/cron` и `/var/spool/cron/crontabs` | Реализован базовый модуль прав для user cron files; metadata restore по машиночитаемому snapshot `MODE/UID/GID` |
| 2.3.8. Установить корректные права доступа к исполняемым файлам и библиотекам операционной системы | done | `check_standard_system_paths_module()` / `apply_standard_system_paths_module()` | `--check`, анализ стандартных путей и `/lib/modules/$(uname -r)`, проверка `go-w` на файлах и родительских директориях | Реализован detect-only модуль для стандартных системных путей; автоматический chmod/chown пока policy-gated |
| 2.3.9. Установить корректные права доступа к SUID/SGID-приложениям | done | `check_suid_sgid_module()` / `apply_suid_sgid_module()` | `--check`, аудит SUID/SGID-файлов в стандартных системных путях | Реализован detect-only модуль аудита SUID/SGID; автоматическое снятие битов/исправление прав пока policy-gated |

| 2.3.10. Установить корректные права доступа к содержимому домашних директорий пользователей | done | `check_home_permissions_module()` / `apply_home_permissions_module()` | `--check`, `--apply`, анализ `/home/*` и shell/history файлов | Реализован базовый модуль прав для чувствительных файлов в home; metadata restore по машиночитаемому snapshot `MODE/UID/GID` |
| 2.3.11. Установить корректные права доступа к домашним директориям пользователей | done | `check_home_permissions_module()` / `apply_home_permissions_module()` | `--check`, `--apply`, анализ `/home/*` | Реализован базовый модуль прав для home dirs; metadata restore по машиночитаемому snapshot `MODE/UID/GID` |

## 2.4. Настройка механизмов защиты ядра Linux

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.4.1. Ограничить доступ к журналу ядра (`kernel.dmesg_restrict=1`) | done | `sysctl_kernel_check_module()` / `apply_sysctl_kernel_module()` | `--check`, `--apply`, `sysctl -n kernel.dmesg_restrict`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.4.2. Скрыть ядерные адреса (`kernel.kptr_restrict=2`) | done | `sysctl_kernel_check_module()` / `apply_sysctl_kernel_module()` | `--check`, `--apply`, `sysctl -n kernel.kptr_restrict`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.4.3. `init_on_alloc=1` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.4.4. `slab_nomerge` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.4.5. `iommu=force iommu.strict=1 iommu.passthrough=0` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.4.6. `randomize_kstack_offset=1` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.4.7. `mitigations=auto,nosmt` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.4.8. Защита eBPF JIT (`net.core.bpf_jit_harden=2`) | done | `sysctl_kernel_check_module()` / `apply_sysctl_kernel_module()` | `--check`, `--apply`, `sysctl -n net.core.bpf_jit_harden`, managed drop-in | Реализован в составе базового sysctl-модуля |

## 2.5. Уменьшение периметра атаки ядра Linux

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.5.1. `vsyscall=none` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.5.2. `kernel.perf_event_paranoid=3` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n kernel.perf_event_paranoid`, managed drop-in | Все профили включая baseline (ФСТЭК 2.5.2) |
| 2.5.3. `debugfs=off` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; соответствует ФСТЭК 2.5.3 («по возможности off») и корпоративному стандарту; эффект после перезагрузки |
| 2.5.4. `kernel.kexec_load_disabled=1` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n kernel.kexec_load_disabled`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.5.5. `user.max_user_namespaces=0` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--apply`, managed drop-in; `--check` использует `USER_NAMESPACES_LIMIT`, а при его отсутствии учитывает фактическое live-значение (`0`/`10000`) если оно уже задано | Значение задаётся через `USER_NAMESPACES_LIMIT` или выбор администратора; Docker/Podman/K8s добавляют `policy_gate`, но не блокируют применение автоматически |
| 2.5.6. `kernel.unprivileged_bpf_disabled=1` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n kernel.unprivileged_bpf_disabled`, managed drop-in | Все профили включая baseline (ФСТЭК 2.5.6) |
| 2.5.7. `vm.unprivileged_userfaultfd=0` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n vm.unprivileged_userfaultfd`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.5.8. `dev.tty.ldisc_autoload=0` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n dev.tty.ldisc_autoload`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.5.9. `tsx=off` | done | `grub_kernel_params_check_module()` / `apply_grub_kernel_params_module()` | `--check`, анализ `/proc/cmdline` | Реализован модуль с автоматической правкой GRUB на всех профилях; эффект после перезагрузки |
| 2.5.10. `vm.mmap_min_addr>=4096` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n vm.mmap_min_addr`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.5.11. `kernel.randomize_va_space=2` | done | `sysctl_attack_surface_check_module()` / `apply_sysctl_attack_surface_module()` | `--check`, `--apply`, `sysctl -n kernel.randomize_va_space`, managed drop-in | Реализован в составе базового sysctl-модуля |

## 2.6. Настройка средств защиты пользовательского пространства со стороны ядра Linux

| Пункт | Статус | Код/блок | Проверка | Комментарий |
|---|---|---|---|---|
| 2.6.1. `kernel.yama.ptrace_scope=3` | done | `sysctl_userspace_protection_check_module()` / `apply_sysctl_userspace_protection_module()` | `--check`, `--apply`, `sysctl -n kernel.yama.ptrace_scope`, managed drop-in | Все профили включая baseline (ФСТЭК 2.6.1) |
| 2.6.2. `fs.protected_symlinks=1` | done | `sysctl_userspace_protection_check_module()` / `apply_sysctl_userspace_protection_module()` | `--check`, `--apply`, `sysctl -n fs.protected_symlinks`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.6.3. `fs.protected_hardlinks=1` | done | `sysctl_userspace_protection_check_module()` / `apply_sysctl_userspace_protection_module()` | `--check`, `--apply`, `sysctl -n fs.protected_hardlinks`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.6.4. `fs.protected_fifos=2` | done | `sysctl_userspace_protection_check_module()` / `apply_sysctl_userspace_protection_module()` | `--check`, `--apply`, `sysctl -n fs.protected_fifos`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.6.5. `fs.protected_regular=2` | done | `sysctl_userspace_protection_check_module()` / `apply_sysctl_userspace_protection_module()` | `--check`, `--apply`, `sysctl -n fs.protected_regular`, managed drop-in | Реализован в составе базового sysctl-модуля |
| 2.6.6. `fs.suid_dumpable=0` | done | `sysctl_userspace_protection_check_module()` / `apply_sysctl_userspace_protection_module()` | `--check`, `--apply`, `sysctl -n fs.suid_dumpable`, managed drop-in | Реализован в составе базового sysctl-модуля |

## Дополнительные меры из внутреннего стандарта (не пункты ФСТЭК 2.x)

Меры взяты из внутреннего Стандарта безопасной настройки и книги Чайка А.А. «Практическая безопасность Linux», БХВ-Петербург 2026.

| Пункт стандарта | Описание | Статус | Код/блок | Профиль |
|---|---|---|---|---|
| п.5.2 | sudo: `use_pty`, `logfile`, `timestamp_timeout=5`, `passwd_tries=3`, `secure_path` | done | `SUDO_POLICY_CONTENT` | все |
| п.7.3 | GRUB: `apparmor=1 security=apparmor` | done | `apply_grub_kernel_params_module()` | strict+ |
| п.7.6 | Core dumps: `limits.d` + `systemd/coredump.conf.d` + `kernel.core_pattern` sysctl dropin | done | `check_coredump_module()` / `apply_coredump_module()` | все |
| п.7.7 | `chmod 600 /boot/grub/grub.cfg` | done | `apply_grub_kernel_params_module()` | все |
| п.8.1 | `net.ipv4.ip_forward=0`, `net.ipv6.conf.all.forwarding=0` | done | `sysctl_network_check_module()` / `apply_sysctl_network_module()` | все |
| п.8.2 | `net.ipv4.conf.all.log_martians=1`, `net.ipv4.conf.default.log_martians=1` | done | `sysctl_network_check_module()` / `apply_sysctl_network_module()` | все |
| п.8.3 | `rp_filter=1`, `accept_redirects=0`, `send_redirects=0`, `tcp_syn_retries=3` | done | `sysctl_network_check_module()` / `apply_sysctl_network_module()` | все | `tcp_syn_retries` добавлен в check начиная с 16.2.8 |
| п.8.3 | `net.ipv4.tcp_timestamps=0` | done | `apply_sysctl_network_module()` | paranoid |
| п.10.3 | rsyslog: установка и включение | done | `check_rsyslog_module()` / `apply_rsyslog_module()` | все |
| п.10.2 | chrony: установка и включение | done | `check_chrony_module()` / `apply_chrony_module()` | все |
| п.10.2 | unattended-upgrades: установка и включение | done | `check_unattended_upgrades_module()` / `apply_unattended_upgrades_module()` | все |
| §2 | apport: отключение (конфликт с `fs.suid_dumpable=0`) | done | `check_apport_module()` / `apply_apport_module()` | все |
| п.9.3 | SSH: `LogLevel VERBOSE` | done | `SSH_HARDENING_BASELINE` | все |
| п.9.4 | SSH: `Banner /etc/issue.net` | done | `SSH_HARDENING_STRICT` | strict+ |
| п.10.5 | rkhunter: обнаружение руткитов | done | `check_rkhunter_module()` / `apply_rkhunter_module()` | paranoid |
| п.4.3 | `pam_pwhistory`: запрет повторного использования паролей (remember=5/10/24) | done | `check_password_policy_module()` / `apply_password_policy_module()` | все |
| п.17.1 | Account audit: вывод активных systemd-служб | done | `apply_account_audit_module()` | все |
| п.17.2 | Account audit: вывод открытых портов (`ss -tlnp`) | done | `apply_account_audit_module()` | все |
| п.8.4 | `net.ipv4.tcp_syncookies=1`: защита от SYN-флуд (Стандарт п.8.4) | done | `apply_sysctl_network_module()` | все |
| п.8.4 | `net.ipv4.icmp_echo_ignore_broadcasts=1`: защита от Smurf-атак (Стандарт п.8.4) | done | `apply_sysctl_network_module()` | все |
| п.8.4 | `net.ipv4.icmp_ignore_bogus_error_responses=1`: защита от поддельных ICMP-ошибок (Стандарт п.8.4) | done | `apply_sysctl_network_module()` | все |
| п.10.6 | `usb_storage` blacklist: блокировка USB-накопителей (Стандарт п.7.5 + п.10.6) | done | `apply_kernel_modules_module()` | paranoid |
| п.11.1 | auditd baseline: `bind/connect` (k=network), `/dev/bus/usb` (k=usb_devices) | done | `apply_auditd_module()` | все |
| п.15.1 | `kernel.modules_disabled=1`: запрет загрузки модулей ядра (write-once) | not_applicable | временно отключено — несовместимо с binfmt_misc/UFW при загрузке через sysctl dropin | paranoid |

## Правило обновления карты

Любое изменение в hardening-модулях должно обновлять:
1. `docs/fstec-mapping.md`
2. `README.md` — если меняются режимы/возможности
3. `CHANGELOG.md`
4. tests / проверки

# Restore model — SecureLinux-NG

## Текущий охват --restore

| Модуль | Файл/объект | Метод restore |
|---|---|---|
| 2.1.2 SSH root | `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf` | backup |
| 2.1.2 SSH hardening | `/etc/ssh/sshd_config.d/61-securelinux-ng-ssh-hardening.conf` | backup |
| 2.1 faillock | `/etc/security/faillock.conf` | backup; тихий пропуск если модуль не применялся (baseline) |
| 2.1 password policy | `/etc/security/pwquality.conf`, `/etc/login.defs` | backup |
| 2.2.1 PAM wheel | `/etc/pam.d/su` | backup |
| 2.2.1 группа wheel | группа `wheel` | groupdel (если создана скриптом) |
| 2.2.2 sudoers | `/etc/sudoers.d/60-securelinux-ng-policy` | backup |
| 2.3.1 | `/etc/passwd`, `/etc/group`, `/etc/shadow` | metadata snapshot |
| 2.3.5 | targets в `/etc/systemd/system` | metadata snapshot |
| 2.3.6 | системные cron targets | metadata snapshot |
| 2.4.1/2/8 | `/etc/sysctl.d/60-securelinux-ng-kernel.conf` | backup + sysctl --system (безусловно) |
| 2.5.x | `/etc/sysctl.d/61-securelinux-ng-attack-surface.conf` | backup + sysctl --system (безусловно) |
| 2.6.x | `/etc/sysctl.d/99-securelinux-ng-userspace-protection.conf` | backup + sysctl --system (безусловно) |
| firewall (UFW) | — | `ufw disable` (если был включён скриптом); восстанавливает nftables (active/enabled) если был замаскирован скриптом; для заранее активного UFW restore остаётся partial и не откатывает исходные правила автоматически |
| /tmp tmpfs | `/etc/fstab` | backup + перезагрузка |
| mount hardening | `/etc/fstab` | backup + перезагрузка; `/dev/shm` и `/var/tmp` монтируются как отдельные `tmpfs` |
| kernel module blacklist | `/etc/modprobe.d/60-securelinux-ng-blacklist.conf` | backup |
| fail2ban | `/etc/fail2ban/jail.local` | backup |
| AIDE | — | ручное удаление `/var/lib/aide/aide.db` |
| AppArmor | — | `aa-complain /etc/apparmor.d/*` вручную |
| 2.1.1 empty_passwords | список имён пользователей с пустым паролем (`empty-password-users-*.txt`) | пустые поля пароля не восстанавливаются автоматически по соображениям безопасности; backup сохраняется только как журнал затронутых УЗ |
| 2.3.2 runtime_paths | файлы запущенных процессов | metadata snapshot |
| 2.3.3 cron_command_paths | файлы из cron | metadata snapshot |
| 2.3.4 sudo_command_paths | файлы из sudoers | metadata snapshot |
| 2.3.8 standard_system_paths | системные бинари/библиотеки | metadata snapshot |
| 2.3.9 suid_sgid | SUID/SGID файлы | metadata snapshot |
| 2.3.10/11 home_permissions | home dirs и sensitive files | metadata snapshot |
| 2.3.7 user_cron | user cron files | metadata snapshot |
| 2.4.3–2.4.7 GRUB | `/etc/default/grub` | backup + update-grub (reboot) |
| account audit | `/var/log/securelinux-ng/account_audit.txt` | удаление через manifest (created_file) |
| auditd | `/etc/audit/rules.d/60-securelinux-ng.rules` | backup |
| auditd extended | `/etc/audit/rules.d/61-securelinux-ng-extended.rules` | backup |
| network sysctl | `/etc/sysctl.d/62-securelinux-ng-network.conf` | backup + sysctl --system |
| network sysctl unit | `/etc/systemd/system/securelinux-ng-sysctl.service` | systemctl disable + удаление + daemon-reload |
| coredump | `/etc/security/limits.d/99-securelinux-ng-coredump.conf`, `/etc/systemd/coredump.conf.d/99-securelinux-ng.conf`, `/etc/sysctl.d/98-securelinux-ng-coredump.conf` | backup + sysctl --system |
| rkhunter | — | пакет не удаляется автоматически |
| 4.3 pam_pwhistory | `/etc/pam.d/common-password` | backup через manifest |
| п.15.1 kernel.modules_disabled | — | временно не применяется; dropin не создаётся |

## Источник manifest

1. `--manifest FILE` — явный путь
2. иначе — последний `manifest-*.json` в `STATE_DIR` (маска)
3. иначе — `manifest.json` в `STATE_DIR` (прямое имя)

## Что хранится в manifest

- `backups`: `[{original, backup}, ...]`
- `created_files`: файлы, созданные скриптом (удаляются при restore)
- `created_groups`: группы, созданные скриптом
- `modified_files`, `apply_report`, `warnings`, `irreversible_changes`

## Metadata snapshot (для модулей прав доступа)

При apply сохраняется: `TARGET=`, `MODE=`, `UID=`, `GID=`.
При restore: `chown uid:gid` + `chmod mode`.
Fallback на старый текстовый формат `stat` сохранён для совместимости.

## Ограничения

- **sysctl restore** (16.2.8+): `sysctl --system` вызывается всегда после restore sysctl dropin-файлов, даже если dropin был удалён (т.е. не существовал до apply). Это гарантирует что runtime-значения sysctl перезагружаются из оставшихся конфигов.
- GRUB: вступает в силу только после перезагрузки.
- `kernel.kexec_load_disabled=1`: необратимо до перезагрузки (write-once).
- auditd: правила перезагружаются через `augenrules --load` или `systemctl restart auditd`.
- 2.3.2/3/4/8/9: restore возвращает прежние права, но не гарантирует безопасность если файлы изменились.
- rkhunter: пакет не удаляется при restore автоматически; при необходимости удалите вручную: `apt-get remove rkhunter`.
- `kernel.modules_disabled=1`: временно не применяется автоматически — dropin не создаётся.


## Атомарная запись /etc/shadow (16.2.8+)

Модуль `2.1.1 empty_passwords` записывает `/etc/shadow` атомарно: через временный файл + `fsync` + `os.replace`. Это гарантирует что аварийное завершение не повредит файл аутентификации.

## Ограничение парольной политики

- Для меры 2.1 restore восстанавливает файловые изменения в `/etc/security/pwquality.conf`, `/etc/login.defs` и `/etc/pam.d/common-password`, но не откатывает уже применённые к существующим локальным УЗ параметры aging, установленные через `chage` во время apply.

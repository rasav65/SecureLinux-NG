# Restore model — SecureLinux-NG

## Зачем нужен сетевой systemd-unit

Сетевой systemd-unit нужен не для постоянного фонового процесса, а для
однократного повторного применения `/etc/sysctl.d/62-securelinux-ng-network.conf`
после `network-online.target`.

Состояние `active (exited)` означает успешное завершение oneshot-команды.
Постоянно работающий процесс в памяти не требуется.

Без этого unit допустим только эквивалентный механизм сетевого менеджера,
который повторно применяет те же параметры после создания и поднятия
интерфейсов.

## Текущий охват --restore

| Модуль | Файл/объект | Метод restore |
|---|---|---|
| 2.1.2 SSH root | `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf` | backup |
| 2.1.2 SSH hardening | `/etc/ssh/sshd_config.d/61-securelinux-ng-ssh-hardening.conf` | backup |
| Corporate faillock | `/etc/security/faillock.conf` | backup; применяется только при включённой корпоративной политике и strict+ |
| Corporate password policy | `/etc/security/pwquality.conf`, `/etc/login.defs`, `/etc/pam.d/common-password` | исходное состояние фиксируется до установки зависимостей; backup либо удаление созданного файла; применяется только по флагу |
| Corporate password aging | `password_aging_snapshots` в manifest | восстановление исходных параметров через `chage` |
| Password policy packages | `installed_packages` в manifest | purge только пакетов и зависимостей, отсутствовавших до apply |
| 2.2.1 PAM wheel | `/etc/pam.d/su` | backup; PAM-блок активируется только после добавления проверенного администратора |
| 2.2.1 членства wheel | `added_group_memberships` в manifest | удаляются только членства, добавленные текущим apply |
| 2.2.1 группа wheel | группа `wheel` | `groupdel`, только если группа создана скриптом и осталась пустой |
| 2.2.2 sudoers | `/etc/sudoers.d/60-securelinux-ng-policy` | backup |
| 2.3.1 | `/etc/passwd`, `/etc/group`, `/etc/shadow` | metadata snapshot |
| 2.3.5 | targets в `/etc/systemd/system` | metadata snapshot |
| 2.3.6 | системные cron targets | metadata snapshot |
| 2.4.1/2/8 | `/etc/sysctl.d/60-securelinux-ng-kernel.conf` | backup файла + runtime snapshot + адресный restore через `sysctl -w` |
| 2.5.x | `/etc/sysctl.d/61-securelinux-ng-attack-surface.conf` | backup файла + runtime snapshot; `kernel.kexec_load_disabled` и `kernel.unprivileged_bpf_disabled` требуют reboot для полного runtime-отката |
| 2.6.x | `/etc/sysctl.d/99-securelinux-ng-userspace-protection.conf` | backup файла + runtime snapshot; `kernel.yama.ptrace_scope=3` требует reboot для полного runtime-отката |
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
| 2.4.3–2.4.7 GRUB | `/etc/default/grub` | backup + update-grub (reboot); generated `grub.cfg` может не совпасть побайтово |
| account audit | `/var/log/securelinux-ng/account_audit.txt` | backup и восстановление, если файл существовал; удаление, только если файл создан скриптом |
| auditd | `/etc/audit/rules.d/60-securelinux-ng.rules` | backup |
| auditd extended | `/etc/audit/rules.d/61-securelinux-ng-extended.rules` | backup |
| network sysctl | `/etc/sysctl.d/62-securelinux-ng-network.conf` | backup файла + runtime snapshot + адресный restore через `sysctl -w` |
| network sysctl unit | `/etc/systemd/system/securelinux-ng-sysctl.service` | backup содержимого и состояния enabled/disabled/masked; удаление только если unit создан скриптом |
| coredump | `/etc/security/limits.d/99-securelinux-ng-coredump.conf`, `/etc/systemd/coredump.conf.d/99-securelinux-ng.conf`, `/etc/sysctl.d/98-securelinux-ng-coredump.conf` | backup файлов + восстановление прежнего runtime `kernel.core_pattern` через `sysctl -w` |
| rkhunter | — | пакет не удаляется автоматически |
| 4.3 pam_pwhistory | `/etc/pam.d/common-password` | входит в backup Corporate password policy |
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
- `additional_measures_enabled`: фактическое состояние дополнительного блока — `true` при `--enable-additional-measures` или config-значении `1`, `false` при обычном apply
- `installed_packages`: новые пакеты password policy
- `added_group_memberships`: членства, добавленные в wheel
- `password_aging_snapshots`: исходные значения aging
- пути к `sysctl-runtime-<module>-<timestamp>.json` для восстановления live sysctl-значений

## Metadata snapshot (для модулей прав доступа)

При apply сохраняется: `TARGET=`, `MODE=`, `UID=`, `GID=`.
При restore: `chown uid:gid` + `chmod mode`.
Fallback на старый текстовый формат `stat` сохранён для совместимости.

## Ограничения

- **sysctl restore**: перед apply сохраняются live-значения каждого managed sysctl-модуля. После восстановления файла значения возвращаются адресно через `sysctl -w`; глобальный `sysctl --system` не используется.
- `kernel.kexec_load_disabled=1` и `kernel.unprivileged_bpf_disabled=1` нельзя вернуть в `0` до перезагрузки; `kernel.yama.ptrace_scope=3` нельзя изменить до перезагрузки. Managed-файлы восстанавливаются, но runtime-откат завершается после reboot.
- GRUB: вступает в силу только после перезагрузки.
- auditd: правила перезагружаются через `augenrules --load` или `systemctl restart auditd`.
- 2.3.2/3/4/8/9: restore возвращает прежние права, но не гарантирует безопасность если файлы изменились.
- Пакеты дополнительных модулей автоматически не удаляются. Исключение — зависимости password policy, впервые установленные текущим apply и записанные в `installed_packages`.
- rkhunter: пакет не удаляется при restore автоматически; при необходимости удалите вручную: `apt-get remove rkhunter`.
- `kernel.modules_disabled=1`: временно не применяется автоматически — dropin не создаётся.


## Атомарная запись /etc/shadow

Модуль `2.1.1 empty_passwords` записывает `/etc/shadow` атомарно: через временный файл + `fsync` + `os.replace`. Это гарантирует что аварийное завершение не повредит файл аутентификации.

## Restore парольной политики и wheel

- Перед изменением активной локальной учётной записи через `chage` исходные поля `last_change`, `min_days`, `max_days`, `warn_days`, `inactive_days` и `expire_date` сохраняются в `password_aging_snapshots` manifest. Restore восстанавливает их через `chage`.
- Manifest старых запусков без `password_aging_snapshots` не содержит данных для обратного восстановления aging; в этом случае модуль сообщает о пропуске.
- Явный `WHEEL_USERS` имеет приоритет. При пустом значении обычный запуск через `sudo` автоматически использует проверенного `SUDO_USER`; ошибка регистрируется только при невозможности безопасного определения администратора.
- Для `wheel` manifest хранит только членства, добавленные текущим apply. Restore сначала возвращает `/etc/pam.d/su`, затем удаляет эти членства и удаляет группу `wheel` только если она была создана скриптом и осталась пустой.

## Уточнения restore v16.2.11

### Дополнительные меры

Обычный `--apply` выполняет основной набор hardening при
`ENABLE_ADDITIONAL_MEASURES=0`.

CLI-флаг `--enable-additional-measures` допустим только вместе с
`--apply`, имеет приоритет над config-файлом и включает 17 модулей:

1. расширенное укрепление SSH;
2. аудит учётных записей;
3. AppArmor;
4. AIDE;
5. fail2ban;
6. rkhunter;
7. отключение опасных модулей ядра;
8. укрепление параметров монтирования;
9. защищённый `/tmp` как `tmpfs`;
10. UFW;
11. auditd и правила аудита;
12. rsyslog;
13. chrony;
14. unattended-upgrades;
15. отключение apport;
16. ограничение core dump;
17. дополнительные сетевые sysctl.

Без CLI-флага дополнительный блок можно включить config-параметром
`ENABLE_ADDITIONAL_MEASURES=1`.

Manifest хранит фактическое состояние в поле
`additional_measures_enabled`: при включённом блоке — `true`, при
обычном apply — `false`.

Флаг не передаётся команде `--restore`. Restore определяет необходимый
объём отката только по manifest. Если поле равно `false`, дополнительные
модули, которые не применялись, пропускаются.

Для старых manifest без этого поля сохраняется совместимое прежнее
поведение полного restore дополнительных модулей.

### Пакеты password policy

Перед установкой сохраняется полный список установленных пакетов.
После установки разница записывается в `installed_packages`.
Restore выполняет purge только этой разницы.

На Ubuntu Server были удалены шесть новых пакетов, на Debian — пять,
поскольку `wamerican` уже присутствовал, а на Ubuntu Minimal —
девять пакетов, включая зависимости `file` и `libmagic`.

### pwquality.conf

Существование `/etc/security/pwquality.conf` определяется до запуска
`apt-get`. Если файл отсутствовал и был создан `libpwquality-common`,
он записывается как созданный и после purge остаётся отсутствующим.

Если файл существовал, сохраняется его исходная копия.

### Runtime sysctl

`kernel.kexec_load_disabled` и `kernel.yama.ptrace_scope` могут
не вернуться к исходному live-значению в текущей загрузке.
После удаления managed drop-in полный возврат завершается reboot.

### GRUB

Restore возвращает `/etc/default/grub` и запускает генератор
конфигурации. Параметры SecureLinux удаляются из `grub.cfg`
и из `/proc/cmdline` после reboot.

`/boot/grub/grub.cfg` не сохраняется как content-backup, поэтому
побайтовое совпадение с исходным generated-файлом не гарантируется.
Функциональный restore и идемпотентная повторная генерация подтверждены.

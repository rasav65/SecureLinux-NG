## 16.2.8 — 2026-04-04

### Исправления (объединённый code review: Claude Opus + ChatGPT Deep Research + Claude Sonnet)

#### Критичные
- **A1**: `manifest_init` больше не вызывает `die` после подтверждения повторного `--apply` — существующий manifest архивируется
- **A2**: `backup_file_checked()` — 16 backup-операций теперь проверяют успех `cp` перед перезаписью конфига
- **A3**: запись `/etc/shadow` атомарная (temp + fsync + `os.replace`)

#### Высокие
- **B1**: `flock`-защита от параллельного `--apply`/`--restore` (`acquire_run_lock`)
- **B2**: все `record_manifest_*` переведены на атомарную запись JSON (temp + `os.replace`)
- **B3**: `sysctl --system` вызывается всегда после restore sysctl dropin-файлов

#### Средние
- **C1**: `sysctl_network_check_module` проверяет `tcp_syn_retries=3`
- **C2**: GRUB `python3 -c` заменён на heredoc
- **C3**: уточнён edge case в `normalize_common_password_stack`
- **C4**: `apply_user_cron_permissions_module` проверяет права перед `chmod`
- **C5**: `check_cron_command_paths_module` получил `EXCLUDED_PARENTS`
- **C6**: `apt_update_once` ставит флаг только при успехе

#### Низкие
- **D1**: `--profile` из CLI всегда приоритетнее config
- **D2**: дедуплицирован dry-run в `apply_empty_passwords_module`
- **D3**: убраны дублирующие вызовы в `main()`
- **D4**: унифицирован IFS tab
- **D5**: `--help`/`--version` работают без проверки системных команд


### Added
- `SYSCTL_NETWORK_CONTENT`: добавлен `net.ipv4.tcp_syn_retries = 3`, все профили (Стандарт безопасной настройки п. 8.3)
- `apply_auditd_module`: в auditd baseline rules добавлены правила аудита сетевых вызовов `bind/connect` (k=network, arch b64/b32) и наблюдение за `/dev/bus/usb` (k=usb_devices) — Стандарт безопасной настройки п. 11.1

## [16.2.7] — 2026-03-24

### Fixed
- `apply_sysctl_kernel_module`, `apply_sysctl_attack_surface_module`, `apply_sysctl_network_module`: запись drop-in больше не считается успешной при сбое `sysctl --system`; теперь фиксируется `ERROR` и warning в manifest
- `check_apparmor_module`: для `baseline` неактивный AppArmor больше не помечается как `RISKY`; выводится как `SKIP`, поскольку мера не обязательна для профиля
- `check_unattended_upgrades_module`: проверка переведена с `systemctl is-active` на `systemctl is-enabled`; для этого модуля оценивается включение автоматических обновлений, а не постоянный runtime-статус
- `restore_rkhunter_module`: предупреждение заменено на информационное сообщение; отсутствие автоматического удаления пакета больше не считается warning restore
- `restore_empty_passwords_module`: восстановление пустых полей пароля в `/etc/shadow` запрещено по соображениям безопасности; restore теперь явно оставляет backup и сообщает об ограничении
- `restore_ufw_module`: для сценария с заранее активным UFW зафиксирован partial restore; существующие правила и исходное состояние firewall не откатываются автоматически
- `run_restore_mode`: разрешение manifest выполняется до fallback-логики `STATE_DIR`, чтобы restore не пытался искать manifest в подменённом каталоге

- `check_apport_module` / `apply_apport_module`: убрана неверная привязка `apport` к ФСТЭК 2.6.6; `apport` теперь отражается как дополнительная мера отключения crash-reporting
- `sysctl_attack_surface_check_module`: проверка `user.max_user_namespaces` больше не уходит в `SKIP` только из-за отсутствия `USER_NAMESPACES_LIMIT` в конфиге; после интерактивного apply учитывается фактическое live-значение `0`/`10000`
- `apply_grub_kernel_params_module`: `chmod 600` для `grub.cfg` применяется на всех профилях, в соответствии с внутренним стандартом
- `check_apparmor_module`: на `baseline` активный AppArmor больше не засчитывается как обязательный `OK` пункта профиля; выводится как не требуемый профилем
- `restore_apparmor_module`, `restore_aide_module`, `restore_apport_module`: убраны лишние `WARN` на профилях/сценариях, где модуль не применялся

### Docs
- `README.md`: оформлено осознанное отступление по `/etc/shadow = 640 root:shadow` вместо буквального `600` из ФСТЭК 2.3.1 / внутреннего стандарта

- **ФСТЭК 2.5.2/2.5.6/2.6.1**: `perf_event_paranoid`, `unprivileged_bpf_disabled`, `ptrace_scope` теперь применяются для всех профилей включая baseline (ранее требовался strict+)
- **USER_NAMESPACES_LIMIT**: передаётся в check-модуль через argv вместо env — проверка namespaces теперь работает корректно
- **Интерактивные prompt**: добавлена проверка TTY и timeout 60с — скрипт не зависает в неинтерактивном окружении (ansible/CI)
- **SSH hardening check**: проверяет значения параметров, а не только их наличие
- **UFW**: убран hardcoded порт 15000/udp Kaspersky — заменён на конфигурируемый `UFW_EXTRA_RULES`
- **coredump**: добавлен `kernel.core_pattern=|/bin/false` через sysctl dropin
- **pam_wheel**: regex принимает аргументы `use_uid` и `group=wheel` в любом порядке
- **grep -Fv**: исправлен unescaped dot в grep для user.max_user_namespaces
- **check_password_policy_module**: убрана зависимость от DRY_RUN — aging проверяется всегда
- **sshd -t**: подавлен вывод в apply_ssh_root_login_module
- **read /dev/tty**: manifest overwrite prompt читает из /dev/tty
- **import sys**: убран дубль в sysctl_network_check_module
- **Broken systemd symlinks**: silent skip в apply_systemd_unit_one
- **Manifest overwrite prompt**: принимает y и yes
- **Debian 13**: протестировано baseline/strict/paranoid — errors=0
- **Интерактивный prompt user.max_user_namespaces**: убран timeout — ждёт ввод администратора бесконечно
- **Broken systemd symlinks**: вывод перенесён в debug log вместо SKIP
- **Manifest overwrite prompt**: принимает y и yes

## [16.2.6] - 2026-03-22

### Fixed
- `apply_ssh_root_login_module`: добавлен rollback файла при провале `sshd -t`
- `apply_password_policy_module`: ошибка merge pwquality.conf теперь ERROR+return — partial-apply невозможен
- `restore_account_audit_module`: согласован с apply — удаляет файл через manifest если трекался
- `write_report`: исправлены устаревшие fstec_items (2.5.3 debugfs, 2.5.5 user_namespaces, account_audit/17.1/17.2)
- `apply_mount_hardening_module`: убран двойной `manifest_has_backup_for` для fstab
- `check_password_policy_module`: проверка minlen теперь сверяет конкретное значение по профилю

## [16.2.5] - 2026-03-21

### Fixed
- `run_apply_mode`: добавлен guard — при наличии существующего manifest запрашивается явное подтверждение перед перезаписью
- `apply_*`: повторный `--apply` без `--restore` больше не перезаписывает оригинальные backup — добавлена функция `manifest_has_backup_for` и проверка перед `cp` для всех системных файлов (fstab, pwquality.conf, common-password, login.defs, faillock.conf, pam su, GRUB)

## [16.2.4] - 2026-03-21

### Fixed
- `apply_mount_hardening_module`: `/var/tmp` заменён с `bind` на отдельный `tmpfs`; устранено зависание при shutdown на Ubuntu 24.04
- `apply_password_policy_module`: ошибка установки `libpam-pwquality` теперь выдаёт `ERROR` и прерывает модуль — PAM стек больше не ломается
- `restore_faillock_module`: добавлен тихий пропуск если модуль не применялся — устранён ложный warning на baseline
- Исправлен мусорный комментарий у `_APT_UPDATED`
- `account_audit`: добавлены `record_manifest_created_file` / `record_manifest_modified_file` для файла отчёта
- `apply_mount_hardening_module`, `apply_tmp_tmpfs_module`: временные файлы `/tmp/_sl_*.py` заменены на inline `python3 -` heredoc
- `apply_password_policy_module`: добавлена проверка кода возврата merge `pwquality.conf`
- `sysctl_attack_surface_check_module`: `user.max_user_namespaces` проверяется только если задан `USER_NAMESPACES_LIMIT`; при пустом значении выдаётся `skipped` вместо `risky`
- `run_check_mode`: добавлена обработка `INFO`-строк от `sysctl_attack_surface_check_module`
- `restore_sysctl_network_module`: добавлены `systemctl disable` и `daemon-reload` для `securelinux-ng-sysctl.service`
- `apply_ssh_hardening_module`: при ошибке `sshd -t` восстанавливается backup вместо простого `rm -f`
- `check_ssh_hardening_module`: расширен список проверяемых параметров; для `strict+` добавлена проверка криптографических параметров
- `normalize_common_password_stack`: существующая строка `pam_pwquality.so` заменяется на эталонную с `retry=3`
- `restore_ufw_module`: сохраняется и восстанавливается состояние `nftables` (active/enabled) через `apply_report` в manifest

## [16.2.3] - 2026-03-17

### Added
- `net.ipv4.tcp_syncookies = 1` — защита от SYN-флуд; добавлен в `SYSCTL_NETWORK_CONTENT`, все профили (Чайка А.А. «Практическая безопасность Linux», гл. 15)
- `net.ipv4.icmp_echo_ignore_broadcasts = 1` — защита от Smurf-атак; добавлен в `SYSCTL_NETWORK_CONTENT`, все профили
- `net.ipv4.icmp_ignore_bogus_error_responses = 1` — защита от поддельных ICMP-ошибок; добавлен в `SYSCTL_NETWORK_CONTENT`, все профили (CIS/KSPP)
- `usb_storage` blacklist — блокировка USB-накопителей добавлена в `KERNEL_MODULE_BLACKLIST`; только профиль `paranoid`; добавляется с `add_warning` (корпоративная политика)
- `kernel.modules_disabled=1` — новый модуль `apply/check/restore_modules_disabled_module()`; только профиль `paranoid`; write-once параметр ядра; dropin `63-securelinux-ng-modules-disabled.conf`; фиксируется как `irreversible_change` в manifest

### Fixed
- `pam_faillock`: применение и проверка ограничены профилями `strict`/`paranoid`; baseline больше не требует `faillock.conf`; параметры приведены к корпоративному стандарту: `deny=5`, `unlock_time=900`
- GRUB 2.5.3: параметр `debugfs` переведён с `debugfs=no-mount` на `debugfs=off`; apply-логика теперь заменяет уже существующее значение того же ключа в `GRUB_CMDLINE_LINUX_DEFAULT`, а не только добавляет отсутствующие параметры

- Password policy: после обновления `/etc/login.defs` параметры aging теперь применяются к существующим локальным учётным записям через `chage` (root + UID>=UID_MIN, кроме `nologin`/`false`)
- `common-password`: добавлена нормализация порядка `pam_pwquality -> pam_pwhistory -> pam_unix`; устранён сценарий некорректной вставки `pam_pwhistory`
- `check_password_policy_module()`: проверка приведена в соответствие apply-логике — проверяются точные значения `PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_WARN_AGE`, порядок PAM-стека и факт применения `chage`
- `README.md`: описание меры 2.1 уточнено — отражены `chage` для существующих УЗ и порядок `common-password`
- `apply_empty_passwords_module()`: устранена лишняя перезапись `/etc/shadow` и ложная запись в manifest/report при отсутствии УЗ с пустым паролем
- `apply_pam_wheel_module()`: добавлена проверка успешности `groupadd wheel`; manifest/report больше не фиксируют создание группы при ошибке
- password policy: устранено расхождение `check/apply` для профиля `paranoid`; `PASS_MAX_DAYS` синхронизирован как 45 дней
- `check_password_policy_module()`: проверка aging переведена с locale-зависимого `chage -l` на числовые поля `/etc/shadow` (`min/max/warn`), устранено ложное срабатывание на системах с неанглийской локалью
- `check_password_policy_module()`: при запуске без root проверка aging больше не падает на `/etc/shadow`, а помечается как неполная (`warning`)
- `check_password_policy_module()`: уточнено итоговое сообщение для non-root режима — теперь явно отражается неполная проверка, а не отсутствие локальных УЗ
- `apply_password_policy_existing_accounts()`: для уже просроченных существующих УЗ добавлен bootstrap-режим — `lastchg` сдвигается на текущую дату перед применением нового aging, чтобы не вызывать принудительную смену пароля и lockout при первом входе
- README.md: добавлено предупреждение о password aging для существующих локальных УЗ, историческом риске немедленной экспирации в старых версиях и bootstrap-поведении текущей версии
- restore: для `fail2ban`, `rkhunter`, `mount hardening` и `/tmp tmpfs` добавлен тихий пропуск, если модуль не применялся в исходном apply/manifest
- paranoid restore: устранено двойное восстановление `/etc/fstab`, если одновременно применялись `mount hardening` и `/tmp tmpfs`
- `apply_apparmor_module()`: предупреждение уточнено — скрипт не заявляет автоматический перевод уже существующих профилей в enforce; оставлена только ручная команда `aa-enforce`
- `run_restore_mode()`: профиль для restore-report теперь берётся из manifest, чтобы после `strict`/`paranoid` restore не показывал ложный `baseline`
- `write_report()`: для `password_policy` уточнён тип restore — файловый откат не восстанавливает runtime-state, уже применённый через `chage`

- `load_config()`: добавлена обработка ключа `USER_NAMESPACES_LIMIT` — ранее попадал в `*` → warning «Неизвестный ключ»; значение не устанавливалось; интерактивный вопрос задавался даже при наличии ключа в конфиге
- `restore_empty_passwords_module`: исправлена необъявленная переменная `$empty_users_file` → `$backup` (два места)
- `restore_empty_passwords_module`: исправлены буквальные LF внутри строкового литерала Python в heredoc (`shadow.write_text("\n".join(...))`)
- `wait_for_dpkg_lock()`: ожидание lock вынесено в отдельную функцию; проверяет `lock-frontend` и `lock`; вызывается перед каждым `apt-get install` через `-o DPkg::Lock::Timeout=300`; устраняет race condition при postinst предыдущего пакета
- `apply_modules_disabled_module`: убран немедленный `sysctl -w kernel.modules_disabled=1` — параметр применяется только через dropin при следующей загрузке; немедленное применение ломало UFW/iptables при boot (emergency mode)
- `check_modules_disabled_module`: проверяет наличие dropin-файла вместо live-значения sysctl — значение вступает в силу только после reboot
- `sysctl_network_check_module`: добавлены три пропущенных параметра в проверку — `tcp_syncookies`, `icmp_echo_ignore_broadcasts`, `icmp_ignore_bogus_error_responses`; несоответствие apply (15 параметров) и check (12 параметров) устранено
- Комментарий `# Version:` в заголовке скрипта обновлён до 16.2.3
- `FSTEC_DONE_ITEMS` обновлён с 37 до 42 (dry-run вывод)
- `apply_modules_disabled_module` перемещён в конец `run_apply_mode` — dropin больше не активируется при промежуточных вызовах `sysctl --system`
- `apply_mount_hardening_module`: backup fstab переименован с `fstab.mount.bak` на `fstab.bak`; `apply_tmp_tmpfs_module` пропускает backup если mount_hardening уже сохранил его в этом сеансе — устранён конфликт двойной записи fstab
- `apply_modules_disabled_module`: временно отключён — `kernel.modules_disabled=1` через dropin в `/etc/sysctl.d/` применяется при каждом `sysctl --system` и блокирует загрузку модулей `binfmt_misc`/`xt_*` (UFW), что приводит к emergency mode при загрузке; требует реализации механизма предварительной загрузки модулей
- `print_report_stdout`: метки `фстэк: применено полностью/частично` заменены на `статус done/partial` — старые метки были семантически некорректны

### Fixed (audit)
- `load_config()`: выполнение прерывается (`die`) при некорректном config-файле вместо продолжения
- `apply_sudo_command_paths_module` (2.3.4): добавлен `chown root:root` — соответствие README
- `apply_runtime_paths_module` (2.3.2) и `apply_sudo_command_paths_module` (2.3.4): `parent_go_w` риск теперь выводит `[WARN]` с указанием каталога вместо молчаливого пропуска
- `implemented_items` в отчёте: исключены записи со статусом `not_applicable` из счётчика реализованных позиций (было 60, стало 59)
- `run_report_mode`: добавлено предупреждение что режим `--report` не выполняет проверку системы
- `tests/smoke.sh`: исправлены устаревшие ожидания (`фстэк: всего мер: 52` → `позиций: 60`, `фстэк: применено частично:` → `статус partial`)
- `docs/compatibility.md`: исправлены формулировки preflight — `policy_gate` добавляет запись в отчёт, автоматического запрета мер нет
- `docs/architecture.md`: то же — уточнена модель preflight
- `README.md`: `2.3.1 /etc/shadow` — исправлено на `chmod 640 root:shadow` (соответствие коду); добавлены пропущенные зависимости `uname`, `date`, `visudo`

## [16.2.2] - 2026-03-16

### Added
- `pam_pwhistory`: запрет повторного использования паролей (`/etc/pam.d/common-password`) — Стандарт 4.3; remember=5/10/24 по профилям baseline/strict/paranoid
- `account audit`: добавлен вывод активных systemd-служб (17.1) и открытых портов (17.2) в `account_audit.txt`

### Fixed
- `restore_empty_passwords_module`: restore больше не перезаписывает текущие пароли пользователей — восстанавливается только пустое поле для УЗ у которых оно было при apply
- `apply_empty_passwords_module`: вместо полного backup `/etc/shadow` (хэши паролей) сохраняется только список имён пользователей с пустым паролем (`empty-password-users-TIMESTAMP.txt`, chmod 600)
- `restore_auditd_module`: extended rules пропускаются при restore если не применялись (профиль baseline) — устранён spurious warning
- `restore_empty_passwords_module`: файл со списком пользователей удаляется после restore
- `restore_auditd_module`: исправлен `AttributeError: 'str' object has no attribute 'get'` при проверке `created_files`

### Not implemented (осознанные решения)
- Стандарт 4.6 (автоблокировка неиспользуемых УЗ) — не реализуется автоматически: риск блокировки служебных УЗ; отчёт для ручного контроля формируется в `account_audit.txt`
- Стандарт 9.5 (AllowUsers/AllowGroups SSH) — зависит от инфраструктуры; настраивается вручную согласно внутреннему стандарту организации
- Стандарт 14.3 (хранение журналов ≥3 мес.) — зависит от дискового пространства и инфраструктуры; настраивается вручную
- Стандарт 16.1–16.3 (защита учётных данных в файлах) — выходит за рамки OS hardening; реализуется на уровне приложений
- `ENCRYPT_METHOD=YESCRYPT` вместо `SHA512` (Приложение А Стандарта) — осознанное отступление: YESCRYPT надёжнее; зафиксировано в разделе 18 Стандарта

## [16.2.1] - 2026-03-15

### Fixed
- `user.max_user_namespaces` prompt: невалидный ввод теперь повторяет запрос вместо молчаливого skip; добавлен явный `case 3` для пропуска
- `grub_kernel_params_check_module`: добавлены пропущенные параметры `vsyscall=none` (ФСТЭК 2.5.1), `debugfs=no-mount` (2.5.3), `tsx=off` (2.5.9); для strict/paranoid добавлена проверка `apparmor=1 security=apparmor`; модуль принимает профиль как аргумент
- `check_systemd_unit_one` / `apply_systemd_unit_one`: удалён дублирующийся `return 0` (мёртвый код)
- `apply_pam_wheel_module`: удалён избыточный `if` после `die` (мёртвый код)
- `apply_sysctl_network_module`: исправлен отступ блока создания systemd unit
- `tests/smoke.sh`: добавлен `run_unprivileged()` — root-guard проверки корректно работают при запуске тестов от root

### Fixed (restore)
- `resolve_restore_manifest`: добавлен fallback на `manifest.json` если `manifest-*.json` не найден
- `restore_systemd_unit_targets_module`: восстановление только файлов из manifest (было: сканирование всей системы → 114 spurious warnings → 9)
- `restore_metadata_from_stat_snapshot`: ложные `[WARN]` при отсутствии снапшота и при попытке парсить backup содержимого как metadata понижены до `[i]`
- Вывод `фстэк: всего мер` → `позиций: N (40 пунктов ФСТЭК 25.12.2022 + N дополнительных мер)` — счётчик теперь берётся из `FSTEC_TOTAL_ITEMS`

### Added
- `apply_ufw_module`: обязательное правило `15000/udp Kaspersky` — все профили
- `examples/config.*.conf`: закомментированные примеры правил UFW для сетей (`UFW_ALLOW_FROM_1/2`)

## [16.2.0] - 2026-03-15

### Fixed
- `sysctl --system` RC временно игнорируется для dropin-модулей (на тот момент для устранения ложных `[ERROR]` при reapply, например `ptrace_scope=3`); в более поздних версиях логика частично пересмотрена
- Двойной `--force-confold` во всех 10 вызовах `apt-get install` устранён
- `pwquality.conf`: перезапись заменена на merge — параметры ФСТЭК применяются поверх существующей конфигурации
- `faillock.conf`: перезапись заменена на merge — параметры ФСТЭК применяются поверх существующей конфигурации
- AIDE: инициализация базы данных пропускается если `/var/lib/aide/aide.db` уже существует
- AppArmor: если пакет уже установлен — профили не изменяются, только проверяется статус enforce; `[WARN]` с требованием ФСТЭК
- fail2ban: `jail.local` не перезаписывается если файл уже существует; `[WARN]` с требованием ФСТЭК
- UFW: `--force reset` не выполняется если ufw уже активен; проверяется политика default incoming — `[ERROR]` если не `deny`
- Предупреждение о нехватке RAM вынесено в отдельную функцию `check_memory_requirements()`, вызывается в `run_apply_mode` до начала работы

### Added
- `apply_sysctl_network_module` / `check_sysctl_network_module` / `restore_sysctl_network_module`: сетевые sysctl (п.8.1-8.3) — `ip_forward=0`, `ipv6.forwarding=0`, `log_martians=1`, `rp_filter=1`, `accept_redirects=0`, `send_redirects=0` — все профили
- `apply_coredump_module` / `check_coredump_module` / `restore_coredump_module`: полное отключение core dumps (п.7.6) — `limits.d/99-securelinux-ng-coredump.conf` + `systemd/coredump.conf.d/99-securelinux-ng.conf` — все профили
- `apply_rkhunter_module` / `check_rkhunter_module` / `restore_rkhunter_module`: установка rkhunter (п.10.5) — paranoid
- sudo policy (п.5.2): добавлены `Defaults use_pty`, `logfile=/var/log/sudo.log`, `timestamp_timeout=5`, `passwd_tries=3`, `secure_path` — все профили
- SSH baseline: добавлен `LogLevel VERBOSE` (п.9.3) — все профили
- SSH strict+: добавлен `Banner /etc/issue.net` (п.9.4)
- GRUB strict+: добавлены `apparmor=1 security=apparmor` (п.7.3)
- GRUB strict+: `chmod 600 grub.cfg` после update-grub (п.7.7)
- Network sysctl paranoid: добавлен `tcp_timestamps=0` (п.8.3)

### Sources
- Внутренний стандарт безопасной настройки (пп. 5.2, 7.3, 7.6, 7.7, 8.1-8.3, 9.3, 9.4, 10.5)
- Чайка А.А. «Практическая безопасность Linux», БХВ-Петербург 2026

## [16.1.4] - 2026-03-15

### Fixed
- `partial` label: уточнена формулировка — откат требует reboot или ручных действий (не «применено частично»)
- Выравнивание тегов вывода `[i]`, `[?]`, `[WARN]`, `[FAIL]` до 8 символов для единообразия с `[OK]`, `[RISKY]`, `[SKIP]`, `[ERROR]`
- `aide --init`: добавлен `--config /etc/aide/aide.conf` для корректной работы на Ubuntu 24.04
- `apply_empty_passwords_module`: убран посторонний `print(changed)` выводивший `0` в stdout
- Убрано безусловное `[SKIP] framework в активной разработке` из preflight
- `apply_mount_hardening_module`, `apply_tmp_tmpfs_module`: заменены `python3 -c` heredoc на temp-файл для устранения SyntaxError на Ubuntu 24.04

### Added
- Лог-сообщения перед каждым `apt-get install` для индикации прогресса
- Секция «Конфигурационный файл» в README с примерами `--config` и `USER_NAMESPACES_LIMIT`
- Таблица покрытия ФСТЭК (done/partial) в README
- Ссылка на методдокумент ФСТЭК 25.12.2022 в README

## [16.1.3] - 2026-03-15

### Added
- `apply_apport_module` / `check_apport_module` / `restore_apport_module`: отключение apport (ФСТЭК 2.6.6 — конфликт с `fs.suid_dumpable=0`)
- `user.max_user_namespaces=0` в `61-securelinux-ng-attack-surface.conf` (ФСТЭК 2.5.5); пропускается с WARNING при наличии Docker/Podman/K8s

### Fixed
- GRUB hardening (`apply_grub_kernel_params_module`) теперь применяется на всех профилях включая baseline (ФСТЭК 2.4.3–2.4.7 не имеет ограничений по профилю)
- `check_aide_module`: profile gate strict — baseline не получает risky за отсутствие AIDE
- `check_fail2ban_module`: profile gate paranoid — baseline/strict не получают risky
- `check_mount_hardening_module`: profile gate paranoid
- `check_tmp_tmpfs_module`: profile gate paranoid
- `sysctl_attack_surface_check_module`: profile-aware — baseline не проверяет `perf_event_paranoid`, `unprivileged_bpf_disabled`
- `sysctl_userspace_protection_check_module`: profile-aware — baseline не проверяет `ptrace_scope`
- `run_restore_mode`: добавлены вызовы `restore_rsyslog_module`, `restore_chrony_module`, `restore_unattended_upgrades_module`, `restore_apport_module`
- `SYSCTL_USERSPACE_PROTECTION_DROPIN`: переименован с `62-` на `99-` для переопределения `/usr/lib/sysctl.d/99-protect-links.conf`
- Runtime paths check: исключены системные директории `/var/log`, `/tmp`, `/run`, `/dev/shm` из проверки `parent_go_w`
- `check_systemd_unit_one` / `apply_systemd_unit_one`: отсутствующие symlink targets → `skipped` вместо `risky`
- Подавлен вывод сообщений `symlink skipped (target managed by package)` в 2.3.5

### Changed
- `add_safe` / `add_risky` / `add_warning` / `add_error` / `add_skipped`: немедленный вывод в терминал в реальном времени
- `print_report_stdout`: вывод risky/warnings/errors в конце отчёта
- `SCRIPT_VERSION`: 16.1.0 → 16.1.2

## [16.1.2] - 2026-03-15

### Fixed
- `check_aide_module`: profile gate strict
- `check_fail2ban_module`: profile gate paranoid
- `check_mount_hardening_module`: profile gate paranoid
- `check_tmp_tmpfs_module`: profile gate paranoid
- `run_restore_mode`: добавлены rsyslog/chrony/unattended_upgrades
- `sysctl_attack_surface_check_module`: profile-aware (perf/bpf skip on baseline)
- `sysctl_userspace_protection_check_module`: profile-aware (ptrace skip on baseline)

## [16.1.0] - 2026-03-15

### Fixed
- `set -Eeuo pipefail` → `set -uo pipefail`: убран `-e`, устранены аварийные выходы по RC≠0 от systemctl/grep
- `apply_ufw_module`: `systemctl is-active/is-enabled nftables` — заменено на `if..then` вместо `&&/||`
- `apply_systemd_unit_one` / `check_systemd_unit_one`: пропуск симлинков (`-L`), устранены 98 ложных ошибок 2.3.5
- dry-run: `fstec_done: 0` / `fstec_partial: 51` → используют `FSTEC_DONE_ITEMS` / `FSTEC_PARTIAL_ITEMS`
- dry-run: FileNotFoundError при чтении несуществующего report — убран python3-блок
- login.defs: разорванный f-string в embedded Python → заменено на heredoc
- Без аргументов: `die` → `usage; exit 0`

### Added
- Модули `apply_rsyslog_module`, `apply_chrony_module`, `apply_unattended_upgrades_module` — baseline (соответствие v15)
- Установка `libpam-pwquality` `cracklib-runtime` в `apply_password_policy_module`
- `FSTEC_DONE_ITEMS=33`, `FSTEC_PARTIAL_ITEMS=18` — константы для dry-run вывода

### Changed
- `apply_aide_module`: профиль без изменений (`strict+`)
- `apply_fail2ban_module`: профиль без изменений (`paranoid`)

## [16.0.0] - 2026-03-14

### Added
- framework skeleton in `securelinux-ng.sh`
- config examples in `examples/`
- basic `syntax` and `smoke` tests
- expanded `docs/architecture.md`
- strict initial `docs/fstec-mapping.md`
- first real hardening module `2.1.2`: disable SSH root login via `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf`
- `--check` and `--apply` coverage for SSH root login enforcement
- `sshd -t` validation after apply
- `2.2.1`: restrict `su` via `pam_wheel.so use_uid group=wheel`
- group `wheel` creation during apply if absent
- managed block insertion into `/etc/pam.d/su`
- `2.3.1`: check/apply owner, group and mode for `/etc/passwd`, `/etc/group`, `/etc/shadow`
- `2.2.2`: add managed sudo policy drop-in `/etc/sudoers.d/60-securelinux-ng-policy` with `visudo` validation
- `2.3.3`: add initial cron ownership/perms module for standard cron targets (later reclassified to `2.3.6`)
- `2.3.5`: add initial systemd unit/drop-in ownership/perms module for `/etc/systemd/system`
- add basic restore flow for managed SSH/PAM/sudo files and created group `wheel`
- add `--manifest FILE` support for restore
- extend restore to `2.3.1`, `2.3.5` and cron-target permissions module (later reclassified from `2.3.3` to `2.3.6`) using metadata snapshots
- fix `record_manifest_backup` call in systemd permissions module
- switch metadata restore snapshots to machine-readable `MODE/UID/GID` format with fallback for legacy snapshots
- add writable fallback `STATE_DIR` for non-root `check/report/restore` runs
- add `fstec_items` and `fstec_summary` to generated report output
- extend smoke test with `--restore --manifest` path
- add smoke assertions for FSTEC summary in stdout
- `2.3.2`: add runtime executable/library permissions scan with policy-gated detect-only apply
- `2.3.4`: add sudo command paths permissions scan with policy-gated detect-only apply
- `2.4.1`, `2.4.2`, `2.4.8`: add base kernel sysctl hardening module with restore support
- suppress non-root sysctl stderr noise in kernel sysctl check module
- `2.4.3`..`2.4.7`: add audit/detect-only GRUB kernel params module based on `/proc/cmdline`
- `2.5.2`, `2.5.4`, `2.5.6`, `2.5.7`, `2.5.8`, `2.5.10`, `2.5.11`: add attack-surface sysctl module with restore support
- `2.6.1`..`2.6.6`: add userspace-protection sysctl module with restore support
- `2.5.1`, `2.5.3`, `2.5.9`: extend GRUB audit module for remaining attack-surface boot params
- `2.1.1`: add empty-password account detection and lock module based on `/etc/shadow`
- handle non-root `/etc/shadow` access gracefully in `2.1.1` without Python traceback
- add centralized execution-context guard: non-dry-run apply and restore now require root
- `2.3.10`, `2.3.11`: add home files and home directories permissions module with metadata restore
- `2.3.7`: add user cron files permissions module with metadata restore
- `2.3.8`: add standard system paths permissions audit module (detect-only apply)
- `2.3.9`: add SUID/SGID audit module (detect-only apply)
- reclassify cron config targets module from `2.3.3` to `2.3.6` in mapping/report
- `2.3.3`: add detect-only audit module for command paths referenced from system cron configs
- fix broken embedded Python quoting in `2.3.8` standard system paths audit module
- isolate smoke-test scans from host `/proc`, `/home`, user-cron, standard-system-path and suid/sgid trees via test-only environment overrides
- align `tests/smoke.sh` with enforced root-guard: non-root restore is now checked as a denial path, not executed as a success path

### Fixed
- normalize explicit `add_policy_gate(...)` markers across remaining detect-only/policy-gated modules, not only `2.3.2` and `2.3.3`
- add `restore_policy_gated_detect_only` to `fstec_summary` and stdout summary, so detect-only modules are counted explicitly in report output
- record explicit policy-gate entries in code for detect-only modules `2.3.2` and `2.3.3`, instead of relying only on warnings/skipped markers
- add missing `--manifest` mention to the `CLI framework` row in `docs/fstec-mapping.md`
- document `--manifest FILE` in `docs/architecture.md` as a supported framework-level option for explicit restore input
- align remaining `2.3.7`, `2.3.10`, `2.3.11` restore wording with machine-readable metadata snapshots in `README.md` and `docs/fstec-mapping.md`
- ignore local state and research worktrees in `.gitignore` to keep `git status` clean during iterative development
- clarify `2.3.6` documentation wording for machine-readable metadata snapshots and cron-target reclassification history
- align `docs/fstec-mapping.md` wording with machine-readable metadata snapshots and the later `2.3.3` → `2.3.6` cron reclassification
- align per-module support bullets in `README.md` with actual restore coverage for SSH/PAM/sudo and metadata-based permission modules
- document actual restore coverage in `README.md` and `docs/restore-model.md` for metadata-based modules and managed sysctl drop-ins
- fix unset shell variable in `2.3.2` dry-run summary output
- dry-run summary output without reading a non-existent report file
- smoke test now uses a local writable state directory


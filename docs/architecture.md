# Архитектура SecureLinux-NG

## Назначение

SecureLinux-NG — framework для безопасной настройки Linux-хостов с опорой на требования и рекомендации ФСТЭК, с обязательной проверкой совместимости до применения изменений, фиксацией действий в manifest/report и контролируемым откатом там, где это возможно.

## Текущая версия: 16.2.8

Framework и все hardening-модули реализованы. История изменений по версиям — в CHANGELOG.md.

## Основные режимы

Поддерживаемые режимы:
- `--help`
- `--version`
- `--check`
- `--apply`
- `--restore`
- `--report`

Поддерживаемые опции framework-уровня:
- `--dry-run`
- `--profile=baseline|strict|paranoid`
- `--config <file>`
- `--manifest <file>` — явный manifest для `--restore`

## Модель профилей

Проект использует три профиля:
- `baseline`
- `strict`
- `paranoid`

Назначение профилей:
- `baseline` — минимально необходимый и максимально совместимый уровень;
- `strict` — усиленный уровень с большим количеством ограничений;
- `paranoid` — максимально жёсткий профиль, допускающий дополнительные compatibility-ограничения.


## Модель конфигурации

Приоритет источников конфигурации:
1. defaults внутри скрипта;
2. внешний config file;
3. CLI overrides.

CLI `--profile` всегда имеет приоритет над значением из config-файла (флаг `_PROFILE_SET_BY_CLI`).

Минимально поддерживаемые ключи config:
- `PROFILE`
- `STATE_DIR`
- `REPORT_FILE`
- `MANIFEST_FILE`
- `USER_NAMESPACES_LIMIT`
- `UFW_EXTRA_RULES`

Требования к config:
- формат `KEY=VALUE`;
- пустые строки и комментарии допустимы;
- неизвестные ключи не должны ломать выполнение, но должны отражаться как warning.

## Preflight / compatibility model

Перед применением hardening-мер должен выполняться preflight-анализ среды.

Минимум, что должен определять preflight:
- семейство ОС;
- версия ОС;
- container / non-container;
- desktop / server-like environment;
- Docker;
- Podman;
- Kubernetes node.

Результат preflight должен раскладываться минимум на 4 категории:
- `safe`
- `risky`
- `skipped`
- `requires_confirmed_policy`

Принцип:
- framework не должен молча применять потенциально опасные меры;
- сомнительные меры маркируются через `policy_gate` — запись в отчёт с предупреждением;
- автоматического запрета мер по среде нет: решение о применении остаётся за администратором.

## Manifest model

Manifest должен быть машинно-читаемым и пригодным для restore/report.

Все записи в manifest выполняются атомарно (temp file + `fsync` + `os.replace`), чтобы прерывание процесса не могло повредить JSON.

Минимальные поля manifest:
- `version`
- `profile`
- `mode`
- `timestamp`
- `backups`
- `created_files`
- `created_groups`
- `modified_files`
- `systemd_units`
- `sysctl_configs`
- `grub_backups`
- `apply_report`
- `warnings`
- `irreversible_changes`


## Restore model

Restore в SecureLinux-NG должен опираться не на догадки, а на manifest.

Restore-модель должна предполагать:
- восстановление изменённых файлов из backup;
- удаление созданных файлов;
- удаление созданных групп;
- удаление созданных systemd unit/drop-in;
- удаление созданных sysctl drop-in;
- отдельную маркировку действий, которые автоматически неоткатны.

Restore-модель не является полностью симметричной для всех мер:
- часть изменений откатывается только частично;
- часть изменений требует ручных действий;
- часть runtime-эффектов не должна восстанавливаться автоматически по соображениям безопасности.

Примеры асимметричного restore:
- пакеты (`rkhunter`, `unattended-upgrades`, `chrony`, `rsyslog`) не удаляются автоматически;
- для заранее активного UFW restore остаётся partial и не откатывает исходные правила автоматически;
- пустые поля пароля в `/etc/shadow` не восстанавливаются автоматически по соображениям безопасности.

Если откат невозможен, это должно быть явно отражено в manifest/report.

При повторном `--apply` с существующим manifest — администратор подтверждает продолжение, после чего существующий manifest архивируется в `.bak-<timestamp>` и создаётся новый.

## Report model

После `--check`, `--apply`, `--restore` и `--report` должен существовать единый формат итогового report.

Минимальные разделы report:
- версия;
- профиль;
- режим;
- сведения о среде;
- `safe`;
- `risky`;
- `skipped`;
- `requires_confirmed_policy`;
- `warnings`;
- `errors`.

На этапе dry-run report может не писаться на диск, но summary должен печататься в stdout.

## Защита от параллельного запуска

Режимы `--apply` и `--restore` защищены через `flock` (`acquire_run_lock`). При обнаружении параллельного экземпляра — немедленное завершение с ошибкой.

## Гарантия backup при apply

Все backup-операции перед перезаписью конфигов выполняются через `backup_file_checked()` с проверкой успеха `cp`. Если backup не удался (диск заполнен, ошибки I/O) — модуль пропускается, а не продолжает с потерянным оригиналом. Это критично для PAM, SSH, sudoers, sysctl dropin-файлов.

## Атомарная запись критичных файлов

Модификация `/etc/shadow` (блокировка пустых паролей) выполняется через атомарную запись: temp file + `fsync` + `os.replace`, чтобы аварийное завершение не могло повредить файл аутентификации.

## Dry-run model

`--dry-run` допустим только вместе с `--apply`.

В dry-run framework обязан:
- ничего не менять в системе;
- показывать, что было бы создано;
- показывать, что было бы изменено;
- показывать, какие артефакты manifest/report были бы созданы;
- печатать итоговую summary без требования реального наличия report-файла.

## Разделение framework и hardening

Правило проекта: framework и hardening не смешивать. Все шесть этапов разработки пройдены: framework, preflight, config/report/manifest, hardening-модули, coverage checks, restore verification.

## Группы hardening-модулей

### Реализованы
1. **identity / auth / PAM / SSH** — 2.1.1, 2.1.2, SSH hardening, faillock, pwquality, login.defs, `chage` для существующих локальных УЗ, нормализация `common-password` (`pam_pwquality -> pam_pwhistory -> pam_unix`), 2.2.1, 2.2.2
2. **file permissions / ownership** — 2.3.1–2.3.11
3. **kernel / sysctl / boot** — 2.4.x, 2.5.x, 2.6.x, GRUB apply
4. **audit** — auditd baseline (identity, sudo, sshd, modules, privileged, network bind/connect, usb_devices) + extended
5. **firewall** — UFW
6. **mount hardening** — /tmp tmpfs, /dev/shm, /var/tmp
7. **kernel modules** — blacklist неиспользуемых ФС и протоколов
8. **intrusion detection** — fail2ban, AIDE, rkhunter
9. **mandatory access control** — AppArmor enforce
10. **reporting** — account audit, coverage report
11. **network hardening** — sysctl network (ip_forward, log_martians, rp_filter, redirects, tcp_syncookies, icmp_echo_ignore_broadcasts, icmp_ignore_bogus_error_responses, tcp_syn_retries)
12. **core dumps** — limits.d + systemd coredump.conf + kernel.core_pattern sysctl dropin

## Трассировка требований

Каждый hardening-блок должен иметь:
- ссылку на пункт ФСТЭК;
- статус покрытия;
- проверку результата;
- отражение в `docs/fstec-mapping.md`.

Блок не считается реализованным окончательно без:
- кода;
- проверки;
- отражения в mapping.

## Структура main()

Порядок вызовов в `main()`:
1. `parse_args` — разбор CLI (включая `--help`/`--version`, которые завершаются сразу);
2. `require_cmds` — проверка наличия обязательных команд;
3. `validate_args` — проверка аргументов;
4. `load_config` — загрузка внешнего config;
5. `validate_args_post_config` — проверка профиля после загрузки конфига;
6. `validate_execution_context` — проверка root для apply/restore;
7. `finalize_paths` — вычисление путей report/manifest/log.

`--help` и `--version` работают без проверки наличия системных команд.

## Документационный принцип

Для SecureLinux-NG порядок должен быть таким:
1. сначала фиксируется архитектура;
2. затем меняется код;
3. затем добавляются тесты;
4. затем обновляются README / CHANGELOG / mapping.

## Report coverage model

Итоговый `report` должен включать не только среду и warnings/errors, но и отдельный блок покрытия ФСТЭК:
- `fstec_items`
- `fstec_summary`

Это позволяет видеть текущий фактический объём реализованных модулей без чтения `docs/fstec-mapping.md`.

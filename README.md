# SecureLinux-NG

> Bash-скрипт безопасной настройки Linux-хостов по требованиям ФСТЭК России.
> Покрывает 40 пунктов методического документа от 25.12.2022 + 20 дополнительных мер = 60 позиций; из них 59 реализованы: `done=39`, `partial=20`. `15.1 kernel.modules_disabled=1` временно не применяется автоматически.

![Version](https://img.shields.io/badge/версия-16.2.11-blue)
![Platform](https://img.shields.io/badge/ОС-Debian%2012%2F13%20%7C%20Ubuntu%2022.04%2F24.04-informational)
![FSTEC](https://img.shields.io/badge/ФСТЭК-40%20пунктов%20%2B%2020%20доп.%20мер%20%3D%2060%20позиций-green)
![License](https://img.shields.io/badge/лицензия-MIT-lightgrey)

---

## Назначение

SecureLinux-NG — инструмент управляемой безопасной настройки Linux-хостов в соответствии с **«Рекомендациями по безопасной настройке операционных систем Linux»** ФСТЭК России (методический документ от 25.12.2022).

Ключевые возможности:

- Три профиля: `baseline` / `strict` / `paranoid`
- Дополнительные меры отключены по умолчанию и включаются для текущего `--apply` флагом `--enable-additional-measures` либо параметром `ENABLE_ADDITIONAL_MEASURES=1` в config-файле
- JSON manifest — каждое изменение фиксируется, откат через `--restore`
- Preflight-анализ среды — Docker, K8s, desktop, container
- `--check` / `--apply` / `--restore` / `--report` / `--dry-run`
- Debian 12/13, Ubuntu 22.04/24.04

---

## Быстрый старт

```bash
wget https://github.com/rasav65/SecureLinux-NG/archive/refs/heads/main.tar.gz
tar -xzf main.tar.gz
cd SecureLinux-NG-main
```

> **⚠ На рабочих серверах — всегда выполняйте `--dry-run` перед `--apply`.**

```bash
# Просмотр изменений без применения
sudo ./securelinux-ng.sh --apply --dry-run --profile strict

# Применение основного набора без дополнительных мер
sudo ./securelinux-ng.sh --apply --profile baseline
sudo ./securelinux-ng.sh --apply --profile strict --config examples/config.strict.conf

```

### **Применение с дополнительными мерами и расширенными политиками безопасности**

> **Важно:** подробное описание параметра [`--enable-additional-measures`](#дополнительные-меры) приведено ниже, в разделе [«Дополнительные меры»](#дополнительные-меры).

```bash
sudo ./securelinux-ng.sh \
  --apply \
  --profile baseline \
  --enable-additional-measures

# Проверка состояния
sudo ./securelinux-ng.sh --check --profile strict

# Откат
sudo ./securelinux-ng.sh --restore
```

---

## Надёжность framework

> Раздел описывает гарантии текущего релиза. История появления изменений указана в `CHANGELOG.md`.

Архитектурные схемы: [`docs/architecture.md`](docs/architecture.md#общая-схема-выполнения).

| Гарантия | Описание |
|---|---|
| Атомарность manifest | Все записи в manifest JSON — через temp + fsync + `os.replace` |
| Атомарность `/etc/shadow` | Блокировка пустых паролей — через temp + fsync + `os.replace` |
| Проверка backup | `backup_file_checked()` — при ошибке backup системный файл не изменяется; модуль прекращает операцию с warning или error |
| Защита от параллельного запуска | `flock` для `--apply` и `--restore` |
| CLI приоритет | `--profile` и `--enable-additional-measures` из командной строки приоритетнее соответствующих значений из config |
| `--help`/`--version` | Работают без проверки наличия системных команд |
| Изолированное применение sysctl | Каждый модуль применяет только собственный drop-in через `sysctl -p`; глобальный `sysctl --system` не используется |
| Runtime restore sysctl | До `apply` сохраняются live-значения каждого sysctl-модуля; при `restore` они возвращаются адресно через `sysctl -w` |
| Проверка auditd runtime | `--check` сверяет `rules.d`, загруженные правила, watch-пути и ключи |
| Безопасный повторный apply/restore | Существующие account audit и systemd unit архивируются и восстанавливаются |
| Код возврата | Отмена `--apply` и итоговые `ERROR` возвращают ненулевой код |

> `securelinux-ng-sysctl.service` является oneshot-unit и повторно применяет
> только сетевой drop-in после `network-online.target`. Это защищает настройки
> `/proc/sys/net/*` от сброса при позднем создании или поднятии интерфейсов.
> Состояние `active (exited)` для этого сервиса штатное.


---

## Профили

| Профиль | Описание | Типичная среда |
|---|---|---|
| `baseline` | Все ФСТЭК 2.1–2.3, sysctl, GRUB, базовые сервисы | Сервер после dry-run и проверки совместимости нагрузки |
| `strict` | baseline + AppArmor, AIDE, auditd extended | Сервер общего назначения |
| `paranoid` | strict + fail2ban, /tmp tmpfs, mount hardening, rkhunter, tcp_timestamps=0, usb_storage blacklist | Изолированный сервер |

**Формулировку про «закрываются все 60» считать устаревшей: в текущей версии реализованы 59 из 60 позиций, а `15.1 kernel.modules_disabled=1` временно не применяется автоматически.**

Подробная таблица совместимости: [`docs/compatibility.md`](docs/compatibility.md)

---

## Покрытие ФСТЭК 25.12.2022

Для всех **40 пунктов** разделов 2.1–2.6 реализовано техническое покрытие `apply/check`; часть мер имеет статус `partial`.

### 2.1. Настройка авторизации

| Пункт | Мера | Профиль |
|---|---|---|
| 2.1.1 | Блокировка УЗ с пустым паролем (`/etc/shadow`) | все |
| 2.1.2 | SSH: `PermitRootLogin no` (drop-in) | все |
| 2.1.2 | SSH: расширенный hardening (Ciphers, MACs, KexAlgorithms, LogLevel) | все/strict |
| Дополнительная корпоративная мера | Password policy: `PASS_MAX_DAYS=90/60/45`, `common-password` → `pam_pwquality -> pam_pwhistory -> pam_unix`; применяется только при `ENABLE_CORPORATE_PASSWORD_POLICY=1` | baseline / strict / paranoid |
| Дополнительная корпоративная мера | PAM faillock: блокировка УЗ при переборе паролей; применяется только при `ENABLE_CORPORATE_PASSWORD_POLICY=1` | strict+ |

По умолчанию `ENABLE_CORPORATE_PASSWORD_POLICY=0`: данные меры не изменяют PAM, `login.defs`, `chage` и `faillock.conf`.

Для безопасного включения ограничения `su` скрипт использует существующих администраторов, уже входящих в `sudo`, `admin` или `wheel`. Явно заданный пробел-разделённый список `WHEEL_USERS` имеет приоритет. Если `WHEEL_USERS` пуст и запуск выполняется через `sudo`, администратор автоматически определяется по проверенному `SUDO_USER`. Затем `root` и выбранные администраторы добавляются в `wheel`, после чего активируется `pam_wheel`. Ошибка регистрируется только когда ни явный список, ни безопасное автоматическое определение недоступны.

### 2.2. Ограничение получения привилегий

| Пункт | Мера | Профиль |
|---|---|---|
| 2.2.1 | Ограничение `su` через `pam_wheel.so use_uid` + непустая группа `wheel`; администраторы задаются через `WHEEL_USERS` либо автоматически определяются по `SUDO_USER` | все |
| 2.2.2 | Sudo policy: `%wheel ALL=(ALL:ALL) ALL`, use_pty, logfile, timeout | все |

### 2.3. Права доступа к объектам файловой системы

| Пункт | Мера | Профиль |
|---|---|---|
| 2.3.1 | `chmod 644 /etc/passwd`, `/etc/group`; `chmod go-rwx /etc/shadow` без изменения владельца и группы | все |
| 2.3.2 | `chmod go-w` файлов запущенных процессов и их библиотек | все |
| 2.3.3 | `chmod go-w` файлов, выполняемых через cron | все |
| 2.3.4 | `chmod go-w` + `chown root` файлов, выполняемых через sudo | все |
| 2.3.5 | Права на `.service` и unit-файлы в `/etc/systemd/system` | все |
| 2.3.6 | Права на `/etc/crontab`, `/etc/cron.d`, `/etc/cron.*` | все |
| 2.3.7 | Права на пользовательские файлы заданий cron | все |
| 2.3.8 | `chmod go-w` системных бинарей и библиотек (`/bin`, `/lib`, `$PATH`) | все |
| 2.3.9 | Аудит и исправление прав SUID/SGID приложений | все |
| 2.3.10 | `chmod go-rwx` для `.bash_history`, `.bashrc`, `.profile` и др. в home | все |
| 2.3.11 | `chmod 700` для домашних директорий пользователей | все |

> Требование ФСТЭК 2.3.1 для `/etc/shadow` реализуется буквально через `chmod go-rwx`: права группы и остальных удаляются без изменения владельца, группы и прав владельца.
> Исходные mode/uid/gid сохраняются в manifest и возвращаются при `--restore`.

## 2.4. Настройка механизмов защиты ядра

| Пункт | Мера | Профиль |
|---|---|---|
| 2.4.1 | `kernel.dmesg_restrict=1` | все |
| 2.4.2 | `kernel.kptr_restrict=2` | все |
| 2.4.3 | GRUB: `init_on_alloc=1` | все |
| 2.4.4 | GRUB: `slab_nomerge` | все |
| 2.4.5 | GRUB: `iommu=force iommu.strict=1 iommu.passthrough=0` | все |
| 2.4.6 | GRUB: `randomize_kstack_offset=1` | все |
| 2.4.7 | GRUB: `mitigations=auto,nosmt` | все |
| 2.4.8 | `net.core.bpf_jit_harden=2` | все |

### 2.5. Уменьшение периметра атаки ядра

| Пункт | Мера | Профиль |
|---|---|---|
| 2.5.1 | GRUB: `vsyscall=none` | все |
| 2.5.2 | `kernel.perf_event_paranoid=3` | все |
| 2.5.3 | GRUB: `debugfs=off` | все |
| 2.5.4 | `kernel.kexec_load_disabled=1` | все |
| 2.5.5 | `user.max_user_namespaces` задаётся через `USER_NAMESPACES_LIMIT` или выбор администратора (`0` / `10000` / skip) | все |
| 2.5.6 | `kernel.unprivileged_bpf_disabled=1` | все |
| 2.5.7 | `vm.unprivileged_userfaultfd=0` | все |
| 2.5.8 | `dev.tty.ldisc_autoload=0` | все |
| 2.5.9 | GRUB: `tsx=off` | все |
| 2.5.10 | `vm.mmap_min_addr=4096` | все |
| 2.5.11 | `kernel.randomize_va_space=2` | все |

### 2.6. Защита пользовательского пространства

| Пункт | Мера | Профиль |
|---|---|---|
| 2.6.1 | `kernel.yama.ptrace_scope=3` | все |
| 2.6.2 | `fs.protected_symlinks=1` | все |
| 2.6.3 | `fs.protected_hardlinks=1` | все |
| 2.6.4 | `fs.protected_fifos=2` | все |
| 2.6.5 | `fs.protected_regular=2` | все |
| 2.6.6 | `fs.suid_dumpable=0` | все |

Подробная карта соответствия: [`docs/fstec-mapping.md`](docs/fstec-mapping.md)

---

## Дополнительные меры

Обычный `--apply` применяет основной набор hardening и сохраняет `ENABLE_ADDITIONAL_MEASURES=0`.

Флаг `--enable-additional-measures` допустим только с `--apply`, имеет приоритет над config-файлом и включает 17 модулей:

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

При таком запуске manifest содержит:

```json
"additional_measures_enabled": true
```

При обычном запуске через `sudo` вручную заполнять `WHEEL_USERS` не требуется: скрипт проверяет и использует `SUDO_USER`. Явно заданный `WHEEL_USERS` применяется с приоритетом.

Меры из внутреннего стандарта организации и книги Чайка А.А. «Практическая безопасность Linux» (БХВ-Петербург, 2026) — не входят в разделы 2.x методдокумента ФСТЭК:

| Пункт стандарта | Мера | Профиль |
|---|---|---|
| п.14.1–14.2 | auditd: baseline + extended rules | все/strict |
| п.8.4 | UFW: default deny incoming, allow SSH | все |
| п.7.5 | Blacklist неиспользуемых модулей ядра (ФС и протоколы) | все |
| п.4.6 | Account audit report | все |
| п.10.4 | /tmp tmpfs (nosuid,nodev,noexec) | paranoid |
| п.10.4 | mount hardening: /dev/shm, /var/tmp | paranoid |
| п.9.6 | fail2ban SSH jail | paranoid |
| п.10.5 | AIDE integrity monitoring | strict+ |
| п.10.1 | AppArmor enforce mode | strict+ |
| п.8.1-8.3 | Network sysctl: ip_forward, log_martians, rp_filter, redirects, tcp_syn_retries | все |
| п.7.6 | Отключение core dumps (limits.d + systemd/coredump.conf + kernel.core_pattern) | все |
| п.7.7 | `chmod 600 /boot/grub/grub.cfg` | все |
| п.9.3 | SSH: `LogLevel VERBOSE` | все |
| п.9.4 | SSH: `Banner /etc/issue.net` | strict+ |
| п.8.3 | `net.ipv4.tcp_timestamps=0` | paranoid |
| п.10.5 | rkhunter: обнаружение руткитов | paranoid |
| п.4.3 | `pam_pwhistory`: опциональная корпоративная мера, включаемая через `ENABLE_CORPORATE_PASSWORD_POLICY=1` | по флагу |
| п.17.1 | Account audit: вывод активных systemd-служб | все |
| п.17.2 | Account audit: вывод открытых портов (`ss -tlnp`) | все |

**Дополнительные меры из книги «Практическая безопасность Linux» (Чайка А.А., 2026):**

| Пункт стандарта | Мера | Профиль |
|---|---|---|
| — | `net.ipv4.tcp_syncookies=1`: защита от SYN-флуд | все |
| — | `net.ipv4.icmp_echo_ignore_broadcasts=1`: защита от Smurf-атак | все |
| — | `net.ipv4.icmp_ignore_bogus_error_responses=1`: защита от поддельных ICMP-ошибок | все |
| п.8.3 | `net.ipv4.tcp_syn_retries=3`: ограничение повторных SYN | все |
| п.14.1 | auditd baseline: аудит `bind/connect` (k=network), `/dev/bus/usb` (k=usb_devices) | все |
| — | `usb_storage` blacklist: блокировка USB-накопителей (дополнительная корпоративная мера) | paranoid |
| — | `kernel.modules_disabled=1`: запрет загрузки модулей ядра (write-once) — **временно не применяется автоматически** | paranoid |

---

## Конфигурационный файл

Чтобы избежать интерактивных вопросов при `--apply`, используйте `--config FILE`.

`ENABLE_ADDITIONAL_MEASURES=1` в config-файле также включает дополнительные меры. Явный флаг `--enable-additional-measures` имеет высший приоритет и не может быть выключен значением `ENABLE_ADDITIONAL_MEASURES=0` из config-файла.

Без Docker/Podman/K8s:
```
PROFILE=strict
USER_NAMESPACES_LIMIT=0
UFW_EXTRA_RULES=15000/udp:Kaspersky
```

С Docker/Podman/K8s:
```
PROFILE=strict
ENABLE_CORPORATE_PASSWORD_POLICY=0
# Дополнительные меры внутреннего стандарта: auditd, UFW, AppArmor, AIDE и другие
ENABLE_ADDITIONAL_MEASURES=0
WHEEL_USERS=
USER_NAMESPACES_LIMIT=10000
UFW_EXTRA_RULES=15000/udp:Kaspersky
```

Готовые шаблоны: `examples/config.baseline.conf`, `examples/config.strict.conf`, `examples/config.paranoid.conf`

---

## Важно перед применением

- `--restore` удаляет только пакеты, впервые установленные модулем корпоративной парольной политики и записанные в manifest-поле `installed_packages`; пакеты дополнительных модулей (chrony, auditd, ufw, AppArmor и др.) автоматически не удаляются
- Перед пакетными операциями скрипт ждёт фактического освобождения блокировок `apt/dpkg`; чужие процессы не завершаются. В интерактивном режиме статус обновляется каждые 30 секунд.
- `kernel.kexec_load_disabled=1` — необратимо до перезагрузки
- GRUB params — вступают в силу только после перезагрузки
- При restore восстанавливается `/etc/default/grub` и выполняется `update-grub`; функциональная конфигурация возвращается, но побайтовое совпадение с исходным `/boot/grub/grub.cfg` не гарантируется
- AppArmor, AIDE, apport — не восстанавливаются автоматически, требуют ручных действий
- `restore 2.1.1`: пустые поля пароля в `/etc/shadow` **не восстанавливаются автоматически** по соображениям безопасности
- UFW: если firewall был активен **до** `--apply`, restore остаётся **partial** — исходные правила и состояние до применения не откатываются автоматически
- UFW: если firewall неактивен, но содержит предварительно настроенные правила, автоматическое включение блокируется; `ufw reset` не выполняется
- SSH-порт для UFW и fail2ban принимается только как число в диапазоне `1–65535`; при некорректном значении используется проверенный fallback
- `unattended-upgrades` в `--check` оценивается по факту **включения автоматических обновлений** (`enabled`), а не по постоянному `active` состоянию службы
- Для профиля `baseline` AppArmor не является обязательной мерой: если он не активен, `--check` помечает это как `SKIP`, а не как `RISKY`
- **Password aging**: применяется через `chage` только при `ENABLE_CORPORATE_PASSWORD_POLICY=1`. Заблокированные, пустые и служебные учётные записи исключаются. До изменения исходные поля aging сохраняются в manifest и восстанавливаются командой `--restore`. Для просроченных активных УЗ `lastchg` сдвигается на сегодня
- `user.max_user_namespaces` — значение задаётся через `USER_NAMESPACES_LIMIT` или выбор администратора при apply; `0` может ломать Docker/Podman/K8s
- Для `kernel.perf_event_paranoid`, `kernel.unprivileged_bpf_disabled` и `vm.mmap_min_addr` скрипт сохраняет уже установленное более строгое числовое значение
- `kernel.modules_disabled=1` — временно не применяется автоматически (несовместим с binfmt_misc и UFW при загрузке); запланирован в следующей версии; только paranoid

Подробно: [`docs/restore-model.md`](docs/restore-model.md), [`docs/compatibility.md`](docs/compatibility.md)

---

## Требования к запуску

- `--check`, `--report`, `--apply --dry-run` рекомендуется выполнять через `sudo` для полного доступа к системным объектам
- `--apply`, `--restore` — требуют `root`
- ОС: Debian 12/13, Ubuntu 22.04/24.04
- Зависимости: `bash`, `python3`, `systemctl`, `sysctl`, `stat`, `awk`, `grep`, `uname`, `date`, `visudo`

---

## Архитектурные принципы

1. **Обратимость** — каждое изменение фиксируется в JSON manifest. `--restore` восстанавливает из backup или удаляет созданные объекты.
2. **Проверяемость** — `--check` работает независимо от `--apply`, не изменяет систему, каждый модуль имеет отдельную check-функцию.
3. **Трассируемость** — каждая мера привязана к пункту ФСТЭК в [`docs/fstec-mapping.md`](docs/fstec-mapping.md) и в JSON report.
4. **Профильное ветвление** — три профиля с явным `profile_allows()` без неявных зависимостей.
5. **Безопасность применения** — preflight определяет среду и добавляет `policy_gate`/warning для compatibility-sensitive мер; окончательное решение остаётся за администратором.

---

## Структура проекта

```
securelinux-ng.sh          — основной скрипт
docs/
  fstec-mapping.md         — карта соответствия требованиям ФСТЭК
  restore-model.md         — модель отката
  architecture.md          — архитектура проекта
  compatibility.md         — совместимость и ограничения по средам
examples/
  config.baseline.conf     — шаблон конфига для baseline
  config.strict.conf       — шаблон конфига для strict
  config.paranoid.conf     — шаблон конфига для paranoid
tests/
  syntax.sh                       — проверка синтаксиса
  smoke.sh                        — полный smoke-набор
  password-policy-regression.sh   — регрессия парольной политики
  backup-failure-regression.sh    — блокировка изменений при ошибке backup
  firewall-safety-regression.sh   — безопасность UFW и определение SSH-порта
  architecture-regression.sh      — соответствие архитектурных схем коду
  wheel-aging-regression.sh       — регрессия wheel и restore aging
  runtime-paths-regression.sh     — права runtime-путей
  fs-critical-regression.sh       — права критических файлов
  wheel-fstec-regression.sh       — безопасная настройка wheel
  additional-measures-optin-regression.sh — opt-in дополнительных мер
  empty-password-restore-regression.sh — restore пустых паролей
  password-package-restore-regression.sh — restore пакетов password policy
  sysctl-stricter-values-regression.sh — сохранение строгих sysctl
```

---

## Осознанные решения

Меры внутреннего стандарта, которые намеренно не реализованы автоматически:

| Пункт стандарта | Причина |
|---|---|
| 4.6 — автоблокировка неиспользуемых УЗ | Риск блокировки служебных УЗ без ручного контроля. Отчёт формируется в `account_audit.txt` |
| 9.5 — `AllowUsers`/`AllowGroups` SSH | Зависит от инфраструктуры. Настраивается вручную согласно внутреннему стандарту |
| 14.3 — хранение журналов ≥3 мес. | Зависит от дискового пространства и инфраструктуры сбора логов |
| 16.1–16.3 — защита учётных данных в файлах | Выходит за рамки OS hardening. Реализуется на уровне приложений |
| `ENCRYPT_METHOD` | Скрипт больше не изменяет алгоритм хеширования паролей автоматически |
| 4.4 — `pam_faillock` | Опциональная корпоративная мера: применяется только при `ENABLE_CORPORATE_PASSWORD_POLICY=1` и профиле `strict`/`paranoid` |
| 9.4 — `Banner /etc/issue.net` только на `strict+` | На `baseline` баннер не устанавливается. Осознанное отступление от Стандарта п. 9.4 |
| 10.4 — mount hardening `/tmp`, `/var/tmp`, `/dev/shm` только на `paranoid` | На `baseline`/`strict` не применяется: риск несовместимости с прикладным ПО. Осознанное отступление от Стандарта п. 10.4 |

---

## Границы применения и соответствия

`SecureLinux-NG` реализует **технические меры hardening уровня ОС**, которые можно автоматически применить, проверить и, где это возможно, откатить.

Проект **не заявляет автоматическое закрытие всех требований ФСТЭК целиком**, потому что часть требований относится:
- к организационным мерам;
- к процессам администрирования и эксплуатации;
- к внешней инфраструктуре и принятым в организации политикам;
- к прикладным системам, журналированию, хранению данных и другим подсистемам вне уровня базового hardening ОС.

Поэтому в проекте используется модель статусов:
- `done` — мера реализована и поддерживается текущей моделью apply/check/restore;
- `partial` — мера реализована частично, требует reboot, ручных действий, отдельного обоснования или не имеет полного безопасного restore;
- `not_applicable` — мера осознанно не автоматизируется в текущей реализации.

Таким образом, `SecureLinux-NG` следует рекомендациям ФСТЭК **в пределах автоматически реализуемых мер ОС hardening**, а полная оценка соответствия должна выполняться с учётом корпоративного регламента, архитектуры системы, состава сервисов и организационных процедур.

## Источники

- **ФСТЭК России, 25.12.2022** — [«Рекомендации по безопасной настройке ОС Linux»](https://fstec.ru/dokumenty/vse-dokumenty/spetsialnye-normativnye-dokumenty/metodicheskij-dokument-ot-25-dekabrya-2022-g) — основной нормативный источник
- **Чайка А.А. «Практическая безопасность Linux»** — БХВ-Петербург, 2026
- **Habr / BI.ZONE** — [практические материалы по ФСТЭК](https://habr.com/ru/companies/bizone/articles/950982/)
- **fortress_improved.sh** (captainzero93) — [Docker-aware логика, preflight](https://github.com/captainzero93/security_harden_linux)
- **JShielder** (JsiTech) — [SSH hardening](https://github.com/Jsitech/JShielder)
- **Hardening-Ubuntu-2024.sh** (AndyHS-506) — [kernel module blacklist, CIS](https://github.com/AndyHS-506/Ubuntu-Hardening)

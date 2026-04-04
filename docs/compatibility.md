# Совместимость — SecureLinux-NG

## Назначение

Документ описывает:
- какие меры могут ломать сервисы или конфликтовать со средой;
- какие preflight-проверки выполняются до применения;
- какие профили допустимы для разных типов хостов.

## Категории хостов

### Сервер общего назначения

Целевая среда. Все модули применяются без ограничений.
Рекомендуемый профиль: `strict` или `paranoid`.

### Хост с Docker

**Затронутые меры:**
- `kernel.unprivileged_bpf_disabled=1` — может конфликтовать с некоторыми сетевыми плагинами (Cilium, eBPF-based CNI).
- `kernel.yama.ptrace_scope=3` — ломает `docker exec` в режиме attach к процессам.
- `user.max_user_namespaces` — может изменяться через `USER_NAMESPACES_LIMIT` или выбор администратора; значение `0` может ломать rootless Docker и контейнерные сценарии, поэтому требует осознанного решения.
- GRUB-параметры `iommu=force` — могут влиять на производительность при pass-through.
- `kernel.modules_disabled=1` — ломает Docker: после установки `1` ни один модуль ядра (включая сетевые) не может быть загружен до перезагрузки.

**Поведение preflight:** при обнаружении Docker (`HAS_DOCKER=1`) добавляется `policy_gate` — запись в отчёт с предупреждением. Автоматического запрета мер нет: решение остаётся за администратором.

**Рекомендация:** профиль `baseline`. Применение `strict`/`paranoid` — только с ручной проверкой совместимости сетевых плагинов.

### Узел Kubernetes

**Затронутые меры:**
- `kernel.yama.ptrace_scope=3` — ломает `kubectl exec` и отладку через strace внутри подов.
- `kernel.unprivileged_bpf_disabled=1` — несовместим с Cilium, Hubble, Tetragon и другими eBPF-агентами.
- `kernel.kexec_load_disabled=1` — безопасно, но необратимо до перезагрузки.
- `fs.protected_fifos=2` / `fs.protected_regular=2` — могут конфликтовать с некоторыми CSI-драйверами.
- GRUB-параметры `mitigations=auto,nosmt` — снижают производительность на многоядерных узлах.

**Поведение preflight:** при обнаружении Kubernetes (`HAS_K8S=1`) добавляется `policy_gate` — запись в отчёт. Автоматического запрета мер нет: решение остаётся за администратором.

**Рекомендация:** профиль `baseline`. Модули `2.6.1` (ptrace) и `2.5.6` (unprivileged BPF) требуют ручного решения перед применением.

### Desktop / jump-host

**Затронутые меры:**
- `kernel.yama.ptrace_scope=3` — ломает отладчики (gdb, strace, lldb), профилировщики.
- `kernel.unprivileged_bpf_disabled=1` — ломает некоторые инструменты мониторинга (bpftrace, perf).
- `kernel.kptr_restrict=2` — затрудняет отладку ядра.
- `fs.suid_dumpable=0` — отключает core dump для SUID-процессов.
- GRUB `mitigations=auto,nosmt` — снижает производительность.

**Поведение preflight:** при обнаружении desktop (`IS_DESKTOP=1`) добавляется `policy_gate` — запись в отчёт. Автоматического запрета мер нет: решение остаётся за администратором.

**Рекомендация:** профиль `baseline`. Пункты `2.6.1`, `2.5.2`, `2.5.6` применять осознанно.

### Контейнер (не хост)

**Затронутые меры:**
- sysctl-модули: большинство параметров недоступны для записи внутри контейнера без `--privileged`.
- GRUB-модуль: `/etc/default/grub` не влияет на ядро хоста изнутри контейнера.
- PAM/shadow-модули: могут работать, но управление пользователями в контейнере нетипично.

**Поведение preflight:** при обнаружении контейнера (`IS_CONTAINER=1`) добавляется `policy_gate` — запись в отчёт. Автоматического запрета мер нет: запуск скрипта внутри контейнера не рекомендуется.

**Рекомендация:** запуск скрипта внутри контейнера не рекомендуется. Hardening применяется на хосте.

## Таблица совместимости мер по средам

| Пункт | Сервер | Docker-хост | K8s-узел | Desktop | Контейнер |
|---|---|---|---|---|---|
| 2.1.1 (пустые пароли) | ✓ | ✓ | ✓ | ✓ | ~ |
| 2.1.2 (SSH root) | ✓ | ✓ | ✓ | ✓ | ~ |
| 2.2.1 (su/wheel) | ✓ | ✓ | ✓ | ✓ | ~ |
| 2.2.2 (sudoers) | ✓ | ✓ | ✓ | ✓ | ~ |
| 2.3.x (права ФС) | ✓ | ✓ | ✓ | ✓ | ~ |
| 2.4.1 dmesg_restrict | ✓ | ✓ | ✓ | ✓ | ✗ |
| 2.4.2 kptr_restrict | ✓ | ✓ | ✓ | ~ | ✗ |
| 2.4.3–2.4.7 (GRUB) | ✓ | ✓ | ~ | ~ | ✗ |
| 2.5.4 kexec_disabled | ✓ | ✓ | ✓ | ✓ | ✗ |
| 2.5.6 unprivileged_bpf | ✓ | ~ | ✗ | ~ | ✗ |
| 2.6.1 ptrace_scope=3 | ✓ | ✗ | ✗ | ✗ | ✗ |
| 2.6.2–2.6.5 (protected_*) | ✓ | ✓ | ~ | ✓ | ✗ |
| 2.6.6 suid_dumpable | ✓ | ✓ | ✓ | ~ | ✗ |
| п.8.1-8.3 network sysctl | ✓ | ✓ | ✓ | ✓ | ✗ |
| п.7.6 coredump disable | ✓ | ✓ | ✓ | ~ | ✗ |
| п.10.5 rkhunter | ✓ | ~ | ~ | ~ | ✗ |
| п.8.4 tcp_syncookies / icmp_ignore_broadcasts / icmp_bogus | ✓ | ✓ | ✓ | ✓ | ✗ |
| п.8.3 tcp_syn_retries=3 | ✓ | ✓ | ✓ | ✓ | ✗ |
| п.10.6 usb_storage blacklist (дополнительная корпоративная мера) | ✓ | ~ | ~ | ~ | ✗ |
| п.15.1 kernel.modules_disabled=1 | ✓ | ✗ | ✗ | ✗ | ✗ |

Обозначения: ✓ совместимо, ~ требует проверки, ✗ несовместимо или неприменимо.

## Профили и среды

| Профиль | Рекомендуемая среда |
|---|---|
| `baseline` | любая среда, включая K8s и Docker |
| `strict` | сервер общего назначения, jump-host без отладчиков |
| `paranoid` | изолированный сервер без контейнерных рабочих нагрузок |

## Необратимые меры

Следующие меры необратимы до перезагрузки или требуют ручного вмешательства:
- `kernel.kexec_load_disabled=1` — необратимо до перезагрузки (sysctl write-once).
- GRUB-параметры — вступают в силу только после перезагрузки.
- Изменения `/etc/shadow` (блокировка пустых паролей) — обратимы через restore; хранится только список имён УЗ с пустым паролем, хэши не сохраняются.
- `kernel.modules_disabled=1` — временно не применяется автоматически; при реализации будет необратимо до перезагрузки (sysctl write-once).

## Гарантия backup при apply (16.2.8+)

Все backup-операции выполняются через `backup_file_checked()`. Если backup не удался — модуль пропускается с warning, а не продолжает работу с потерянным оригиналом. Это критично для PAM, SSH, sudoers, sysctl dropin-файлов.

## Правило обновления

При добавлении нового hardening-модуля обновить:
1. таблицу совместимости выше;
2. список необратимых мер (если применимо);
3. `docs/fstec-mapping.md`.

## Покрытие по профилям

Полное понимание того что применяется на каждом профиле:

| Мера | baseline | strict | paranoid |
|---|---|---|---|
| Все пункты 2.1–2.3 ФСТЭК | ✓ | ✓ | ✓ |
| 2.4.1/2/8 sysctl kernel | ✓ | ✓ | ✓ |
| 2.4.3–2.4.7 GRUB params | ✓ (reboot) | ✓ (reboot) | ✓ (reboot) |
| 2.5.1/3/4/5/7/8/9/10/11 sysctl | ✓ | ✓ | ✓ |
| 2.5.2 perf_event_paranoid=3 | ✓ | ✓ | ✓ |
| 2.5.6 unprivileged_bpf=1 | ✓ | ✓ | ✓ |
| 2.6.1 ptrace_scope=3 | ✓ | ✓ | ✓ |
| 2.6.2–2.6.6 protected_*/suid_dumpable | ✓ | ✓ | ✓ |
| auditd baseline rules | ✓ | ✓ | ✓ |
| auditd extended rules | ✗ | ✓ | ✓ |
| UFW firewall | ✓ | ✓ | ✓ |
| kernel module blacklist | ✓ | ✓ | ✓ |
| rsyslog, chrony, unattended-upgrades | ✓ | ✓ | ✓ |
| apport отключение | ✓ | ✓ | ✓ |
| SSH расширенный (Ciphers/MACs) | ✓ | ✓ строже | ✓ строже |
| PAM faillock | ✗ | ✓ | ✓ |
| Password policy | ✓ | ✓ строже | ✓ строже |
| AppArmor enforce | ✗ | ✓ | ✓ |
| AIDE integrity monitoring | ✗ | ✓ | ✓ |
| fail2ban SSH jail | ✗ | ✗ | ✓ |
| /tmp tmpfs nosuid/nodev/noexec | ✗ | ✗ | ✓ |
| mount hardening /dev/shm /var/tmp | ✗ | ✗ | ✓ |
| п.8.1-8.3 network sysctl | ✓ | ✓ | ✓ |
| п.7.6 coredump disable | ✓ | ✓ | ✓ |
| п.7.7 chmod 600 grub.cfg | ✓ | ✓ | ✓ |
| п.9.3 SSH LogLevel VERBOSE | ✓ | ✓ | ✓ |
| п.9.4 SSH Banner | ✗ | ✓ | ✓ |
| п.7.3 GRUB apparmor=1 security=apparmor | ✗ | ✓ | ✓ |
| п.8.3 tcp_timestamps=0 | ✗ | ✗ | ✓ |
| п.10.5 rkhunter | ✗ | ✗ | ✓ |
| п.4.3 pam_pwhistory | ✓ | ✓ | ✓ |
| п.17.1–17.2 account audit services/ports | ✓ | ✓ | ✓ |
| п.8.4 tcp_syncookies, icmp_ignore_broadcasts, icmp_bogus_errors | ✓ | ✓ | ✓ |
| п.8.3 tcp_syn_retries=3 | ✓ | ✓ | ✓ |
| п.10.6 usb_storage blacklist (дополнительная корпоративная мера) | ✗ | ✗ | ✓ |
| п.15.1 kernel.modules_disabled=1 | ✗ | ✗ | ✗ (временно не применяется) |

**В проектном реестре 60 позиций, из них 59 реализованы; позиция `15.1 kernel.modules_disabled=1` временно не применяется. Поэтому формулировку про «закрываются все 60» считать устаревшей.**

## Гарантии restore для sysctl dropin-файлов (16.2.8+)

Начиная с версии 16.2.8, `sysctl --system` вызывается безусловно после restore каждого sysctl dropin-файла, даже если dropin был удалён. Это гарантирует корректную перезагрузку runtime-значений ядра из оставшихся конфигов.

## Что НЕ восстанавливается через --restore

Администратор должен знать до применения:

| Мера | Восстанавливается? | Примечание |
|---|---|---|
| Managed файлы (sysctl dropins, SSH, PAM, sudoers) | ✓ | Из backup через manifest |
| Права файловой системы (2.3.x) | ✓ | Из metadata snapshot (mode/uid/gid) |
| GRUB params | ✓ | Восстанавливается файл; эффект только после reboot |
| UFW | частично | `ufw disable` если был включён скриптом |
| AppArmor | ✗ | Только `aa-complain /etc/apparmor.d/*` вручную |
| AIDE база данных | ✗ | Удалить `/var/lib/aide/aide.db` вручную |
| apport | ✗ | `systemctl enable --now apport` вручную |
| kernel.kexec_load_disabled=1 | ✗ | Необратимо до перезагрузки (sysctl write-once) |
| Установленные пакеты (chrony, auditd, ufw и др.) | ✗ | Пакеты не удаляются при restore |
| rkhunter | ✗ | `apt-get remove rkhunter` вручную |
| GRUB params в /proc/cmdline | ✗ | Только после reboot |
| kernel.modules_disabled=1 | ✗ | Необратимо до перезагрузки (write-once); dropin удаляется, значение остаётся |


## Примечание по парольной политике

- Мера 2.1 изменяет не только файловые конфигурации, но и параметры aging существующих локальных УЗ через `chage`; это нужно учитывать при повторных `--apply`, `--check`, `--restore` и тестах совместимости.

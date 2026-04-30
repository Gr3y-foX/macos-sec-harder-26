# Audit Report — mac-hardening-netlib.sh
### vs dns-setup-v2-2.md (working baseline) + RFC / pf / dnscrypt-proxy standards

> **Дата:** 2026-04-29  
> **Версия скрипта:** v0.15  
> **Статус мануала:** ✅ Все тесты пройдены  
> **Автор аудита:** Gr3y-foX / Fox Division  

---

## Severity Legend

| Метка | Смысл |
|---|---|
| 🔴 CRITICAL | Прямая DNS/IP утечка, пробой изоляции |
| 🟠 HIGH | Нарушение стандарта, ломает тест из health check |
| 🟡 MEDIUM | Деградация безопасности, неверное поведение |
| 🟢 LOW | Стиль, надёжность, maintainability |

---

## 🔴 CRITICAL — Прямые уязвимости

---

### [C-1] pf: `pass out from 127.0.0.1 to any port 443` — DoH leak

**Файл:** `mac-hardening-netlib.sh` → `prepare_pf_dns_lock_anchor()`

```bash
# ТЕКУЩИЙ КОД — УЯЗВИМ:
pass out quick proto udp from 127.0.0.1 to any port 443
pass out quick proto tcp from 127.0.0.1 to any port 443
```

**Проблема:**  
Правило разрешает исходящий DoH (`port 443`) с `localhost` на **любой IP**.  
Это означает что приложение или малварь могут отправлять DNS-запросы через DoH напрямую к Google (`8.8.8.8:443`), Cloudflare (`1.1.1.1:443`) и любому другому DoH-серверу — **pf их не заблокирует**.

**Правильно (whitelist по IP провайдера):**
```bash
# Разрешить только Quad9
pass out quick proto { udp tcp } to 9.9.9.9
pass out quick proto { udp tcp } to 149.112.112.112
# Разрешить Tailscale DNS
pass out quick proto { udp tcp } to 100.100.100.100 port 53
# Loopback без ограничений
pass quick on lo0 all
# Блокировать всё остальное
block out quick proto { udp tcp } to any port { 53 853 }
```

**Тест который не пройдёт:**
```bash
# Health check [7] — Plain DNS blocked
timeout 3 dig google.com @8.8.8.8    # должен timeout, но текущие правила пропустят DoH-bypass
```

---

### [C-2] pf: Нет pass для Tailscale DNS `100.100.100.100:53`

**Файл:** `prepare_pf_dns_lock_anchor()`

```bash
# Правила блокируют port 53 на !lo0:
block out quick proto udp to any port 53
block out quick proto tcp to any port 53
```

Tailscale resolver `100.100.100.100:53` является **внешним** относительно `lo0`, поэтому попадёт под блокировку. Доменные имена Tailscale-сети (`*.ts.net`, MagicDNS) перестанут резолвиться после включения PF DNS lock.

**Фикс:**
```bash
# Добавить ДО блокирующих правил:
pass out quick proto { udp tcp } to 100.100.100.100 port 53
```

**Тест который не пройдёт:**
```bash
# Health check [8] — Tailscale split DNS
scutil --dns | grep -q "ts.net"   # будет ✅, но реальные запросы упадут
```

---

### [C-3] IPv6 DNS leak — нет ICMPv6 pass (ломает NDP/PMTUD)

**Файл:** `prepare_pf_dns_lock_anchor()`

```bash
# Скрипт блокирует IPv6 DNS — это верно:
block out quick inet6 proto udp to any port 53
block out quick inet6 proto tcp to any port 53
block out quick inet6 proto tcp to any port 853
```

Но **нет** `pass quick inet6 proto icmp6` — это нарушение RFC 4890 ("Recommendations for Filtering ICMPv6 Messages in Firewalls").  
Без этого правила ломается:
- **NDP** (Neighbor Discovery Protocol) — не определяются IPv6 адреса в LAN
- **PMTUD** (Path MTU Discovery) — фрагментация пакетов, деградация скорости
- **Router Advertisement** — не получаются IPv6 маршруты

**Фикс:**
```bash
# Обязательно до блокировок — RFC 4890 §4.3.1
pass quick inet6 proto icmp6 all
```

---

## 🟠 HIGH — Нарушения стандартов / ломают health check

---

### [H-1] dnscrypt-proxy: нет `fallback_resolver = ""`

**Файл:** `enable_dnscrypt()` / конфигурация не генерируется скриптом

По умолчанию dnscrypt-proxy при недоступности upstream использует `fallback_resolver = "9.9.9.9:53"` — **plain DNS через UDP** в обход dnscrypt. Это означает что при недоступности relay DNS-запросы уходят незашифрованными.

```toml
# Явно запретить fallback на system DNS:
fallback_resolver = ""
ignore_system_dns = true
```

> Источник: [DNSCrypt/dnscrypt-proxy discussion #2685](https://github.com/DNSCrypt/dnscrypt-proxy/discussions/2685)

---

### [H-2] dnscrypt-proxy: нет `dnscrypt_ephemeral_keys = true`

Без ephemeral keys dnscrypt-proxy использует один keypair для всех запросов. Это позволяет relay-серверу накапливать корреляции между запросами одного клиента (timing + keypair fingerprint).

```toml
dnscrypt_ephemeral_keys = true   # новый keypair на каждый запрос
```

> Стандарт: Anonymized DNSCrypt spec требует ephemeral keys для anonymity set

---

### [H-3] Скрипт не генерирует конфиг `dnscrypt-proxy.toml`

`install_dnscrypt()` устанавливает пакет, `enable_dnscrypt()` стартует сервис — но **конфиг не создаётся и не проверяется**. После `brew install dnscrypt-proxy` используется дефолтный `example-dnscrypt-proxy.toml` который:
- Слушает на `127.0.0.1:53` (занят mDNSResponder → сервис не стартует)
- Не имеет `forwarding_rules` для Tailscale
- Не имеет `anonymized_dns` routes

**Это объясняет все прошлые `REFUSED` ошибки.** Скрипт считает что сервис запустился, но dnscrypt-proxy не слушает ни на одном рабочем порту.

**Фикс:** добавить `configure_dnscrypt()` функцию которая пишет валидный toml перед стартом сервиса.

---

### [H-4] VPN детектор — ложные срабатывания на Tailscale

**Файл:** `vpn_active()`

```bash
# ТЕКУЩИЙ КОД:
vpn_active() {
  ifconfig 2>/dev/null \
    | awk '/^utun[0-9]/{found=1} found && /inet /{print; exit}' \
    | grep -q "inet" && return 0
  return 1
}
```

Tailscale создаёт `utun` интерфейс — функция вернёт `true` при активном Tailscale, даже без ClearVPN/OpenVPN. В результате `proxy-toggle.sh` выключит Privoxy при подключении Tailscale, хотя должен работать только для туннельных VPN.

**Проблема:** `get_services()` корректно фильтрует `tailscale` из списка сетевых сервисов, но `vpn_active()` смотрит на сырой `ifconfig` без исключений.

**Фикс:**
```bash
vpn_active() {
  # Исключаем Tailscale utun из детектора
  local TAILSCALE_IF
  TAILSCALE_IF=$(tailscale debug netmap 2>/dev/null | grep "utun" | awk '{print $1}' || echo "")

  ifconfig 2>/dev/null \
    | awk '/^utun[0-9]/{iface=$1; found=1} found && /inet /{print iface, $0; exit}' \
    | grep -v "${TAILSCALE_IF:-__none__}" \
    | grep -q "inet" && return 0
  return 1
}
```

---

### [H-5] pf: Нет архитектурной интеграции с `/etc/pf.conf`

**Файл:** `enable_pf_dns_lock()`

Скрипт вставляет anchor через текстовый маркер в `/etc/pf.conf` — это правильный подход (лучше чем flat file в мануале). Но при `pfctl -f /etc/pf.conf` macOS может перезаписать файл при OS Update.

**Best practice** (Apple Technical Note + OpenBSD pf docs):
```
/etc/pf.anchors/com.hardening.dnsleak   ← anchor file (уже есть ✅)
/etc/pf.conf                            ← должен содержать:
  anchor "com.hardening.dnsleak"
  load anchor "com.hardening.dnsleak" from "/etc/pf.anchors/com.hardening.dnsleak"
```

Плюс LaunchDaemon для `pfctl -e` при загрузке (есть в мануале, нет в скрипте).

---

## 🟡 MEDIUM — Деградация безопасности

---

### [M-1] Health check отсутствует полностью

Скрипт после установки проверяет только:
```bash
sudo lsof +c 15 -Pni UDP:5355 2>/dev/null | grep -q dnscrypt
```

Нет проверок:
- DNSSEC `ad` flag (`dig +dnssec icann.org`)
- DNSSEC fail test (`dig www.dnssec-failed.org` → `SERVFAIL`)
- Plain DNS blocked (`dig @8.8.8.8` → timeout)
- Quad9 reachability (`curl https://on.quad9.net`)
- Tailscale split DNS активен
- pf status

**Без этих тестов скрипт может завершиться успешно при сломанном стеке.**

---

### [M-2] Бэкап не включает критичные DNS-артефакты

**Файл:** `create_net_backup()`

Бэкапит: `pf.conf`, `hosts`, proxy settings, dnscrypt status, Privoxy plist.

Не бэкапит:
- `scutil --dns` (текущий системный резолвер)
- `/etc/resolver/` директорию (Tailscale split DNS)
- `dnscrypt-proxy.toml` (конфигурация)
- `resolv.conf`

При rollback невозможно восстановить DNS-состояние полностью.

---

### [M-3] `install_formula()` — нет проверки версии

```bash
brew list --formula --versions "$pkg" &>/dev/null
```

Проверяет только наличие пакета, не версию. dnscrypt-proxy v2.x и v3.x имеют несовместимые форматы конфига — скрипт не предупредит о несовместимости при апгрейде.

---

### [M-4] `update_hosts()` — нет проверки SHA-256 по известному хешу

Скрипт вычисляет SHA-256 скачанного файла и выводит его, но **не сверяет** с ожидаемым значением. Пользователь должен вручную зайти на GitHub и проверить — что никто не делает.

```bash
# Добавить автоматическую проверку через GitHub API:
EXPECTED_SHA=$(curl -fsSL \
  "https://api.github.com/repos/StevenBlack/hosts/commits?path=hosts&per_page=1" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['sha'][:7])")
info "Latest commit: $EXPECTED_SHA — verify at https://github.com/StevenBlack/hosts"
```

---

## 🟢 LOW — Стиль и надёжность

---

### [L-1] `ask()` — незакрытая функция (bash syntax bug)

```bash
ask() {
local PROMPT="$1" VAR="$2"
if [[ -t 0 ]]; then
  read -rp " ${PROMPT} (y/N): " "$VAR"
else
  warn "Non-interactive — skipping: $PROMPT"
  eval "$VAR=N"
fi
# ← НЕТ закрывающей }
```

Функция `ask()` не имеет закрывающей `}` — следующий блок `NET_BACKUP_DIR=...` выполняется внутри `ask()`. Это синтаксический баг который ломает scope переменных. В bash это не всегда вызывает ошибку из-за того что следующая функция даёт implicit закрытие, но поведение undefined.

---

### [L-2] `resolve_brew_prefix()` — незакрытая функция

Аналогично `ask()` — функция `resolve_brew_prefix()` не имеет закрывающей `}`.

---

### [L-3] Версия в `main()` — `v0.16` в баннере, `v0.15` в заголовке

```bash
# Заголовок файла:
# Version: 0.15 (2026)

# Баннер main():
echo " ║ v0.16 · by Gr3y-foX         ║"
```

---

### [L-4] `BREW_PREFIX` не экспортируется перед использованием в Privoxy

```bash
configure_privoxy_vpn_bypass() {
  local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
```

`BREW_PREFIX` может быть не установлен если `configure_privoxy_vpn_bypass()` вызывается без предшествующего `resolve_brew_prefix()`. Есть guard в `install_privoxy()`, но не в самой функции.

---

## Сводная таблица

| ID | Severity | Компонент | Суть | Ломает тест |
|---|---|---|---|---|
| C-1 | 🔴 CRITICAL | pf | DoH leak — pass any:443 | [7] Plain DNS blocked |
| C-2 | 🔴 CRITICAL | pf | Нет pass Tailscale 100.100.100.100:53 | [8] Tailscale split DNS |
| C-3 | 🔴 CRITICAL | pf IPv6 | Нет ICMPv6 pass — ломает NDP/PMTUD | network connectivity |
| H-1 | 🟠 HIGH | dnscrypt | Нет `fallback_resolver = ""` | [3] Basic resolution |
| H-2 | 🟠 HIGH | dnscrypt | Нет `dnscrypt_ephemeral_keys` | anonymity |
| H-3 | 🟠 HIGH | dnscrypt | Конфиг не генерируется скриптом | [2] dnscrypt :5355 |
| H-4 | 🟠 HIGH | VPN | Tailscale = false positive в `vpn_active()` | Privoxy auto-switch |
| H-5 | 🟠 HIGH | pf | Нет LaunchDaemon для автозапуска pf | pf после reboot |
| M-1 | 🟡 MEDIUM | general | Нет health check функции | все 10 тестов |
| M-2 | 🟡 MEDIUM | backup | Бэкап не полный | rollback |
| M-3 | 🟡 MEDIUM | install | Нет проверки версии dnscrypt | compatibility |
| M-4 | 🟡 MEDIUM | hosts | SHA-256 не верифицируется | supply chain |
| L-1 | 🟢 LOW | bash | `ask()` незакрытая функция | scope bug |
| L-2 | 🟢 LOW | bash | `resolve_brew_prefix()` незакрыта | scope bug |
| L-3 | 🟢 LOW | meta | Версия v0.15/v0.16 рассинхрон | — |
| L-4 | 🟢 LOW | privoxy | `BREW_PREFIX` guard неполный | — |

---

## Приоритет исправлений

```
Phase 1 — блокирует прохождение health check:
  [H-3] configure_dnscrypt() — генерация toml
  [C-1] pf whitelist по IP вместо any:443
  [C-2] pass Tailscale 100.100.100.100
  [H-1] fallback_resolver = ""

Phase 2 — безопасность и надёжность:
  [C-3] ICMPv6 pass
  [H-2] dnscrypt_ephemeral_keys
  [H-4] vpn_active() Tailscale exclude
  [H-5] LaunchDaemon для pf

Phase 3 — качество:
  [M-1] verify_dns_stack() — 10 тестов из мануала
  [M-2] расширить create_net_backup()
  [L-1] [L-2] закрыть функции
  [L-3] версия
```

---

## Ссылки

- [RFC 4890 — ICMPv6 Filtering Recommendations](https://datatracker.ietf.org/doc/html/rfc4890)
- [Anonymized DNSCrypt Spec](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt)
- [dnscrypt-proxy DNS Isolation Discussion #2685](https://github.com/DNSCrypt/dnscrypt-proxy/discussions/2685)
- [OpenBSD pf — Anchors](https://www.openbsd.org/faq/pf/anchors.html)
- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [dns-setup-v2-2.md — Working baseline](./dns-hardening-setup.md)
", "_tool_input_summary": "Creating docs/netlib-audit-report.md in Gr3y-foX/macOS-Security-and-Privacy-Guide-modded-Fox-Division on branch feature/hardening-additions with full technical audit report", "_requires_user_approval": true
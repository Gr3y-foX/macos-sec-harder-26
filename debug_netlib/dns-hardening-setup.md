# DNS Hardening Manual — macOS (Apple Silicon)

> **Статус:** Проверено и работает на macOS (Apple Silicon)  
> **Дата:** 2026-04-29  
> **Автор:** Gr3y-foX / Fox Division  
> **Контекст:** Часть [macOS Security & Privacy Guide](../README.md#dns)

---

## Архитектура итогового стека

```
[Приложения / Browser / System]
           ↓
[mDNSResponder — системный резолвер macOS]
           ↓
[Quad9 DoH Profile — 9.9.9.11]       ← зашифрованный DNS на уровне ОС
           +
[dnscrypt-proxy :5355]                ← DNSCrypt + DNSSEC + anonymized relay
           +
[/etc/resolver/]                      ← нативный macOS split DNS для Tailscale
           +
[pf firewall]                         ← блокирует любой plain DNS наружу
           +
[LuLu]                                ← outgoing firewall на уровне приложений
```

> **Почему нет dnsmasq:**  
> На macOS `mDNSResponder` принудительно занимает порт `53` на `*:53` и не освобождает его даже при `bind-interfaces`. dnsmasq не может получить этот порт без отключения SIP. Нативные механизмы macOS (`/etc/resolver/`, DNS Profile) покрывают функционал dnsmasq полностью.

---

## Предварительные требования

- macOS на Apple Silicon (M1–M4)
- [Homebrew](https://brew.sh) установлен
- Tailscale установлен (если используется)
- ClearVPN установлен (если используется)
- LuLu установлен (рекомендуется)

---

## Этап 0 — Бэкап

Выполнить **до любых изменений**.

```bash
sudo mkdir -p ~/dns-hardening-backup/$(date +%Y-%m-%d)
export BACKUP_DIR=~/dns-hardening-backup/$(date +%Y-%m-%d)

# Текущие DNS настройки
scutil --dns > $BACKUP_DIR/system-dns-before.txt
networksetup -getdnsservers Wi-Fi > $BACKUP_DIR/wifi-dns-before.txt

# Системные файлы
sudo cp /etc/hosts $BACKUP_DIR/hosts.bak
sudo pfctl -sr > $BACKUP_DIR/pf-rules-before.txt 2>/dev/null
sudo cp /etc/pf.conf $BACKUP_DIR/pf.conf.bak 2>/dev/null
sudo cp /etc/resolv.conf $BACKUP_DIR/resolv.conf.bak 2>/dev/null

# Сервисы
brew services list > $BACKUP_DIR/brew-services-before.txt
tailscale dns status > $BACKUP_DIR/tailscale-dns-before.txt 2>/dev/null

echo "✅ Backup saved to: $BACKUP_DIR"
```

### Rollback скрипт

```bash
cat > ~/dns-hardening-backup/rollback.sh << 'ROLLBACK'
#!/bin/bash
BACKUP_DIR="$(dirname "$0")"
echo "🔄 Starting rollback from: $BACKUP_DIR"

# pf
sudo pfctl -d 2>/dev/null
[ -f "$BACKUP_DIR/pf.conf.bak" ] && sudo cp $BACKUP_DIR/pf.conf.bak /etc/pf.conf && sudo pfctl -e -f /etc/pf.conf
sudo rm -f /etc/pf.dns.rules
sudo launchctl unload /Library/LaunchDaemons/com.foxdivision.pf.dns.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.foxdivision.pf.dns.plist

# Системный DNS
ORIG_DNS=$(head -1 $BACKUP_DIR/wifi-dns-before.txt)
if [[ "$ORIG_DNS" == "There aren't any DNS Servers"* ]]; then
    sudo networksetup -setdnsservers Wi-Fi "Empty"
else
    sudo networksetup -setdnsservers Wi-Fi $ORIG_DNS
fi

# dnscrypt-proxy
sudo brew services stop dnscrypt-proxy 2>/dev/null
[ -f "$BACKUP_DIR/dnscrypt-proxy.toml.bak" ] && cp $BACKUP_DIR/dnscrypt-proxy.toml.bak /opt/homebrew/etc/dnscrypt-proxy.toml

# Tailscale DNS
tailscale set --accept-dns=true 2>/dev/null

# /etc/resolver
sudo rm -f /etc/resolver/ts.net /etc/resolver/tailscale.com

# /etc/hosts
sudo cp $BACKUP_DIR/hosts.bak /etc/hosts

# Сброс кеша
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder

echo "✅ ROLLBACK COMPLETE"
echo "Verify: scutil --dns && curl -I https://google.com"
ROLLBACK

chmod +x ~/dns-hardening-backup/rollback.sh
```

---

## Этап 1 — Quad9 DNS Profile (DoH)

Установить официальный Quad9 профиль с DNSSEC и фильтрацией малвари.

1. Скачать профиль: [docs.quad9.net](https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/#download-profile)
2. **Использовать сервер `9.9.9.11`** (совместим с iCloud Private Relay)
3. Открыть скачанный `.mobileconfig` → System Settings → Privacy & Security → Profiles → Install
4. Убедиться что профиль активен:

```bash
scutil --dns | grep -E "nameserver|Do[HT]|9\.9\.9"
```

> **Важно:** iCloud Private Relay конфликтует с профилями `9.9.9.9`. Использовать только `9.9.9.11`.

---

## Этап 2 — dnscrypt-proxy

### Установка

```bash
brew install dnscrypt-proxy
```

### Конфигурация

```bash
nano /opt/homebrew/etc/dnscrypt-proxy.toml
```

```toml
# Слушать на нестандартном порту (53 занят mDNSResponder)
listen_addresses = ['127.0.0.1:5355', '[::1]:5355']
max_clients = 250

# Использовать Quad9 с DNSSEC + threat filtering
server_names = ['quad9-doh-ip4-port443-filter-ecs-pri']

# Фильтры серверов
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true

require_dnssec = true
require_nolog = true
require_nofilter = false   # false = допускаем серверы с фильтрацией (Quad9)

# Сеть
force_tcp = false
timeout = 5000
keepalive = 30

# Bootstrap — только для получения списка резолверов при старте
# НЕ используется для пользовательских запросов
bootstrap_resolvers = ['9.9.9.11:53', '149.112.112.112:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'

# Фильтры запросов
block_ipv6 = false
block_unqualified = true   # блокировать запросы без домена (утечки)
block_undelegated = true   # блокировать несуществующие TLD

# Кеш
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# Логирование
log_files_max_size = 10
log_files_max_age = 7
log_files_max_backups = 1

# Tailscale split DNS forwarding
forwarding_rules = '/opt/homebrew/etc/forwarding-rules.txt'

# Anonymized DNS — relay и server от РАЗНЫХ провайдеров
[anonymized_dns]
routes = [
    { server_name='quad9-doh-ip4-port443-filter-ecs-pri', via=['anon-cs-de', 'anon-cs-nl'] }
]
skip_incompatible = false

# Query log для аудита
[query_log]
# file = '/var/log/dnscrypt-proxy-query.log'
format = 'tsv'

# NX log — подозрительные NXDOMAIN (малварь, broken apps)
[nx_log]
# file = '/var/log/dnscrypt-proxy-nx.log'
format = 'tsv'

# Официальные источники резолверов с minisign верификацией
[sources.public-resolvers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
]
cache_file = 'public-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73

[sources.relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/relays.md'
]
cache_file = 'relays.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73

# Workaround для серверов с известными багами (официальный список)
[broken_implementations]
fragments_blocked = [
  'cisco', 'cisco-ipv6', 'cisco-familyshield',
  'cisco-familyshield-ipv6', 'cisco-sandbox',
  'cleanbrowsing-adult', 'cleanbrowsing-adult-ipv6',
  'cleanbrowsing-family', 'cleanbrowsing-family-ipv6',
  'cleanbrowsing-security', 'cleanbrowsing-security-ipv6'
]
```

### Forwarding rules для Tailscale

```bash
cat > /opt/homebrew/etc/forwarding-rules.txt << 'EOF'
ts.net          100.100.100.100
tailscale.com   100.100.100.100
EOF
```

### Запуск

```bash
sudo brew services start dnscrypt-proxy

# Проверка
sudo lsof -Pni UDP:5355 | grep dnscrypt
dig google.com @127.0.0.1 -p 5355
```

---

## Этап 3 — Tailscale split DNS (нативный macOS)

`mDNSResponder` поддерживает `/etc/resolver/` — по одному файлу на домен.

```bash
sudo mkdir -p /etc/resolver

sudo tee /etc/resolver/ts.net << 'EOF'
nameserver 100.100.100.100
EOF

sudo tee /etc/resolver/tailscale.com << 'EOF'
nameserver 100.100.100.100
EOF

# Отключить Tailscale MagicDNS override (иначе перезапишет системный DNS)
tailscale set --accept-dns=false

# Проверить
scutil --dns | grep -A3 "ts.net"
```

---

## Этап 4 — /etc/hosts (StevenBlack blocklist)

```bash
# Бэкап текущего hosts
sudo cp /etc/hosts /etc/hosts.bak

# Добавить StevenBlack unified hosts (~100k доменов)
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts

# Сброс кеша
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder

# Проверка
grep "doubleclick.net" /etc/hosts | head -3
```

---

## Этап 5 — pf firewall (блокировка plain DNS)

```bash
sudo tee /etc/pf.dns.rules << 'EOF'
# Разрешить localhost DNS (dnscrypt-proxy)
pass quick on lo0 proto { udp tcp } from any to 127.0.0.1 port 53
pass quick on lo0 proto { udp tcp } from any to ::1 port 53
pass quick on lo0 proto { udp tcp } from any to 127.0.0.1 port 5355

# Разрешить Tailscale resolver
pass proto { udp tcp } from any to 100.100.100.100 port 53

# Разрешить dnscrypt-proxy исходящий DoH (Quad9)
pass out proto tcp from any to 9.9.9.9 port { 443 5443 }
pass out proto tcp from any to 149.112.112.112 port { 443 5443 }
pass out proto udp from any to 9.9.9.9 port { 443 5443 }

# Разрешить dnscrypt relay трафик
pass out proto { udp tcp } from any to any port 5443

# БЛОКИРОВАТЬ любой plain DNS наружу
block drop quick on !lo0 proto { udp tcp } from any to any port 53
block drop quick proto { udp tcp } from any to any port 853
EOF

sudo pfctl -e -f /etc/pf.dns.rules

# Проверка правил
sudo pfctl -sr | grep "port = 53"
```

### Автозапуск pf при загрузке

```bash
sudo tee /Library/LaunchDaemons/com.foxdivision.pf.dns.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.foxdivision.pf.dns</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/pfctl</string>
        <string>-e</string>
        <string>-f</string>
        <string>/etc/pf.dns.rules</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.foxdivision.pf.dns.plist
```

---

## Этап 6 — Полная верификация стека

```bash
echo "=== DNS Stack Health Check ==="

echo -n "[1] Quad9 Profile active:    "
scutil --dns | grep "9\.9\.9" | head -1 || echo "❌ NOT FOUND"

echo -n "[2] dnscrypt-proxy :5355:    "
sudo lsof -Pni UDP:5355 | grep dnscrypt | head -1 || echo "❌ NOT RUNNING"

echo -n "[3] Basic resolution:        "
dig +short google.com @127.0.0.1 -p 5355 | head -1 || echo "❌ FAILED"

echo -n "[4] DNSSEC (ad flag):        "
dig +dnssec icann.org @127.0.0.1 -p 5355 2>/dev/null | grep -o "flags:.*" | grep "ad" && echo "✅" || echo "❌ NO AD FLAG"

echo -n "[5] DNSSEC fail test:        "
dig www.dnssec-failed.org @127.0.0.1 -p 5355 2>/dev/null | grep "SERVFAIL" && echo "✅" || echo "❌"

echo -n "[6] Quad9 reachability:      "
curl -s --max-time 5 https://on.quad9.net && echo "" || echo "❌ FAILED"

echo -n "[7] Plain DNS blocked:       "
timeout 3 dig google.com @8.8.8.8 2>/dev/null | grep "NOERROR" && echo "❌ NOT BLOCKED" || echo "✅ BLOCKED"

echo -n "[8] Tailscale split DNS:     "
scutil --dns | grep -q "ts.net" && echo "✅" || echo "❌ NOT CONFIGURED"

echo -n "[9] pf status:               "
sudo pfctl -s info 2>/dev/null | grep "Status" || echo "❌ pf disabled"

echo -n "[10] StevenBlack hosts:      "
grep -c "0.0.0.0" /etc/hosts | xargs -I{} echo "{} entries ✅"

echo "=============================="
```

### Ожидаемые результаты

| Тест | Ожидаемый результат |
|---|---|
| Quad9 Profile | `9.9.9.11` в scutil --dns |
| dnscrypt-proxy | слушает `127.0.0.1:5355` |
| Basic resolution | возвращает IP |
| DNSSEC ad flag | `flags: qr rd ra ad` |
| DNSSEC fail | `SERVFAIL` |
| Quad9 reachability | `Yes` |
| Plain DNS `@8.8.8.8` | timeout / connection refused |
| Tailscale split DNS | `ts.net` в resolver list |
| pf | `Status: Enabled` |
| StevenBlack hosts | 100k+ записей |

---

## Совместимость с VPN

### Tailscale
- `tailscale set --accept-dns=false` — обязательно, иначе перезапишет системный DNS
- MagicDNS покрывается через `/etc/resolver/ts.net`
- Форвардинг через `forwarding-rules.txt` в dnscrypt-proxy

### ClearVPN
- При подключении ClearVPN пушит свои DNS — dnscrypt-proxy на `:5355` **не затрагивается**
- Quad9 профиль работает поверх ClearVPN туннеля
- При необходимости проверить: `scutil --dns` до и после подключения ClearVPN

---

## Откат

```bash
sudo bash ~/dns-hardening-backup/rollback.sh
```

---

## Известные ограничения macOS

| Ограничение | Причина | Обходной путь |
|---|---|---|
| dnsmasq не может занять порт 53 | `mDNSResponder` держит `*:53` принудительно | Использовать `/etc/resolver/` + Quad9 Profile |
| `bind-interfaces` всегда включён | macOS OS limitation (в логах dnsmasq) | Не использовать dnsmasq как резолвер |
| iCloud Private Relay конфликт | Конфликт с некоторыми DNS профилями | Использовать `9.9.9.11` вместо `9.9.9.9` |

---

## Источники и документация

- [DNSCrypt/dnscrypt-proxy — официальный конфиг](https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/example-dnscrypt-proxy.toml)
- [Quad9 macOS Setup Guide](https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/)
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
- [Tailscale DNS documentation](https://tailscale.com/kb/1054/dns)
- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)

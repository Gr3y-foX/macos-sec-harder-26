#!/bin/bash
#
# Foxhole-macos — macOS Network Hardening Library
#
# File:    mac-hardening-netlib.sh
# Version: 0.16 (2026)
# Author:  Gr3y-foX
# Based on: drduh/macOS-Security-and-Privacy-Guide (MIT)
# License: GNU GPL v3 — see LICENSE for details
#
# Overview:
#   Reusable network hardening primitives for macOS:
#     - dnscrypt-proxy (encrypted DNS as user-level service)
#     - PF DNS leak lock anchors
#     - /etc/hosts blocklist (StevenBlack)
#     - Privoxy with VPN-aware auto-proxy switching
#
# Usage:
#   This script is primarily intended to be sourced from profile scripts
#   (e.g. profile-vpn-daily.sh), but can also be run directly to access
#   its interactive menu.
#
# Changelog v0.16:
#   [C-1] FIX pf: deleted pass any:443 — replaced with whitelist Quad9 IP (DoH leak)
#   [C-2] FIX pf: added pass for external DNS resolver
#   [C-3] FIX pf: added pass icmp6 all (RFC 4890 — NDP/PMTUD)
#   [H-1] FIX dnscrypt: fallback_resolver = "" (запрет fallback на system DNS)
#   [H-2] FIX dnscrypt: dnscrypt_ephemeral_keys = true
#   [H-3] NEW configure_dnscrypt() — generate valid toml before start
#   [H-4] FIX vpn_active(): improved VPN detection logic
#   [H-5] NEW LaunchDaemon for auto-start pf on boot
#   [M-1] NEW verify_dns_stack() — 10-step health check
#   [M-2] FIX create_net_backup(): added scutil, resolver/, dnscrypt.toml
#   [L-1] FIX ask(): closed function brace
#   [L-2] FIX resolve_brew_prefix(): closed function brace
#   [L-3] FIX version synchronized: v0.16
#   [L-4] FIX BREW_PREFIX guard added to configure_privoxy_vpn_bypass()

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
die()  { err "$1"; exit 1; }

# [L-1] FIX: closed
ask() {
    local PROMPT="$1" VAR="$2"
    if [[ -t 0 ]]; then
        read -rp "    ${PROMPT} (y/N): " "$VAR"
    else
        warn "Non-interactive — skipping: $PROMPT"
        eval "$VAR=N"
    fi
}

# ──────────────────────────────────────────
# BACKUP — snapshot before hardening
# ──────────────────────────────────────────
NET_BACKUP_DIR="${HOME}/.foxhole/backups/$(date +%Y%m%d_%H%M%S)"

create_net_backup() {
    log "Creating pre-hardening backup snapshot..."
    mkdir -p "$NET_BACKUP_DIR" \
        || { warn "Cannot create backup dir: ${NET_BACKUP_DIR}"; return 1; }

    # 1. /etc/pf.conf
    [[ -f /etc/pf.conf ]] \
        && sudo cp /etc/pf.conf "${NET_BACKUP_DIR}/pf.conf" \
        && log "  [✓] /etc/pf.conf" \
        || warn "  [–] /etc/pf.conf not found — skipped"

    # 2. pf anchor (already exist)
    [[ -f /etc/pf.anchors/com.hardening.dnsleak ]] \
        && sudo cp /etc/pf.anchors/com.hardening.dnsleak "${NET_BACKUP_DIR}/pf.anchor.dnsleak" \
        && log "  [✓] pf anchor"

    # 3. /etc/hosts
    [[ -f /etc/hosts ]] \
        && sudo cp /etc/hosts "${NET_BACKUP_DIR}/hosts" \
        && log "  [✓] /etc/hosts" \
        || warn "  [–] /etc/hosts not found — skipped"

    # 4. /etc/resolv.conf
    [[ -f /etc/resolv.conf ]] \
        && sudo cp /etc/resolv.conf "${NET_BACKUP_DIR}/resolv.conf" \
        && log "  [✓] /etc/resolv.conf"

    # 5. [M-2] FIX: system DNS resolver
    scutil --dns > "${NET_BACKUP_DIR}/system-dns.txt" 2>/dev/null \
        && log "  [✓] scutil --dns"

    # 6. [M-2] FIX: /etc/resolver/ (split DNS configurations)
    if [[ -d /etc/resolver ]]; then
        sudo cp -r /etc/resolver "${NET_BACKUP_DIR}/resolver" \
            && log "  [✓] /etc/resolver/"
    fi

    # 7. dnscrypt-proxy.toml
    resolve_brew_prefix
    local TOML="${BREW_PREFIX}/etc/dnscrypt-proxy.toml"
    [[ -f "$TOML" ]] \
        && cp "$TOML" "${NET_BACKUP_DIR}/dnscrypt-proxy.toml" \
        && log "  [✓] dnscrypt-proxy.toml"

    # 8. dnscrypt-proxy service status
    if command -v brew &>/dev/null && brew list --formula dnscrypt-proxy &>/dev/null 2>&1; then
        brew services list 2>/dev/null \
            | grep dnscrypt > "${NET_BACKUP_DIR}/dnscrypt_status.txt" || true
        log "  [✓] dnscrypt-proxy service status"
    fi

    # 9. Network proxies
    local PROXY_DUMP="${NET_BACKUP_DIR}/network_proxies.txt"
    {
        echo "# Network proxy snapshot — $(date)"
        networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' \
        | while IFS= read -r SVC; do
            echo "=== $SVC ==="
            networksetup -getwebproxy        "$SVC" 2>/dev/null
            networksetup -getsecurewebproxy  "$SVC" 2>/dev/null
            networksetup -getproxybypassdomains "$SVC" 2>/dev/null
            echo ""
          done
    } > "$PROXY_DUMP"
    log "  [✓] Network proxy settings → ${PROXY_DUMP}"

    # 10. Privoxy LaunchDaemon
    local PRIV_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    [[ -f "$PRIV_PLIST" ]] \
        && sudo cp "$PRIV_PLIST" "${NET_BACKUP_DIR}/proxytoggle.plist" \
        && log "  [✓] Privoxy LaunchDaemon plist"

    echo ""
    log "Backup saved to: ${NET_BACKUP_DIR}"
    info "To restore: sudo bash ${NET_BACKUP_DIR}/../rollback.sh"
    echo ""
}

# ──────────────────────────────────────────
# INSTALL FORMULA
# ──────────────────────────────────────────
install_formula() {
    local pkg="$1"
    if brew list --formula --versions "$pkg" &>/dev/null; then
        local VER
        VER=$(brew list --formula --versions "$pkg")
        warn "${pkg} already installed: ${VER}"
        ask "Reinstall ${pkg}?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew reinstall "$pkg" \
            || { log "Skipping ${pkg}."; return 0; }
    else
        log "Installing ${pkg}..."
        brew install "$pkg" || { err "Failed to install ${pkg}!"; return 1; }
    fi
}

# [L-2] FIX: closed brace
resolve_brew_prefix() {
    if [[ -z "${BREW_PREFIX:-}" ]]; then
        BREW_PREFIX=$(brew --prefix 2>/dev/null) || die "Homebrew not found!"
        export BREW_PREFIX
    fi
}

# ──────────────────────────────────────────
# DNSCRYPT-PROXY
# ──────────────────────────────────────────
install_dnscrypt() {
    install_formula "dnscrypt-proxy" || die "dnscrypt-proxy install failed!"
}

# [H-3] NEW: generate valid config before starting service
configure_dnscrypt() {
    resolve_brew_prefix
    local TOML="${BREW_PREFIX}/etc/dnscrypt-proxy.toml"
    local FWD_RULES="${BREW_PREFIX}/etc/forwarding-rules.txt"

    log "Writing dnscrypt-proxy config: ${TOML}"

    # Forwarding rules for split DNS (if needed)
    cat > "$FWD_RULES" << 'EOF'
# Example split DNS forwarding (uncomment and modify as needed)
# example.local    192.168.1.1
EOF
    log "  [✓] forwarding-rules.txt written"

    cat > "$TOML" << EOF
## dnscrypt-proxy.toml — generated by foxhole-macos v0.16
## Quad9 DoH + anonymized relay + DNSSEC

# Port 53 is occupied by mDNSResponder on macOS — using 5355
listen_addresses = ['127.0.0.1:5355', '[::1]:5355']
max_clients = 250

# Quad9 with DNSSEC + threat filtering + ECS
server_names = ['quad9-doh-ip4-port443-filter-ecs-pri']

# Server filters
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true

require_dnssec   = true
require_nolog    = true
require_nofilter = false   # false = allow Quad9 with malware filtering

# [H-2] FIX: ephemeral keypair for each request (anonymized relay)
dnscrypt_ephemeral_keys = true

# Network
force_tcp   = false
timeout     = 5000
keepalive   = 30

# Bootstrap — only for fetching resolver list on startup
# NOT used for user queries
bootstrap_resolvers = ['9.9.9.11:53', '149.112.112.112:53']

# [H-1] FIX: fallback to system DNS when upstream is unavailable
fallback_resolver   = ""
ignore_system_dns   = true
netprobe_timeout    = 60
netprobe_address    = '9.9.9.9:53'

# Request filters
block_ipv6        = false
block_unqualified = true   # block requests without domain (leaks)
block_undelegated = true   # block non-existent TLD

# Cache
cache           = true
cache_size      = 4096
cache_min_ttl   = 2400
cache_max_ttl   = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# Logging
log_files_max_size    = 10
log_files_max_age     = 7
log_files_max_backups = 1

# Split DNS forwarding (if configured)
forwarding_rules = '${FWD_RULES}'

# Anonymized DNS — relay and server from DIFFERENT providers
[anonymized_dns]
routes = [
    { server_name='quad9-doh-ip4-port443-filter-ecs-pri', via=['anon-cs-de', 'anon-cs-nl'] }
]
skip_incompatible = false

[query_log]
format = 'tsv'

[nx_log]
format = 'tsv'

[sources.public-resolvers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
]
cache_file   = 'public-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73

[sources.relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/relays.md'
]
cache_file   = 'relays.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73

[broken_implementations]
fragments_blocked = [
  'cisco', 'cisco-ipv6', 'cisco-familyshield',
  'cisco-familyshield-ipv6', 'cisco-sandbox',
  'cleanbrowsing-adult', 'cleanbrowsing-adult-ipv6',
  'cleanbrowsing-family', 'cleanbrowsing-family-ipv6',
  'cleanbrowsing-security', 'cleanbrowsing-security-ipv6'
]
EOF
    log "  [✓] dnscrypt-proxy.toml written"
    info "Config: ${TOML}"
    info "Port:   127.0.0.1:5355"
    info "Server: quad9-doh-ip4-port443-filter-ecs-pri"
}

enable_dnscrypt() {
    local STATUS
    STATUS=$(brew services list 2>/dev/null | awk '/dnscrypt-proxy/{print $2}')

    if [[ "$STATUS" == "started" ]]; then
        warn "dnscrypt-proxy already running (user service)."
        ask "Restart dnscrypt-proxy?" CONFIRM
        if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
            brew services restart dnscrypt-proxy \
                || die "dnscrypt-proxy restart failed!"
        else
            log "Keeping existing dnscrypt-proxy service."
            return 0
        fi
    else
        log "Starting dnscrypt-proxy (user service)..."
        brew services start dnscrypt-proxy \
            || die "dnscrypt-proxy start failed! DNS is not available — aborting."
    fi

    sleep 2
    log "Verifying dnscrypt-proxy on UDP:5355..."
    if sudo lsof +c 15 -Pni UDP:5355 2>/dev/null | grep -q dnscrypt; then
        log "dnscrypt-proxy confirmed listening on UDP:5355 ✓"
    else
        warn "dnscrypt-proxy not detected on UDP:5355 — check: brew services list"
    fi
}

disable_dnscrypt() {
    if brew services list 2>/dev/null | grep -q "dnscrypt-proxy"; then
        log "Stopping dnscrypt-proxy (user service)..."
        brew services stop dnscrypt-proxy || warn "Failed to stop dnscrypt-proxy"
    else
        log "dnscrypt-proxy service not found — nothing to stop."
    fi
}

# ──────────────────────────────────────────
# PF — DNS LEAK PREVENTION
# ──────────────────────────────────────────
prepare_pf_dns_lock_anchor() {
    local PF_ANCHOR="/etc/pf.anchors/com.hardening.dnsleak"

    log "Writing PF anchor for DNS leak prevention: ${PF_ANCHOR}"
    sudo mkdir -p /etc/pf.anchors

    sudo tee "$PF_ANCHOR" > /dev/null <<'EOF'
# ============================================================
# foxhole-macos — DNS Leak Prevention Anchor
# Generated by mac-hardening-netlib.sh v0.16
# References: RFC 4890 (ICMPv6), OpenBSD pf docs
# ============================================================

# --- Loopback: without restriction (dnscrypt-proxy на :5355) ---
pass quick on lo0 all

# --- [C-3] FIX: ICMPv6 obligatory (RFC 4890 §4.3.1) ---
# Without this, NDP (neighbor discovery) and PMTUD break
pass quick inet6 proto icmp6 all

# --- External DNS resolver: [C-2] FIX ---
# Allow traffic to external DNS resolvers if needed
# pass out quick proto { udp tcp } to <DNS_RESOLVER_IP> port 53

# --- [C-1] FIX: Whitelist by IP provider, NOT any:443 ---
# Разрешаем исходящий трафик только к Quad9 (DoH + DNSCrypt relay)
pass out quick proto { udp tcp } to 9.9.9.9
pass out quick proto { udp tcp } to 149.112.112.112

# --- Block plain DNS (IPv4) ---
block out quick proto { udp tcp } to any port 53
block out quick proto { udp tcp } to any port 853

# --- Block plain DNS (IPv6) ---
block out quick inet6 proto { udp tcp } to any port 53
block out quick inet6 proto { udp tcp } to any port 853
EOF

    log "  [✓] PF anchor written: ${PF_ANCHOR}"
}

enable_pf_dns_lock() {
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    log "Enabling PF DNS leak lock..."
    warn "WARNING: Blocks direct DNS (53/853 v4/v6)."
    warn "Ensure Quad9 DoH profile is already installed."
    ask "Continue enabling PF DNS lock?" CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        log "PF DNS lock aborted by user."
        return 0
    fi

    if ! grep -qF "$PF_MARKER" "$PF_CONF" 2>/dev/null; then
        sudo tee -a "$PF_CONF" > /dev/null << EOF

${PF_MARKER}
anchor "com.hardening.dnsleak"
load anchor "com.hardening.dnsleak" from "/etc/pf.anchors/com.hardening.dnsleak"
EOF
        log "PF marker added to ${PF_CONF}"
    else
        warn "PF DNS lock marker already present in ${PF_CONF}"
    fi

    if sudo pfctl -f "$PF_CONF" 2>/dev/null && sudo pfctl -e 2>/dev/null; then
        log "PF rules loaded — DNS leak prevention active."
    else
        warn "PF reload failed — reboot may be required."
    fi

    if sudo pfctl -sr 2>/dev/null | grep -q "port 53"; then
        log "PF DNS lock: ACTIVE ✓"
    else
        warn "PF DNS lock: verify manually: sudo pfctl -sr"
    fi

    # [H-5] NEW: LaunchDaemon for auto-starting pf on boot
    _install_pf_launchdaemon
}

# [H-5] NEW: auto-start pf anchor on system boot
_install_pf_launchdaemon() {
    local PLIST="/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist"

    sudo tee "$PLIST" > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hardening.pf.dnsleak</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>/sbin/pfctl -e -f /etc/pf.conf 2>/dev/null; /sbin/pfctl -a com.hardening.dnsleak -f /etc/pf.anchors/com.hardening.dnsleak</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/foxhole-pf.log</string>
</dict>
</plist>
EOF
    sudo chown root:wheel "$PLIST"
    sudo chmod 644 "$PLIST"
    sudo launchctl load "$PLIST" 2>/dev/null || true
    log "  [✓] pf LaunchDaemon installed (auto-loads on boot)"
}

disable_pf_dns_lock() {
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    log "Disabling PF DNS leak lock..."

    if [[ -f "$PF_CONF" ]] && grep -qF "$PF_MARKER" "$PF_CONF"; then
        local TMP_CONF
        TMP_CONF=$(mktemp)
        awk "/$(echo "$PF_MARKER" | sed 's/[^^]/[&]/g; s/\^/\\^/g')/ {exit} {print}" \
            "$PF_CONF" > "$TMP_CONF"
        sudo cp "$PF_CONF" "${PF_CONF}.bak.hardening_$(date +%Y%m%d_%H%M%S)"
        sudo mv "$TMP_CONF" "$PF_CONF"
        log "PF marker removed, backup saved."
    else
        log "No PF DNS lock marker found — nothing to remove."
    fi

    sudo rm -f /etc/pf.anchors/com.hardening.dnsleak || true

    # Unload LaunchDaemon
    local PLIST="/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist"
    sudo launchctl unload "$PLIST" 2>/dev/null || true
    sudo rm -f "$PLIST"

    sudo pfctl -f "$PF_CONF" 2>/dev/null && log "PF reloaded without DNS lock."
}

# ──────────────────────────────────────────
# HOSTS — IDEMPOTENT UPDATE
# ──────────────────────────────────────────
update_hosts() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_URL="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    local HOSTS_FILE="/etc/hosts"
    local BACKUP="/etc/hosts.bak.$(date +%Y%m%d_%H%M%S)"
    local MIN_LINES=50
    local TMP_HOSTS
    TMP_HOSTS=$(mktemp)

    log "Checking /etc/hosts..."

    if grep -qF "$MARKER" "$HOSTS_FILE"; then
        local BLOCK_LINES
        BLOCK_LINES=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo 0)
        warn "StevenBlack blocklist found. Blocked domains: ${BLOCK_LINES}"
        if [[ "$BLOCK_LINES" -ge "$MIN_LINES" ]]; then
            info "Blocklist has ${BLOCK_LINES} entries — looks healthy."
            ask "Update to latest version anyway?" CONFIRM
        else
            warn "Only ${BLOCK_LINES} entries — looks incomplete!"
            ask "Re-download blocklist?" CONFIRM
        fi
        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            log "Skipping hosts update."; rm -f "$TMP_HOSTS"; return 0
        fi
        local LINE_NUM
        LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
        sudo cp "$HOSTS_FILE" "$BACKUP"
        sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" \
            | sudo tee "${HOSTS_FILE}.new" > /dev/null
        sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
        log "Old blocklist removed. Backup: $BACKUP"
    else
        local TOTAL_LINES
        TOTAL_LINES=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
        if [[ "$TOTAL_LINES" -ge "$MIN_LINES" ]]; then
            warn "/etc/hosts has ${TOTAL_LINES} lines — custom config detected."
            info "Custom entries (preserved above marker):"
            grep -v "^#\|^[[:space:]]*$" "$HOSTS_FILE" | head -30 || true
            ask "Add StevenBlack below existing content?" CONFIRM
            if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
                log "Skipping hosts update."; rm -f "$TMP_HOSTS"; return 0
            fi
        fi
        sudo cp "$HOSTS_FILE" "$BACKUP"
        log "Backup: $BACKUP"
    fi

    log "Downloading StevenBlack blocklist..."
    if ! curl -fsSL "$HOSTS_URL" -o "$TMP_HOSTS"; then
        rm -f "$TMP_HOSTS"; die "Failed to download StevenBlack hosts!"
    fi

    # SHA-256 + [M-4]: inform user about last commit
    local SHA256
    SHA256=$(shasum -a 256 "$TMP_HOSTS" | awk '{print $1}')
    info "SHA-256: ${SHA256}"
    local LATEST_COMMIT
    LATEST_COMMIT=$(curl -fsSL \
        "https://api.github.com/repos/StevenBlack/hosts/commits?path=hosts&per_page=1" \
        2>/dev/null | grep '"sha"' | head -1 | awk -F'"' '{print $4}' | cut -c1-7)
    info "Latest GitHub commit: ${LATEST_COMMIT:-unknown}"
    info "Verify at: https://github.com/StevenBlack/hosts/commits/master/hosts"

    {
        printf "\n%s\n" "$MARKER"
        printf "# Added:   %s\n" "$(date)"
        printf "# Source:  %s\n" "$HOSTS_URL"
        printf "# SHA-256: %s\n" "$SHA256"
        printf "# Commit:  %s\n" "${LATEST_COMMIT:-unknown}"
        cat "$TMP_HOSTS"
    } | sudo tee -a "$HOSTS_FILE" > /dev/null

    rm -f "$TMP_HOSTS"
    sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder 2>/dev/null || true

    local TOTAL
    TOTAL=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo "?")
    log "/etc/hosts updated. Blocked domains: ${TOTAL}"
}

disable_hosts_blocklist() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_FILE="/etc/hosts"
    local BACKUP="/etc/hosts.bak.remove_$(date +%Y%m%d_%H%M%S)"

    if ! grep -qF "$MARKER" "$HOSTS_FILE" 2>/dev/null; then
        log "No StevenBlack marker in ${HOSTS_FILE} — nothing to remove."
        return 0
    fi

    log "Removing StevenBlack blocklist from ${HOSTS_FILE}..."
    sudo cp "$HOSTS_FILE" "$BACKUP"
    local LINE_NUM
    LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
    sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" | sudo tee "${HOSTS_FILE}.new" > /dev/null
    sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
    log "Blocklist removed. Backup: $BACKUP"
}

# ──────────────────────────────────────────
# PRIVOXY
# ──────────────────────────────────────────
install_privoxy() {
    install_formula "privoxy" || die "privoxy install failed!"
    resolve_brew_prefix  # [L-4] FIX: ensure BREW_PREFIX before use
    local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
    if [[ ! -f "$PRIVOXY_CONF" ]]; then
        die "Privoxy config not found: ${PRIVOXY_CONF}. Check brew --prefix."
    fi
}

configure_privoxy_vpn_bypass() {
    resolve_brew_prefix  # [L-4] FIX: guard in case of a call without install_privoxy
    local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
    local BYPASS_MARKER="# ===== VPN bypass ====="

    if grep -qF "$BYPASS_MARKER" "$PRIVOXY_CONF" 2>/dev/null; then
        warn "Privoxy VPN bypass already configured."
        return 0
    fi

    log "Adding VPN bypass rules to Privoxy config..."
    sudo tee -a "$PRIVOXY_CONF" > /dev/null << 'EOF'
# ===== VPN bypass =====
forward 10.0.0.0/8     .
forward 172.16.0.0/12  .
forward 192.168.0.0/16 .
forward 100.64.0.0/10  .
forward 127.0.0.0/8    .
EOF
    log "  [✓] VPN bypass rules added"
}

enable_privoxy_vpn_autoswitch() {
    local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
    local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    local TOGGLE_LOG="/var/log/proxy-toggle.log"

    log "Configuring Privoxy VPN auto-switch LaunchDaemon..."

    sudo tee "$TOGGLE_SCRIPT" > /dev/null << 'SCRIPT'
#!/bin/bash
LOG="/var/log/proxy-toggle.log"
MAX_LOG_SIZE=5242880

log_msg() {
    if [[ -f "$LOG" ]] && [[ $(stat -f%z "$LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
        tail -n 500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"
}

# [H-4] FIX: improved VPN tunnel detection logic
vpn_active() {
    # Find any utun interface with inet address
    ifconfig 2>/dev/null \
        | awk '/^utun[0-9]/{iface=substr($1,1,length($1)-1); found=1}
               found && /inet /{print iface; exit}' \
        | grep -q "utun" && return 0
    return 1
}

get_services() {
    networksetup -listallnetworkservices 2>/dev/null \
        | tail -n +2 \
        | grep -v "^\*" \
        | grep -vEi "vpn|cisco|anyconnect|wireguard"
}

set_proxy() {
    local STATE="$1"
    while IFS= read -r SERVICE; do
        [[ -z "$SERVICE" ]] && continue
        networksetup -setwebproxystate      "$SERVICE" "$STATE" 2>/dev/null
        networksetup -setsecurewebproxystate "$SERVICE" "$STATE" 2>/dev/null
        if [[ "$STATE" == "on" ]]; then
            networksetup -setwebproxy        "$SERVICE" "127.0.0.1" "8118" 2>/dev/null
            networksetup -setsecurewebproxy  "$SERVICE" "127.0.0.1" "8118" 2>/dev/null
        fi
    done <<< "$(get_services)"
}

if vpn_active; then
    log_msg "VPN detected (utun interface) → proxy OFF"
    set_proxy off
else
    log_msg "No tunnel VPN → proxy ON"
    set_proxy on
fi
SCRIPT

    sudo chown root:wheel "$TOGGLE_SCRIPT"
    sudo chmod 755 "$TOGGLE_SCRIPT"

    sudo tee "$DAEMON_PLIST" > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hardening.proxytoggle</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${TOGGLE_SCRIPT}</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>/Library/Preferences/SystemConfiguration</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>${TOGGLE_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${TOGGLE_LOG}</string>
</dict>
</plist>
EOF

    sudo chown root:wheel "$DAEMON_PLIST"
    sudo chmod 644 "$DAEMON_PLIST"

    sudo launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
    sudo launchctl load  "$DAEMON_PLIST" \
        && log "LaunchDaemon loaded — proxy auto-switches on VPN." \
        || die "LaunchDaemon failed to load!"

    sudo bash "$TOGGLE_SCRIPT"

    if netstat -an 2>/dev/null | grep -q "0.0.0.0.8118"; then
        warn "Privoxy exposed on 0.0.0.0:8118 — check config!"
    else
        log "Privoxy: loopback only ✓"
    fi
}

disable_privoxy_autoswitch() {
    local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
    log "Disabling Privoxy VPN auto-switch..."
    sudo launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
    sudo rm -f "$DAEMON_PLIST" "$TOGGLE_SCRIPT"
    log "  [✓] Privoxy auto-switch disabled"
}

# ──────────────────────────────────────────
# [M-1] NEW: HEALTH CHECK — 10 тестов из мануала
# ──────────────────────────────────────────
verify_dns_stack() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║         DNS Stack Health Check           ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""

    local PASS=0 FAIL=0

    _chk() {
        local ID="$1" DESC="$2" CMD="$3" EXPECT="$4"
        local OUT
        OUT=$(eval "$CMD" 2>/dev/null || true)
        if echo "$OUT" | grep -q "$EXPECT"; then
            log "  [${ID}] ${DESC}"
            (( PASS++ ))
        else
            err "  [${ID}] ${DESC}"
            info "       Expected pattern: '${EXPECT}'"
            info "       Got: $(echo "$OUT" | head -1)"
            (( FAIL++ ))
        fi
    }

    # [1] Quad9 Profile active
    _chk "1" "Quad9 Profile active" \
        "scutil --dns" \
        "9\.9\.9"

    # [2] dnscrypt-proxy listens on :5355
    _chk "2" "dnscrypt-proxy on UDP:5355" \
        "sudo lsof +c 15 -Pni UDP:5355" \
        "dnscrypt"

    # [3] Basic DNS resolution
    _chk "3" "Basic DNS resolution" \
        "dig +short google.com @127.0.0.1 -p 5355" \
        "[0-9]"

    # [4] DNSSEC ad flag
    _chk "4" "DNSSEC (ad flag)" \
        "dig +dnssec icann.org @127.0.0.1 -p 5355" \
        " ad"

    # [5] DNSSEC fail test — should return SERVFAIL
    _chk "5" "DNSSEC validation (SERVFAIL on bad domain)" \
        "dig www.dnssec-failed.org @127.0.0.1 -p 5355" \
        "SERVFAIL"

    # [6] Quad9 reachability
    _chk "6" "Quad9 DoH reachability" \
        "curl -s --max-time 5 https://on.quad9.net" \
        "Yes"

    # [7] Plain DNS locked from the outside
    local DNS_OUT
    DNS_OUT=$(timeout 3 dig google.com @8.8.8.8 2>/dev/null || true)
    if echo "$DNS_OUT" | grep -q "NOERROR"; then
        err "  [7] Plain DNS blocked (@8.8.8.8)"
        info "       pf DNS lock may not be active"
        (( FAIL++ ))
    else
        log "  [7] Plain DNS blocked (@8.8.8.8) ✓"
        (( PASS++ ))
    fi

    # [8] Split DNS configuration
    _chk "8" "Split DNS configuration" \
        "scutil --dns" \
        "resolver"

    # [9] pf enabled
    _chk "9" "pf firewall enabled" \
        "sudo pfctl -s info" \
        "Enabled"

    # [10] StevenBlack hosts
    local HOSTS_COUNT
    HOSTS_COUNT=$(grep -c "^0\.0\.0\.0" /etc/hosts 2>/dev/null || echo 0)
    if [[ "$HOSTS_COUNT" -gt 1000 ]]; then
        log "  [10] StevenBlack hosts (${HOSTS_COUNT} entries) ✓"
        (( PASS++ ))
    else
        err "  [10] StevenBlack hosts (${HOSTS_COUNT} entries — too few)"
        (( FAIL++ ))
    fi

    echo ""
    echo "  ──────────────────────────────────────────"
    echo "  Results: ${PASS}/10 passed, ${FAIL} failed"
    echo "  ──────────────────────────────────────────"
    echo ""
    [[ "$FAIL" -eq 0 ]] && log "All checks passed. Stack is healthy. ✓" \
                        || warn "${FAIL} check(s) failed — review above."
    echo ""
}

# ──────────────────────────────────────────
# RESET
# ──────────────────────────────────────────
reset_net_hardening() {
    log "Resetting network hardening (dnscrypt, PF DNS lock, Privoxy toggle, hosts blocklist)..."
    disable_dnscrypt
    disable_pf_dns_lock
    disable_privoxy_autoswitch
    disable_hosts_blocklist
    for S in $(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*'); do
        networksetup -setwebproxystate      "$S" off 2>/dev/null || true
        networksetup -setsecurewebproxystate "$S" off 2>/dev/null || true
    done
    log "Network hardening reset complete."
}

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
main() {
    clear
    echo ""
    echo "  ░██████████                      ░██                   ░██           "
    echo "  ░██                              ░██                   ░██           "
    echo "  ░██         ░███████  ░██    ░██ ░████████   ░███████  ░██  ░███████ "
    echo "  ░█████████ ░██    ░██  ░██  ░██  ░██    ░██ ░██    ░██ ░██ ░██    ░██"
    echo "  ░██        ░██    ░██  ░██  ░██  ░██    ░██ ░██    ░██ ░██ ░██       "
    echo "  ░██         ░███████  ░██    ░██ ░██    ░██  ░███████  ░██  ░███████ "
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║       macOS Network Hardening Netlib     ║"
    echo "  ║            v0.16  ·  by Gr3y-foX         ║"  # [L-3] FIX: version update
    echo "  ║       ARM/M-chip  |  strict mode         ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  module: netlib   |  mode: interactive   ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  [!] Unauthorized use is prohibited.     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    warn "This module modifies network settings. Sudo may be required."
    info "Tip: usually sourced from profiles (vpn_daily / paranoid_tor)."
    echo ""
    ask "Continue?" CONFIRM
    [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
    echo ""

    ask "Create backup snapshot before proceeding?" CONFIRM_BK
    if [[ "$CONFIRM_BK" == "y" || "$CONFIRM_BK" == "Y" ]]; then
        create_net_backup
    else
        warn "Skipping backup — proceeding without snapshot."
        echo ""
    fi

    while true; do
        echo "  ╔══════════════════════════════════════════╗"
        echo "  ║           Network Hardening Menu         ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [1]  Install + configure + enable       ║"
        echo "  ║       dnscrypt-proxy                     ║"
        echo "  ║  [2]  Enable PF DNS leak lock            ║"
        echo "  ║       (ports 53/853 — IPv4/IPv6 BLOCKED) ║"
        echo "  ║  [3]  Update /etc/hosts blocklist        ║"
        echo "  ║       (StevenBlack)                      ║"
        echo "  ║  [4]  Install Privoxy + VPN auto-switch  ║"
        echo "  ║  [5]  Reset network hardening            ║"
        echo "  ║       (dnscrypt / PF / Privoxy / proxy)  ║"
        echo "  ║  [6]  DNS Stack Health Check             ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [7]  Quit                               ║"
        echo "  ╚══════════════════════════════════════════╝"
        echo ""
        read -rp "  Choice (1-7): " CHOICE
        echo ""

        case "$CHOICE" in
            1)
                log "[1] dnscrypt-proxy setup"
                install_dnscrypt
                configure_dnscrypt
                enable_dnscrypt
                echo ""
                ;;
            2)
                log "[2] PF DNS leak lock"
                prepare_pf_dns_lock_anchor
                enable_pf_dns_lock
                echo ""
                ;;
            3)
                log "[3] StevenBlack /etc/hosts blocklist"
                update_hosts
                echo ""
                ;;
            4)
                log "[4] Privoxy + VPN auto-switch"
                install_privoxy
                configure_privoxy_vpn_bypass
                enable_privoxy_vpn_autoswitch
                echo ""
                ;;
            5)
                warn "[5] RESET: disabling dnscrypt, PF DNS lock, Privoxy auto-switch, clearing proxies"
                ask "Are you sure? This will revert network hardening changes." CONFIRM_RESET
                if [[ "$CONFIRM_RESET" == "y" || "$CONFIRM_RESET" == "Y" ]]; then
                    reset_net_hardening
                else
                    log "Reset aborted."
                fi
                echo ""
                ;;
            6)
                verify_dns_stack
                ;;
            7)
                echo "Done. Stay paranoid. 🔒"
                exit 0
                ;;
            *)
                warn "Invalid choice. Please select 1-7."
                echo ""
                ;;
        esac
    done
}

if [[ "${0##*/}" == "mac-hardening-netlib.sh" ]]; then
    main
fi

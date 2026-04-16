#!/bin/bash
# ============================================================
#  macOS Advanced Security Hardening Script v1
#  this module work on setting netlibs
#  Based on: github.com/drduh/macOS-Security-and-Privacy-Guide
#  Author: Grey Fox
#  Changes v1: ARM/M-chip paths, strict error handling,
#  Services used: dnscrypt-proxy, PF - dns leak prevention,
#  StevenBlack Blocklist, Privoxy
# ============================================================

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

source ./mac-hardening-netlib.sh
resolve_brew_prefix 

# ──────────────────────────────────────────
# DNSCRYPT-PROXY
# ──────────────────────────────────────────
install_dnscrypt() {
  install_formula "dnscrypt-proxy" || die "dnscrypt-proxy install failed!"
}

enable_dnscrypt() {
  # user-level service, without sudo
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
      || die "dnscrypt-proxy start failed! DNS недоступен — прерываем."
  fi

  sleep 2
  log "Verifying dnscrypt-proxy on UDP:5355..."
  if sudo lsof +c 15 -Pni UDP:5355 2>/dev/null | grep -q dnscrypt; then
    log "dnscrypt-proxy confirmed listening on UDP:5355"
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

  sudo tee "$PF_ANCHOR" > /dev/null <<'EOF'
# Block all direct DNS (IPv4 + IPv6) — only dnscrypt-proxy / DoH allowed
# pass только с localhost на DoH-порты
pass out quick proto udp from 127.0.0.1 to any port 443
pass out quick proto tcp from 127.0.0.1 to any port 443
pass out quick proto udp from 127.0.0.1 to any port 8443
pass out quick proto tcp from 127.0.0.1 to any port 8443
pass out quick proto udp from ::1 to any port 443
pass out quick proto tcp from ::1 to any port 443

# Блокируем прямые DNS (IPv4)
block out quick proto udp to any port 53
block out quick proto tcp to any port 53
block out quick proto tcp to any port 853

# Блокируем прямые DNS (IPv6)
block out quick inet6 proto udp to any port 53
block out quick inet6 proto tcp to any port 53
block out quick inet6 proto tcp to any port 853
EOF
}

enable_pf_dns_lock() {
  local PF_CONF="/etc/pf.conf"
  local PF_MARKER="# ===== hardening dns lock ====="

  log "Enabling PF DNS leak lock..."

  warn "ВНИМАНИЕ: Эта секция заблокирует прямые DNS-запросы (53/853 v4/v6)."
  warn "Убедитесь, что DoH/DNS профиль (например Quad9) уже настроен."
  ask "Продолжить включение PF DNS lock?" CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    log "PF DNS lock aborted by user."
    return 0
  fi

  if ! grep -qF "$PF_MARKER" "$PF_CONF" 2>/dev/null; then
    sudo tee -a "$PF_CONF" > /dev/null <<EOF

$PF_MARKER
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
}

disable_pf_dns_lock() {
  local PF_CONF="/etc/pf.conf"
  local PF_MARKER="# ===== hardening dns lock ====="

  log "Disabling PF DNS leak lock..."

  if [[ -f "$PF_CONF" ]] && grep -qF "$PF_MARKER" "$PF_CONF"; then
    local TMP_CONF
    TMP_CONF=$(mktemp)

    # вырезаем блок маркера
    awk "
      /$PF_MARKER/ {exit}
      {print}
    " "$PF_CONF" > "$TMP_CONF"

    sudo cp "$PF_CONF" "${PF_CONF}.bak.hardening_$(date +%Y%m%d_%H%M%S)"
    sudo mv "$TMP_CONF" "$PF_CONF"
    log "PF marker removed, backup saved."
  else
    log "No PF DNS lock marker found — nothing to remove."
  fi

  # You can leave the anchor or delete it as well
  sudo rm -f /etc/pf.anchors/com.hardening.dnsleak || true

  if sudo pfctl -f "$PF_CONF" 2>/dev/null; then
    log "PF reloaded without DNS lock."
  fi
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

    # [FIX v5] SHA-256 for verification
    local SHA256
    SHA256=$(shasum -a 256 "$TMP_HOSTS" | awk '{print $1}')
    info "SHA-256 скачанного файла: ${SHA256}"
    info "Сверьте с: https://github.com/StevenBlack/hosts (последний коммит)"

    {
        printf "\n%s\n" "$MARKER"
        printf "# Added: %s\n" "$(date)"
        printf "# Source: %s\n" "$HOSTS_URL"
        printf "# SHA-256: %s\n" "$SHA256"
        cat "$TMP_HOSTS"
    } | sudo tee -a "$HOSTS_FILE" > /dev/null

    rm -f "$TMP_HOSTS"

    local TOTAL
    TOTAL=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo "?")
    log "/etc/hosts updated. Blocked domains: ${TOTAL}"

}

# ──────────────────────────────────────────
# HOSTS — DISABLE HOST BLOCKLIST
# ──────────────────────────────────────────
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

  sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" > "${HOSTS_FILE}.new"
  sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
  log "Blocklist removed. Backup: $BACKUP"
}

# ──────────────────────────────────────────
# PRIVOXY
# ──────────────────────────────────────────

install_privoxy() {
  install_formula "privoxy" || die "privoxy install failed!"

  if [[ -z "${BREW_PREFIX:-}" ]]; then
    die "BREW_PREFIX is not set. Call resolve_brew_prefix first."
  fi

  local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
  if [[ ! -f "$PRIVOXY_CONF" ]]; then
    die "Privoxy config not found: ${PRIVOXY_CONF}. Проверьте brew --prefix."
  fi
}

configure_privoxy_vpn_bypass() {
  local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
  local BYPASS_MARKER="# ===== VPN bypass ====="

  if grep -qF "$BYPASS_MARKER" "$PRIVOXY_CONF" 2>/dev/null; then
    warn "Privoxy VPN bypass already configured."
    return 0
  fi

  log "Adding VPN bypass rules to Privoxy config..."
  sudo tee -a "$PRIVOXY_CONF" > /dev/null <<'EOF'
# ===== VPN bypass =====
forward 10.0.0.0/8   .
forward 172.16.0.0/12 .
forward 192.168.0.0/16 .
forward 100.64.0.0/10 .
forward 127.0.0.0/8   .
EOF
}

enable_privoxy_vpn_autoswitch() {
  local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
  local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
  local TOGGLE_LOG="/var/log/proxy-toggle.log"

  log "Configuring Privoxy VPN auto-switch LaunchDaemon..."

  sudo tee "$TOGGLE_SCRIPT" > /dev/null <<'SCRIPT'
#!/bin/bash
LOG="/var/log/proxy-toggle.log"
MAX_LOG_SIZE=5242880 # 5 MB

log_msg() {
  if [[ -f "$LOG" ]] && [[ $(stat -f%z "$LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
    tail -n 500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
  fi
  echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"
}

vpn_active() {
  ifconfig 2>/dev/null \
    | awk '/^utun[0-9]/{found=1} found && /inet /{print; exit}' \
    | grep -q "inet" && return 0
  return 1
}

get_services() {
  networksetup -listallnetworkservices 2>/dev/null \
    | tail -n +2 \
    | grep -v "^\*" \
    | grep -vEi "vpn|cisco|anyconnect|wireguard|tailscale"
}

set_proxy() {
  local STATE="$1"
  while IFS= read -r SERVICE; do
    [[ -z "$SERVICE" ]] && continue
    networksetup -setwebproxystate "$SERVICE" "$STATE" 2>/dev/null
    networksetup -setsecurewebproxystate "$SERVICE" "$STATE" 2>/dev/null
    if [[ "$STATE" == "on" ]]; then
      networksetup -setwebproxy "$SERVICE" "127.0.0.1" "8118" 2>/dev/null
      networksetup -setsecurewebproxy "$SERVICE" "127.0.0.1" "8118" 2>/dev/null
    fi
  done <<< "$(get_services)"
}

if vpn_active; then
  log_msg "VPN detected → proxy OFF"
  set_proxy off
else
  log_msg "No VPN → proxy ON"
  set_proxy on
fi
SCRIPT

  sudo chown root:wheel "$TOGGLE_SCRIPT"
  sudo chmod 755 "$TOGGLE_SCRIPT"

  sudo tee "$DAEMON_PLIST" > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
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
  sudo launchctl load "$DAEMON_PLIST" \
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
}

#---------------------------------------
# RESET NETWORK HARDENING
#---------------------------------------
reset_net_hardening() {
  log "Resetting network hardening (dnscrypt, PF DNS lock, Privoxy toggle, hosts blocklist)..."

  disable_dnscrypt
  disable_pf_dns_lock
  disable_privoxy_autoswitch
  disable_hosts_blocklist  # опционально, если хочешь

  # Disable system HTTP(S) proxies
  for S in $(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*'); do
    networksetup -setwebproxystate "$S" off 2>/dev/null || true
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
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║   macOS Security Hardening Netlib    ║"
  echo "  ║           v1 · by Grey Fox           ║"
  echo "  ║              ARM/M-chip              ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
  warn "This script modifies network-related system settings. Sudo may be required."
  ask "Continue?" CONFIRM
  [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
  echo ""

  # Just a quick reminder that this is a module, not a full installer
  info "Tip: This file is usually loaded from profiles (paranoid_tor / vpn_daily)."
  info "You can now manually load individual blocks for testing."
  echo ""

  while true; do
    echo "Select action:"
    echo "  [1] Install + enable dnscrypt-proxy (user service)"
    echo "  [2] Enable PF DNS leak lock (53/853 v4/v6 BLOCKED)"
    echo "  [3] Update /etc/hosts with StevenBlack blocklist"
    echo "  [4] Install Privoxy + configure VPN auto-switch"
    echo "  [5] Reset network hardening (dnscrypt/PF/Privoxy/proxy)"
    echo "  [6] Quit"
    echo ""
    read -rp "Choice (1-6): " CHOICE
    echo ""

    case "$CHOICE" in
      1)
        log "[1] dnscrypt-proxy setup"
        install_dnscrypt
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
        update_hosts_blocklist
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
        echo "Done. Stay paranoid. 🔒"
        exit 0
        ;;
      *)
        warn "Invalid choice. Please select 1-6."
        echo ""
        ;;
    esac
  done
}

# If the file is run directly (rather than via `source`), open the menu
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main
fi



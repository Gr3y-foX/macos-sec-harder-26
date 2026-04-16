#!/bin/bash

# Profile: VPN Daily
# Dependencies:
#   - common-functions: log, warn, err, die, ask, resolve_brew_prefix
#   - mac-hardening-netlib.sh: install_dnscrypt, enable_dnscrypt, disable_dnscrypt,
#       reset_net_hardening, install_privoxy, ... (as needed)

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

set -uo pipefail

# Load common code (adjust paths as needed)
# source "./mac-hardening-common.sh"   # if you have a shared log/ask/die file
source "./mac-hardening-netlib.sh"

# Just a sanity-check: are the basic functions defined?
command -v log >/dev/null 2>&1 || { echo "[!] log() is not defined. Source base script first."; exit 1; }
command -v ask >/dev/null 2>&1 || { echo "[!] ask() is not defined. Source base script first."; exit 1; }

# For netlib we need BREW_PREFIX
resolve_brew_prefix

# ──────────────────────────────────────────
# PF KILLSWITCH ДЛЯ VPN
# ──────────────────────────────────────────
enable_pf_vpn_killswitch() {
  local PF_CONF="/etc/pf.conf"
  local PF_VPN_ANCHOR="/etc/pf.anchors/com.hardening.vpnkillswitch"
  local PF_VPN_MARKER="# ===== hardening vpn killswitch ====="

  echo ""
  warn ""The VPN kill switch will block all traffic except for VPN traffic."
  warn "Before enabling: The VPN must be connected so that the utun interface and server IP are known."
  echo ""
  ifconfig | grep -E "utun[0-9]" || true
  echo ""
  read -rp "Enter the name of the VPN interface (e.g., utun2): " VPN_IF
  read -rp "Enter the external IP address of the VPN server (peer), for example 198.51.100.10: " VPN_PEER_IP
  read -rp "Enter the name of the physical interface (Wi-Fi is usually en0): " INT_IF

  if [[ -z "$VPN_IF" || -z "$VPN_PEER_IP" || -z "$INT_IF" ]]; then
    err "All values are required. Aborting."
    return 1
  fi

  log "Writing PF anchor for killswitch: ${PF_VPN_ANCHOR}"
  sudo tee "$PF_VPN_ANCHOR" > /dev/null <<EOF
int_if = "${INT_IF}"
vpn_if = "${VPN_IF}"
vpn_gw = "${VPN_PEER_IP}"

set block-policy drop
set skip on lo0

block all
block out inet6

# Разрешаем базовый DHCP/ARP на физическом интерфейсе
pass on \$int_if inet proto icmp all keep state
pass on \$int_if proto { tcp, udp } from any port 67:68 to any port 67:68 keep state

# Разрешаем подключение к самому VPN-серверу
pass out on \$int_if proto { tcp, udp } to \$vpn_gw keep state

# Разрешаем весь трафик через VPN-интерфейс
pass on \$vpn_if all keep state
EOF

  if ! grep -qF "$PF_VPN_MARKER" "$PF_CONF" 2>/dev/null; then
    log "Adding anchor killswitch to ${PF_CONF}"
    sudo tee -a "$PF_CONF" > /dev/null <<EOF

$PF_VPN_MARKER
anchor "com.hardening.vpnkillswitch"
load anchor "com.hardening.vpnkillswitch" from "/etc/pf.anchors/com.hardening.vpnkillswitch"
EOF
  else
    warn "VPN killswitch marker already exists in ${PF_CONF}"
  fi

  log "Loading PF config with killswitch..."
  sudo pfctl -f "$PF_CONF" && sudo pfctl -e \
    && log "VPN killswitch active: traffic only through ${VPN_IF} or to ${VPN_PEER_IP}." \
    || warn "Failed to load PF with killswitch. Check the config."
}

disable_pf_vpn_killswitch() {
  local PF_CONF="/etc/pf.conf"
  local PF_VPN_ANCHOR="/etc/pf.anchors/com.hardening.vpnkillswitch"
  local PF_VPN_MARKER="# ===== hardening vpn killswitch ====="

  log "Disabling VPN killswitch..."

  if [[ -f "$PF_CONF" ]] && grep -qF "$PF_VPN_MARKER" "$PF_CONF"; then
    local TMP_CONF
    TMP_CONF=$(mktemp)
    awk "
      /$PF_VPN_MARKER/ {exit}
      {print}
    " "$PF_CONF" > "$TMP_CONF"

    sudo cp "$PF_CONF" "${PF_CONF}.bak.vpnks_$(date +%Y%m%d_%H%M%S)"
    sudo mv "$TMP_CONF" "$PF_CONF"
    log "VPN killswitch marker removed from pf.conf (backup saved)."
  else
    log "VPN killswitch marker not found in pf.conf."
  fi

  sudo rm -f "$PF_VPN_ANCHOR" || true

  # Reload default PF (without killswitch)
  sudo pfctl -f "$PF_CONF" 2>/dev/null || true
}

# ──────────────────────────────────────────
# МЕНЮ ПРОФИЛЯ VPN DAILY
# ──────────────────────────────────────────

main() {
  clear
  echo ""
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║        VPN Daily Profile Setup       ║"
  echo "  ║           by Grey Fox (Archont)      ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
  warn ""This profile requires the use of a commercial VPN client."
  warn "The script does not configure the VPN itself, only the environment around it."
  ask "Continue?" CONFIRM
  [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
  echo ""

  while true; do
    echo "Select an action:"
    echo "  [1] No VPN mode: install + enable dnscrypt-proxy"
    echo "  [2] VPN mode: disable dnscrypt-proxy"
    echo "  [3] Enable PF VPN killswitch (traffic only via utun + VPN IP)"
    echo "  [4] Disable PF VPN killswitch"
    echo "  [5] Reset network hardening (dnscrypt/PF/Privoxy/proxy)"
    echo "  [6] Exit"
    echo ""
    read -rp "Choice (1-6): " CHOICE
    echo ""

    case "$CHOICE" in
      1)
        log "[1] No VPN mode: dnscrypt-proxy as local DNS"
        install_dnscrypt
        enable_dnscrypt
        echo ""
        ;;
      2)
        log "[2] VPN mode: disable dnscrypt-proxy (trust VPN client's DNS)"
        disable_dnscrypt
        echo ""
        ;;
      3)
        log "[3] Enable PF VPN killswitch"
        enable_pf_vpn_killswitch
        echo ""
        ;;
      4)
        log "[4] Disable PF VPN killswitch"
        disable_pf_vpn_killswitch
        echo ""
        ;;
      5)
        warn "[5] RESET: Rollback of dnscrypt, PF DNS lock/killswitch, Privoxy, and system proxies"       
        ask "Точно выполнить reset_net_hardening()?" CONFIRM_RESET
        if [[ "$CONFIRM_RESET" == "y" || "$CONFIRM_RESET" == "Y" ]]; then
          reset_net_hardening
        else
          log "Reset cancelled."
        fi
        echo ""
        ;;
      6)
        echo "Done. VPN Daily profile configured."
        exit 0
        ;;
      *)
        warn "Invalid choice. Please select 1-6."
        echo ""
        ;;
    esac
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main
fi
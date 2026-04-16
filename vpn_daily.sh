#!/bin/bash

# VPN Daily profile — a simple wrapper around a commercial VPN (ClearVPN/OpenVPN)
# It is assumed that:
#   - the basic hardening installer has already been run
#   - mac-hardening-netlib.sh is located nearby and contains:
#       install_dnscrypt, enable_dnscrypt, disable_dnscrypt, reset_net_hardening

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

set -uo pipefail

# Here we assume that log/warn/err/ask/die are already available (from the base script)
# If you run the profile separately, you can add simple fallbacks:
log()   { echo "[+] $*"; }
warn()  { echo "[!] $*"; }
err()   { echo "[✗] $*" >&2; }
ask()   { local P="$1" V="$2"; read -rp " ${P} (y/N): " "$V"; }

# Connect netlib
source "./mac-hardening-netlib.sh"

# For netlib you need BREW_PREFIX
resolve_brew_prefix

main() {
  clear
  echo ""
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║          VPN Daily Profile          ║"
  echo "  ║      ClearVPN / OpenVPN friendly    ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
  warn "Profile for ordinary users: no PF, no complex rules."
  warn "Idea: set up once → turn on ClearVPN/OpenVPN → enjoy."
  ask "Continue?" CONFIRM
  [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
  echo ""

  while true; do
    echo "Choose an action:"
    echo "  [1] Mode WITHOUT VPN: install + enable dnscrypt-proxy (local DNS)"
    echo "  [2] Mode WITH VPN: disable dnscrypt-proxy (use DNS from VPN client)"
    echo "  [3] Show tips for ClearVPN/OpenVPN and DNS leak test"
    echo "  [4] RESET: soft rollback of network settings (dnscrypt/proxy) from netlib"
    echo "  [5] Exit"
    echo ""
    read -rp "Choice (1-5): " CHOICE
    echo ""

    case "$CHOICE" in
      1)
        log "[1] Mode WITHOUT VPN: dnscrypt-proxy as local DNS"
        install_dnscrypt
        enable_dnscrypt
        echo ""
        ;;

      2)
        log "[2] Mode WITH VPN: disable dnscrypt-proxy (but don't touch PF/hosts)"
        disable_dnscrypt
        echo ""
        ;;

      3)
        echo "===How to use this profile with ClearVPN + OpenVPN ==="
        echo ""
        echo "1) Install and configure ClearVPN (official client)."
        echo "2) Install an OpenVPN client (Tunnelblick / OpenVPN Connect) and import the .ovpn file."
        echo "3) For regular Wi-Fi without a VPN, you can enable dnscrypt-proxy (step 1)."
        echo "4) When you enable ClearVPN or OpenVPN:"
        echo "   - You can leave dnscrypt disabled (step 2) to avoid confusion."
        echo "   - DNS and traffic encryption are provided by the VPN client itself."
        echo ""
        echo "=== How to check that the VPN is working and there are no DNS leaks ==="
        echo "   1) Connect to the VPN."
        echo "   2) Open any DNS leak test in your browser, for example:"
        echo "      - https://ipleak.net/"
        echo "      - https://www.dnsleaktest.com/"
        echo "      - https://www.comparitech.com/privacy-security-tools/dns-leak-test/"
        echo "   3) Make sure that:"
        echo "      - IP and geolocation → match the VPN, not your ISP."
        echo "      - DNS servers → belong to the VPN (or a neutral provider),"
        echo "        but not your local ISP."
        echo ""
        ;;

      4)
        warn "[4] RESET: rollback dnscrypt and network proxies (from netlib)"
        ask "Execute reset_net_hardening()?" CONFIRM_RESET
        if [[ "$CONFIRM_RESET" == "y" || "$CONFIRM_RESET" == "Y" ]]; then
          reset_net_hardening
        else
          log "Reset cancelled."
        fi
        echo ""
        ;;

      5)
        echo "Done. For daily use: turn on your VPN and forget about it."
        exit 0
        ;;

      *)
        warn "Invalid choice. Specify 1-5."
        echo ""
        ;;
    esac
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main
fi
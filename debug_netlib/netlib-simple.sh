#!/bin/bash
#
# Foxhole-macos — macOS Network Hardening Library (Simple Edition)
#
# File:    netlib-simple.sh
# Version: 1.0 (2026)
# Author:  Gr3y-foX
# Based on: drduh/macOS-Security-and-Privacy-Guide (MIT)
# License: GNU GPL v3 — see LICENSE for details
#
# Overview:
#   Simplified network hardening for macOS. No external daemon dependencies.
#     - pf DNS leak lock (blocks plain DNS port 53/853, IPv4 + IPv6)
#     - /etc/hosts blocklist (StevenBlack, ~100k domains)
#     - Tailscale split DNS via /etc/resolver/ (native macOS mechanism)
#
# Target:     General users. Stable daily use. ClearVPN / Tailscale compatible.
# Not included: dnscrypt-proxy, Privoxy, anonymized relay (see netlib-advanced.sh)
#
# Requirements:
#   - macOS 13+ (Apple Silicon)
#   - Quad9 DoH Profile installed manually (see menu option [0])
#   - Tailscale installed (optional, only for option [3])
#
# Usage:
#   bash netlib-simple.sh          — interactive menu
#   source netlib-simple.sh        — load functions into current shell
#

set -euo pipefail

# ──────────────────────────────────────────
# COLOURS + LOGGING
# ──────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
die()  { err "$1"; exit 1; }

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
# BACKUP
# ──────────────────────────────────────────
NET_BACKUP_DIR="${HOME}/.foxhole/backups/$(date +%Y%m%d_%H%M%S)"

create_net_backup() {
    log "Creating pre-hardening backup snapshot..."
    mkdir -p "$NET_BACKUP_DIR" \
        || { warn "Cannot create backup dir: ${NET_BACKUP_DIR}"; return 1; }

    # /etc/pf.conf
    [[ -f /etc/pf.conf ]] \
        && sudo cp /etc/pf.conf "${NET_BACKUP_DIR}/pf.conf" \
        && log "  [✓] /etc/pf.conf" \
        || warn "  [–] /etc/pf.conf not found — skipped"

    # pf anchor (if already exists)
    [[ -f /etc/pf.anchors/com.hardening.dnsleak ]] \
        && sudo cp /etc/pf.anchors/com.hardening.dnsleak \
                   "${NET_BACKUP_DIR}/pf.anchor.dnsleak" \
        && log "  [✓] pf anchor"

    # /etc/hosts
    [[ -f /etc/hosts ]] \
        && sudo cp /etc/hosts "${NET_BACKUP_DIR}/hosts" \
        && log "  [✓] /etc/hosts" \
        || warn "  [–] /etc/hosts not found — skipped"

    # /etc/resolv.conf
    [[ -f /etc/resolv.conf ]] \
        && sudo cp /etc/resolv.conf "${NET_BACKUP_DIR}/resolv.conf" \
        && log "  [✓] /etc/resolv.conf"

    # System DNS resolver state
    scutil --dns > "${NET_BACKUP_DIR}/system-dns.txt" 2>/dev/null \
        && log "  [✓] scutil --dns"

    # /etc/resolver/ (Tailscale split DNS)
    if [[ -d /etc/resolver ]]; then
        sudo cp -r /etc/resolver "${NET_BACKUP_DIR}/resolver" \
            && log "  [✓] /etc/resolver/"
    fi

    echo ""
    log "Backup saved to: ${NET_BACKUP_DIR}"
    info "To restore: sudo bash ${NET_BACKUP_DIR}/../rollback.sh"
    echo ""
}

# ──────────────────────────────────────────
# QUAD9 DOH PROFILE — manual install guide
# ──────────────────────────────────────────
guide_quad9_profile() {
    echo ""
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║           Quad9 DoH Profile — Install Guide          ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo ""
    info  "  Quad9 profile encrypts DNS at OS level (DNSSEC + malware filter)."
    info  "  Must be installed manually — macOS requires user interaction."
    echo ""
    echo "  Steps:"
    echo "  ─────────────────────────────────────────────────────────"
    echo "  1. Open in browser:"
    echo "     https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/"
    echo ""
    echo "  2. Download the profile for server 9.9.9.11"
    echo "     (9.9.9.11 = ECS-compatible, works with iCloud Private Relay)"
    echo ""
    echo "  3. Open downloaded .mobileconfig file"
    echo "     → System Settings → Privacy & Security → Profiles → Install"
    echo ""
    echo "  4. Verify installation:"
    echo "     scutil --dns | grep '9\\.9\\.9'"
    echo ""
    echo "  ─────────────────────────────────────────────────────────"
    echo ""

    local VERIFIED
    VERIFIED=$(scutil --dns 2>/dev/null | grep "9\.9\.9" | head -1 || true)
    if [[ -n "$VERIFIED" ]]; then
        log "  Quad9 profile detected: ${VERIFIED}"
    else
        warn "  Quad9 profile NOT detected — install before enabling pf DNS lock."
    fi
    echo ""
}

# ──────────────────────────────────────────
# PF — DNS LEAK PREVENTION
# ──────────────────────────────────────────
prepare_pf_dns_lock_anchor() {
    local PF_ANCHOR="/etc/pf.anchors/com.hardening.dnsleak"

    log "Writing PF anchor for DNS leak prevention: ${PF_ANCHOR}"
    sudo mkdir -p /etc/pf.anchors

    sudo tee "$PF_ANCHOR" > /dev/null << 'EOF'
# ============================================================
# foxhole-macos — DNS Leak Prevention Anchor (Simple Edition)
# Generated by netlib-simple.sh v1.0
# References: RFC 4890 (ICMPv6), OpenBSD pf docs
# ============================================================

# --- Loopback: unrestricted (mDNSResponder lives here) ---
pass quick on lo0 all

# --- ICMPv6: mandatory per RFC 4890 §4.3.1 ---
# Required for NDP (neighbor discovery) and PMTUD.
# Removing this breaks IPv6 connectivity silently.
pass quick inet6 proto icmp6 all

# --- Tailscale DNS: MagicDNS resolver ---
# 100.100.100.100 is external to lo0 — must be explicitly allowed.
pass out quick proto { udp tcp } to 100.100.100.100 port 53

# --- Quad9 DoH: port 443 only ---
# 9.9.9.9  = standard Quad9
# 9.9.9.11 = ECS-compatible (used by macOS DoH profile — must be here)
# 149.112.112.112 = Quad9 secondary
# Port restriction prevents plain DNS (53) leaks to Quad9 IPs.
pass out quick proto { udp tcp } to 9.9.9.9     port 443
pass out quick proto { udp tcp } to 9.9.9.11    port 443
pass out quick proto { udp tcp } to 149.112.112.112 port 443

# --- Block plain DNS (IPv4): silent drop, no ICMP response ---
# block drop = attacker gets no confirmation rules exist.
# block out  = sends ICMP unreachable (reveals firewall presence).
block drop quick proto { udp tcp } to any port 53
block drop quick proto { udp tcp } to any port 853

# --- Block plain DNS (IPv6) ---
block drop quick inet6 proto { udp tcp } to any port 53
block drop quick inet6 proto { udp tcp } to any port 853
EOF

    log "  [✓] PF anchor written: ${PF_ANCHOR}"
}

enable_pf_dns_lock() {
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    log "Enabling PF DNS leak lock..."
    warn "This blocks all plain DNS (port 53/853) except Quad9 DoH and Tailscale."
    warn "Ensure Quad9 DoH Profile is installed first (menu option [0])."
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
        warn "PF DNS lock marker already present in ${PF_CONF} — reloading rules."
    fi

    if sudo pfctl -f "$PF_CONF" 2>/dev/null && sudo pfctl -e 2>/dev/null; then
        log "PF rules loaded."
    else
        warn "PF reload returned non-zero — rules may still be loaded. Verify:"
        warn "  sudo pfctl -sr | grep 'port 53'"
    fi

    if sudo pfctl -sr 2>/dev/null | grep -q "port 53"; then
        log "PF DNS lock: ACTIVE ✓"
    else
        warn "PF DNS lock: not confirmed — run: sudo pfctl -sr"
    fi

    _install_pf_launchdaemon
}

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
        log "PF marker removed. Backup saved."
    else
        log "No PF DNS lock marker found — nothing to remove."
    fi

    sudo rm -f /etc/pf.anchors/com.hardening.dnsleak || true

    local PLIST="/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist"
    sudo launchctl unload "$PLIST" 2>/dev/null || true
    sudo rm -f "$PLIST"

    sudo pfctl -f "$PF_CONF" 2>/dev/null \
        && log "PF reloaded without DNS lock." \
        || warn "PF reload failed — may need reboot."
}

# ──────────────────────────────────────────
# HOSTS — STEVENBLACK BLOCKLIST
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
        warn "StevenBlack blocklist already present. Entries: ${BLOCK_LINES}"
        if [[ "$BLOCK_LINES" -ge "$MIN_LINES" ]]; then
            ask "Update to latest version anyway?" CONFIRM
        else
            warn "Only ${BLOCK_LINES} entries — looks incomplete."
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
        log "Old blocklist removed. Backup: ${BACKUP}"
    else
        sudo cp "$HOSTS_FILE" "$BACKUP"
        log "Backup: ${BACKUP}"
    fi

    log "Downloading StevenBlack blocklist..."
    if ! curl -fsSL "$HOSTS_URL" -o "$TMP_HOSTS"; then
        rm -f "$TMP_HOSTS"
        die "Failed to download StevenBlack hosts!"
    fi

    local SHA256
    SHA256=$(shasum -a 256 "$TMP_HOSTS" | awk '{print $1}')
    info "SHA-256: ${SHA256}"

    local LATEST_COMMIT
    LATEST_COMMIT=$(curl -fsSL \
        "https://api.github.com/repos/StevenBlack/hosts/commits?path=hosts&per_page=1" \
        2>/dev/null | grep '"sha"' | head -1 | awk -F'"' '{print $4}' | cut -c1-7 \
        || echo "unknown")
    info "Latest GitHub commit: ${LATEST_COMMIT}"
    info "Verify at: https://github.com/StevenBlack/hosts/commits/master/hosts"

    {
        printf "\n%s\n" "$MARKER"
        printf "# Added:   %s\n" "$(date)"
        printf "# Source:  %s\n" "$HOSTS_URL"
        printf "# SHA-256: %s\n" "$SHA256"
        printf "# Commit:  %s\n" "$LATEST_COMMIT"
        cat "$TMP_HOSTS"
    } | sudo tee -a "$HOSTS_FILE" > /dev/null

    rm -f "$TMP_HOSTS"
    sudo dscacheutil -flushcache \
        && sudo killall -HUP mDNSResponder 2>/dev/null \
        || true

    local TOTAL
    TOTAL=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo "?")
    log "/etc/hosts updated. Blocked domains: ${TOTAL}"
}

disable_hosts_blocklist() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_FILE="/etc/hosts"

    if ! grep -qF "$MARKER" "$HOSTS_FILE" 2>/dev/null; then
        log "No StevenBlack marker in ${HOSTS_FILE} — nothing to remove."
        return 0
    fi

    local BACKUP="/etc/hosts.bak.remove_$(date +%Y%m%d_%H%M%S)"
    log "Removing StevenBlack blocklist from ${HOSTS_FILE}..."
    sudo cp "$HOSTS_FILE" "$BACKUP"
    local LINE_NUM
    LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
    sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" \
        | sudo tee "${HOSTS_FILE}.new" > /dev/null
    sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
    log "Blocklist removed. Backup: ${BACKUP}"
}

# ──────────────────────────────────────────
# TAILSCALE — SPLIT DNS (native macOS)
# ──────────────────────────────────────────
setup_tailscale_resolver() {
    log "Configuring Tailscale split DNS via /etc/resolver/..."
    sudo mkdir -p /etc/resolver

    sudo tee /etc/resolver/ts.net > /dev/null << 'EOF'
nameserver 100.100.100.100
EOF
    log "  [✓] /etc/resolver/ts.net"

    sudo tee /etc/resolver/tailscale.com > /dev/null << 'EOF'
nameserver 100.100.100.100
EOF
    log "  [✓] /etc/resolver/tailscale.com"

    echo ""
    info "Tailscale MagicDNS must be disabled to prevent it overriding system DNS:"
    info "  tailscale set --accept-dns=false"
    echo ""

    if command -v tailscale &>/dev/null; then
        ask "Run 'tailscale set --accept-dns=false' now?" CONFIRM
        if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
            tailscale set --accept-dns=false \
                && log "  [✓] Tailscale accept-dns=false" \
                || warn "  tailscale command failed — run manually"
        fi
    else
        warn "  Tailscale CLI not found — skip or install Tailscale first."
    fi

    echo ""
    log "Verify: scutil --dns | grep -A3 'ts.net'"
}

disable_tailscale_resolver() {
    log "Removing Tailscale split DNS resolver files..."
    sudo rm -f /etc/resolver/ts.net /etc/resolver/tailscale.com
    log "  [✓] /etc/resolver/ts.net removed"
    log "  [✓] /etc/resolver/tailscale.com removed"
    info "To re-enable Tailscale MagicDNS: tailscale set --accept-dns=true"
}

# ──────────────────────────────────────────
# HEALTH CHECK — 6 tests
# ──────────────────────────────────────────
verify_dns_stack() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║       DNS Stack Health Check             ║"
    echo "  ║       netlib-simple v1.0                 ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""

    local PASS=0 FAIL=0

    _chk() {
        local ID="$1" DESC="$2" CMD="$3" EXPECT="$4"
        local OUT
        OUT=$(eval "$CMD" 2>/dev/null || true)
        if echo "$OUT" | grep -qE "$EXPECT"; then
            log "  [${ID}] ${DESC} ✓"
            (( PASS++ )) || true
        else
            err "  [${ID}] ${DESC}"
            info "       Expected: '${EXPECT}'"
            info "       Got:      $(echo "$OUT" | head -1 || echo '<empty>')"
            (( FAIL++ )) || true
        fi
    }

    _chk "1" "Quad9 DoH Profile active" \
        "scutil --dns" \
        "9\.9\.9"

    _chk "2" "Quad9 DoH reachability (on.quad9.net)" \
        "curl -s --max-time 5 https://on.quad9.net" \
        "[Yy]es"

    local DNS_OUT
    DNS_OUT=$(timeout 3 dig google.com @8.8.8.8 2>/dev/null || true)
    if echo "$DNS_OUT" | grep -q "NOERROR"; then
        err "  [3] Plain DNS blocked (@8.8.8.8:53)"
        info "       pf DNS lock may not be active — run option [1]"
        (( FAIL++ )) || true
    else
        log "  [3] Plain DNS blocked (@8.8.8.8:53) ✓"
        (( PASS++ )) || true
    fi

    _chk "4" "pf firewall enabled" \
        "sudo pfctl -s info" \
        "Enabled"

    _chk "5" "Tailscale split DNS (/etc/resolver/ts.net)" \
        "scutil --dns" \
        "ts\.net"

    local HOSTS_COUNT
    HOSTS_COUNT=$(grep -c "^0\.0\.0\.0" /etc/hosts 2>/dev/null || echo 0)
    if [[ "$HOSTS_COUNT" -gt 1000 ]]; then
        log "  [6] StevenBlack hosts (${HOSTS_COUNT} entries) ✓"
        (( PASS++ )) || true
    else
        err "  [6] StevenBlack hosts (${HOSTS_COUNT} entries — run option [2])"
        (( FAIL++ )) || true
    fi

    echo ""
    echo "  ──────────────────────────────────────────"
    echo "  Results: ${PASS}/6 passed   ${FAIL} failed"
    echo "  ──────────────────────────────────────────"
    echo ""
    if [[ "$FAIL" -eq 0 ]]; then
        log "All checks passed. Stack is healthy ✓"
    else
        warn "${FAIL} check(s) failed — see details above."
    fi
    echo ""
}

# ──────────────────────────────────────────
# RESET
# ──────────────────────────────────────────
reset_net_hardening() {
    log "Resetting network hardening..."
    warn "This will remove: pf DNS lock, StevenBlack hosts, Tailscale resolver."
    ask "Are you sure?" CONFIRM_RESET
    if [[ "$CONFIRM_RESET" != "y" && "$CONFIRM_RESET" != "Y" ]]; then
        log "Reset aborted."; return 0
    fi

    disable_pf_dns_lock
    disable_hosts_blocklist
    disable_tailscale_resolver

    sudo dscacheutil -flushcache \
        && sudo killall -HUP mDNSResponder 2>/dev/null \
        || true

    log "Network hardening reset complete."
    info "DNS cache flushed. System DNS back to default."
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
    echo "  ║    macOS Network Hardening — Simple      ║"
    echo "  ║          v1.0  ·  by Gr3y-foX            ║"
    echo "  ║      ARM/M-chip  |  user-friendly        ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  No external daemons. No dnscrypt.       ║"
    echo "  ║  ClearVPN + Tailscale compatible.        ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  [!] Unauthorized use is prohibited.     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    warn "This module modifies network settings. Sudo required for pf and hosts."
    echo ""
    ask "Continue?" CONFIRM
    [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
    echo ""

    ask "Create backup snapshot before proceeding?" CONFIRM_BK
    if [[ "$CONFIRM_BK" == "y" || "$CONFIRM_BK" == "Y" ]]; then
        create_net_backup
    else
        warn "Skipping backup."
        echo ""
    fi

    while true; do
        echo "  ╔══════════════════════════════════════════╗"
        echo "  ║         Network Hardening Menu           ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [0]  Quad9 DoH Profile install guide   ║"
        echo "  ║       (DNSSEC + malware filter)          ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [1]  Enable pf DNS leak lock            ║"
        echo "  ║       (block port 53/853, IPv4 + IPv6)   ║"
        echo "  ║  [2]  Update /etc/hosts blocklist        ║"
        echo "  ║       (StevenBlack ~100k domains)        ║"
        echo "  ║  [3]  Setup Tailscale split DNS          ║"
        echo "  ║       (/etc/resolver/ — no daemons)      ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [4]  DNS Stack Health Check (6 tests)  ║"
        echo "  ║  [5]  Reset all network hardening        ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [6]  Quit                               ║"
        echo "  ╚══════════════════════════════════════════╝"
        echo ""
        read -rp "  Choice (0-6): " CHOICE
        echo ""

        case "$CHOICE" in
            0) guide_quad9_profile ;;
            1)
                log "[1] pf DNS leak lock"
                prepare_pf_dns_lock_anchor
                enable_pf_dns_lock
                echo ""
                ;;
            2)
                log "[2] StevenBlack /etc/hosts blocklist"
                update_hosts
                echo ""
                ;;
            3)
                log "[3] Tailscale split DNS"
                setup_tailscale_resolver
                echo ""
                ;;
            4) verify_dns_stack ;;
            5)
                reset_net_hardening
                echo ""
                ;;
            6)
                echo "  Done. Stay safe. 🔒"
                exit 0
                ;;
            *)
                warn "Invalid choice. Select 0-6."
                echo ""
                ;;
        esac
    done
}

if [[ "${0##*/}" == "netlib-simple.sh" ]]; then
    main
fi

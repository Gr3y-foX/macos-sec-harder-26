#!/bin/bash
# ============================================================
#  macOS Advanced Security Hardening Script
#  Based on: github.com/drduh/macOS-Security-and-Privacy-Guide
#  Author: Grey Fox
# ============================================================

if [[ "$EUID" -eq 0 ]]; then
    echo "Do not run as root. Homebrew will break."; exit 1
fi

trap 'err "Unexpected error on line $LINENO. Continuing..."' ERR

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

ask() {
    local PROMPT="$1" VAR="$2"
    if [[ -t 0 ]]; then
        read -rp "    ${PROMPT} (y/N): " "$VAR"
    else
        warn "Non-interactive — skipping: $PROMPT"
        eval "$VAR=N"
    fi
}

install_formula() {
    local pkg="$1"
    if brew list --formula --versions "$pkg" &>/dev/null; then
        warn "${pkg} already installed: $(brew list --formula --versions "$pkg")"
        ask "Reinstall ${pkg}?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew reinstall "$pkg" \
            || { log "Skipping ${pkg}."; return 0; }
    else
        log "Installing ${pkg}..."
        brew install "$pkg" || err "Failed to install ${pkg}!"
    fi
}

# ──────────────────────────────────────────
# CHECKING DEPENDENCIES
# ──────────────────────────────────────────
check_requirements() {
    log "Checking requirements..."
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        log "Homebrew: $(brew --version | head -1)"
    fi
    command -v curl &>/dev/null || { err "curl not found!"; exit 1; }
}

# ──────────────────────────────────────────
# CHECKING THE INTERNET
# ──────────────────────────────────────────
check_connectivity() {
    log "Checking connectivity..."
    if ! curl -fsSL --max-time 8 https://formulae.brew.sh > /dev/null 2>&1; then
        err "No internet or DNS broken!"
        info "Quick fix: sudo networksetup -setdnsservers Wi-Fi 1.1.1.1"
        exit 1
    fi
    log "Connectivity OK."
}

# ──────────────────────────────────────────
# CASK INSTALLATION — checks brew, /Applications, and deprecated status
# ──────────────────────────────────────────
install_cask() {
    local pkg="$1"
    local label="${2:-$1}"
    local app_path="${3:-}"  # опциональный путь к .app

    # Check: deprecated cask?
    local CASK_INFO
    CASK_INFO=$(brew info --cask "$pkg" 2>/dev/null)
    if echo "$CASK_INFO" | grep -qi "deprecated\|disabled"; then
        warn "${label} cask is DEPRECATED/DISABLED in Homebrew."
        info "  Reason: $(echo "$CASK_INFO" | grep -i 'deprecated\|disabled' | head -1 | xargs)"
        ask "Install anyway (may be unmaintained)?" CONFIRM
        [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { log "Skipping ${label}."; return 0; }
    fi

    # Check: Already in Brew?
    if brew list --cask "$pkg" &>/dev/null; then
        warn "${label} already installed via Homebrew."
        ask "Reinstall ${label}?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew reinstall --cask "$pkg" \
            || { log "Skipping ${label}."; return 0; }
        return 0
    fi

    # Check: Is it already in /Applications (installed manually)?
    if [[ -n "$app_path" && -d "$app_path" ]]; then
        warn "${label} already installed at ${app_path} (manual install, not via Homebrew)."
        ask "Reinstall via Homebrew anyway? (will overwrite)" CONFIRM
        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            log "Skipping ${label} — using existing install."
            return 0
        fi
        # Homebrew requires the --force option to overwrite an existing .app file
        log "Installing ${label} with --force (overwrite existing)..."
        brew install --cask --force "$pkg" \
            && log "${label} installed." \
            || err "Failed. Try: brew install --cask --force ${pkg}"
        return 0
    fi

    log "Installing ${label}..."
    brew install --cask "$pkg" \
        && log "${label} installed." \
        || err "Failed to install ${label}! Manual: https://objective-see.org"
}



# ──────────────────────────────────────────
# FIREWALL
# ──────────────────────────────────────────
configure_firewall() {
    local FW="/usr/libexec/ApplicationFirewall/socketfilterfw"
    log "Checking firewall state..."
    local STATE
    STATE=$(sudo "$FW" --getglobalstate 2>/dev/null)
    if echo "$STATE" | grep -q "enabled"; then
        warn "Firewall already enabled."
        ask "Reconfigure stealth/signing settings anyway?" CONFIRM
        [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { log "Skipping firewall."; return 0; }
    fi
    sudo "$FW" --setglobalstate on
    sudo "$FW" --setstealthmode on
    sudo "$FW" --setallowsigned off
    sudo "$FW" --setallowsignedapp off
    sudo pkill -HUP socketfilterfw 2>/dev/null || true
    log "Firewall: ON | Stealth: ON | Signed apps: BLOCKED"
}


# ──────────────────────────────────────────
# DNSCRYPT-PROXY
# ──────────────────────────────────────────
configure_dnscrypt() {
    install_formula "dnscrypt-proxy"
    local STATUS
    STATUS=$(sudo brew services list 2>/dev/null | awk '/dnscrypt-proxy/{print $2}')
    if [[ "$STATUS" == "started" ]]; then
        warn "dnscrypt-proxy already running."
        ask "Restart service?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && sudo brew services restart dnscrypt-proxy \
            || { log "Skipping restart."; return 0; }
    else
        log "Starting dnscrypt-proxy..."
        sudo brew services start dnscrypt-proxy
    fi
    sleep 2
    log "Verifying DNS listener on UDP:5355..."
    if sudo lsof +c 15 -Pni UDP:5355 2>/dev/null | grep -q dnscrypt; then
        log "dnscrypt-proxy confirmed listening."
    else
        warn "dnscrypt-proxy not detected on UDP:5355 — check manually."
    fi
}

# ──────────────────────────────────────────
# HOSTS — 50-line test + idempotent update
# ──────────────────────────────────────────
update_hosts() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_URL="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    local HOSTS_FILE="/etc/hosts"
    local BACKUP="/etc/hosts.bak.$(date +%Y%m%d_%H%M%S)"
    local MIN_LINES=50

    log "Checking /etc/hosts..."

    # Have you already set up a blocklist?
    if grep -qF "$MARKER" "$HOSTS_FILE"; then
        local BLOCK_LINES
        BLOCK_LINES=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo 0)
        warn "StevenBlack blocklist found. Blocked domains: ${BLOCK_LINES}"

        if [[ "$BLOCK_LINES" -ge "$MIN_LINES" ]]; then
            info "Blocklist has ${BLOCK_LINES} entries (≥ ${MIN_LINES} threshold) — looks healthy."
            ask "Update to latest version anyway?" CONFIRM
        else
            warn "Blocklist has only ${BLOCK_LINES} entries (< ${MIN_LINES}) — looks incomplete!"
            ask "Re-download blocklist?" CONFIRM
        fi

        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            log "Skipping hosts update."
            return 0
        fi

        # Removing the old block (BSD-compatible)
        local LINE_NUM
        LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
        sudo cp "$HOSTS_FILE" "$BACKUP"
        sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" | sudo tee "${HOSTS_FILE}.new" > /dev/null
        sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
        log "Old blocklist removed. Backup: $BACKUP"
    else
        # No blocklist—checking the total file size
        local TOTAL_LINES
        TOTAL_LINES=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
        if [[ "$TOTAL_LINES" -ge "$MIN_LINES" ]]; then
            warn "/etc/hosts has ${TOTAL_LINES} lines — likely has custom config."
            info "Custom entries (will be preserved above marker):"
            grep -v "^#\|^[[:space:]]*$" "$HOSTS_FILE" | head -30 || true
            ask "Add StevenBlack blocklist below existing content?" CONFIRM
            [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { log "Skipping hosts update."; return 0; }
        fi
        sudo cp "$HOSTS_FILE" "$BACKUP"
        log "Backup: $BACKUP"
    fi

    log "Downloading StevenBlack blocklist..."
    {
        printf "\n%s\n" "$MARKER"
        printf "# Added: %s\n" "$(date)"
        printf "# Source: %s\n" "$HOSTS_URL"
        curl -fsSL "$HOSTS_URL"
    } | sudo tee -a "$HOSTS_FILE" > /dev/null

    local TOTAL
    TOTAL=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo "?")
    log "/etc/hosts updated. Blocked domains: ${TOTAL}"
}

# ──────────────────────────────────────────
# PRIVOXY — FIXED: sudo for networksetup
# ──────────────────────────────────────────
configure_privoxy() {
    install_formula "privoxy"

    local STATUS
    STATUS=$(brew services list | awk '/privoxy/{print $2}')
    if [[ "$STATUS" == "started" ]]; then
        warn "Privoxy already running."
        ask "Restart?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] && brew services restart privoxy || true
    else
        brew services start privoxy
    fi

    log "Configuring proxy on active network interfaces..."
    local SERVICES
    # Remove the asterisk (*) from disabled interfaces
    SERVICES=$(networksetup -listallnetworkservices 2>/dev/null \
        | tail -n +2 \
        | grep -v "^\*")

    while IFS= read -r SERVICE; do
        [[ -z "$SERVICE" ]] && continue
        local CURRENT
        CURRENT=$(networksetup -getwebproxy "$SERVICE" 2>/dev/null \
            | awk '/Server:/{print $2}')
        if [[ "$CURRENT" == "127.0.0.1" ]]; then
            warn "Proxy already set on: $SERVICE"
        else
            # networksetup requires sudo for system settings
            sudo networksetup -setwebproxy "$SERVICE" 127.0.0.1 8118 2>/dev/null \
                && sudo networksetup -setsecurewebproxy "$SERVICE" 127.0.0.1 8118 2>/dev/null \
                && log "Proxy set on: $SERVICE" \
                || warn "Could not set proxy on: $SERVICE (skipping)"
        fi
    done <<< "$SERVICES"
}



# ──────────────────────────────────────────
# OBJECTIVE-SEE + LYNIS
# ──────────────────────────────────────────
install_security_tools() {
    log "Installing security tools..."

    install_cask "lulu"           "LuLu Firewall"           "/Applications/LuLu.app"
    install_cask "blockblock"     "BlockBlock"              "/Applications/BlockBlock.app"
    install_cask "knockknock"     "KnockKnock"              "/Applications/KnockKnock.app"
    install_cask "do-not-disturb" "DoNotDisturb"            "/Applications/DoNotDisturb.app"
    install_formula "lynis"

    # ── pip-audit via pipx (more stable than the brew formula at python@3.14) ──
    log "Installing pip-audit via pipx..."
    install_formula "pipx"
    if command -v pip-audit &>/dev/null; then
        warn "pip-audit already installed: $(pip-audit --version 2>/dev/null)"
        ask "Upgrade pip-audit?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] && pipx upgrade pip-audit
    else
        pipx install pip-audit \
            && log "pip-audit installed: $(pip-audit --version)" \
            || err "Failed to install pip-audit via pipx!"
    fi
    # Make sure that the pipx bin directory is in the PATH for Lynis
    pipx ensurepath > /dev/null 2>&1 || true

    # ── brew-vulns (offical Homebrew tap, not formula) ──────────────
    log "Checking brew-vulns (CVE scanner for Homebrew)..."
    if brew tap | grep -q "homebrew/brew-vulns"; then
        warn "brew-vulns tap already added."
    else
        brew tap homebrew/brew-vulns \
            && log "brew-vulns tap added." \
            || err "Failed to tap homebrew/brew-vulns!"
    fi
    # brew-vulns это subcommand, not formula — check via brew vulns --version
    if brew vulns --version &>/dev/null 2>&1; then
        warn "brew-vulns already installed: $(brew vulns --version 2>/dev/null)"
        ask "Update brew-vulns?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew upgrade homebrew/brew-vulns/brew-vulns \
            || log "Skipping brew-vulns update."
    else
        brew install homebrew/brew-vulns/brew-vulns \
            && log "brew-vulns installed. Run: brew vulns" \
            || err "Failed to install brew-vulns!"
    fi

    # ── Mergen (GitHub release, not in brew) ───────────────────────────
    log "Checking Mergen Security Auditor..."
    if [[ -d "/Applications/Mergen.app" ]]; then
        warn "Mergen already installed at /Applications/Mergen.app."
        ask "Reinstall latest from GitHub?" CONFIRM
        [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { log "Skipping Mergen."; }
    else
        ask "Install Mergen (download from GitHub releases)?" CONFIRM
        if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
            local MERGEN_URL="https://github.com/sametsazak/mergen/releases/latest/download/Mergen.dmg"
            local MERGEN_DMG="/tmp/Mergen.dmg"
            log "Downloading Mergen..."
            if curl -fsSL -o "$MERGEN_DMG" "$MERGEN_URL"; then
                hdiutil attach "$MERGEN_DMG" -quiet
                cp -R "/Volumes/Mergen/Mergen.app" /Applications/ 2>/dev/null \
                    && log "Mergen installed to /Applications/Mergen.app" \
                    || err "Could not copy Mergen.app — mount manually: open $MERGEN_DMG"
                hdiutil detach "/Volumes/Mergen" -quiet 2>/dev/null || true
                rm -f "$MERGEN_DMG"
            else
                err "Download failed. Manual install: https://github.com/sametsazak/mergen/releases"
            fi
        else
            log "Skipping Mergen."
        fi
    fi
}

# ──────────────────────────────────────────
# MISC DEFAULTS — Syntax CORRECTED (without associative arrays)
# ──────────────────────────────────────────
apply_defaults() {
    log "Applying macOS privacy defaults..."

    # Screensaver — require password immediately
    defaults write com.apple.screensaver askForPassword -int 1
    defaults write com.apple.screensaver askForPasswordDelay -int 0

    # Crash reporter — disable dialog
    defaults write com.apple.CrashReporter DialogType -string "none"

    # Finder — Show hidden files and extensions
    defaults write com.apple.finder AppleShowAllFiles -bool true
    defaults write NSGlobalDomain AppleShowAllExtensions -bool true

    # Do not save documents to iCloud by default
    defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false

    # Show ~/Library in Finder
    chflags nohidden ~/Library

    warn "Finder needs restart to apply display changes."
    ask "Restart Finder now?" CONFIRM
    [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] && killall Finder 2>/dev/null || true

    log "Defaults applied."
}


# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
clear
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   macOS Security Hardening Script    ║"
echo "  ║         by Archont / drduh            ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
warn "This script modifies system settings. Sudo required."
ask "Continue?" CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
echo ""

check_requirements
check_connectivity
configure_firewall
configure_dnscrypt
update_hosts
configure_privoxy
install_security_tools
apply_defaults

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║          MANUAL STEPS REMAIN         ║"
echo "  ╚══════════════════════════════════════╝"
info "1. Quad9 DNS profile:"
echo "     https://docs.quad9.net/assets/mobileconfig/Quad9_Secured_DNS_over_HTTPS_ECS_20260119.mobileconfig"
info "2. OpenVPN client: https://openvpn.net/client/"
info "3. VPN leak check: https://timbrica.com/en/vpn-checker"
info "4. Pareto Security: https://paretosecurity.com/apps"
info "5. Lynis audit:    sudo lynis audit system"
info "6. CVE scan installed packages: brew vulns"
info "6. Run package CVE audit: pip-audit"
info "7. CIS Benchmark audit:         open /Applications/Mergen.app"
echo ""
log "Done. Stay paranoid. 🔒"
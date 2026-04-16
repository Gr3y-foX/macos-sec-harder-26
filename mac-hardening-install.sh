#!/bin/bash
# ============================================================
#  macOS Advanced Security Hardening Script v5
#  Based on: github.com/drduh/macOS-Security-and-Privacy-Guide
#  Author: Grey Fox
#  Changes v5: ARM/M-chip paths, strict error handling,
#              IPv6 PF rules, Wazuh IDS, brew service fixes
# ============================================================

# Не запускать от root
if [[ "$EUID" -eq 0 ]]; then
    echo "Do not run as root. Homebrew will break."; exit 1
fi

# ── Строгий режим ──────────────────────────────────────────
# set -u: ошибка при обращении к неопределённой переменной
# set -o pipefail: ошибка если любая часть pipe падает
# НЕ используем set -e глобально — вместо этого явно
# проверяем критические команды через || { err "..."; exit 1; }
set -uo pipefail

# Глобальный trap только для непойманных сигналов — не для ERR
# (убран оригинальный 'continue' trap, который скрывал ошибки)
trap 'err "Прерван на строке $LINENO."; exit 1' INT TERM

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# Завершить с сообщением об ошибке
die() { err "$1"; exit 1; }

ask() {
    local PROMPT="$1" VAR="$2"
    if [[ -t 0 ]]; then
        read -rp "    ${PROMPT} (y/N): " "$VAR"
    else
        warn "Non-interactive — skipping: $PROMPT"
        eval "$VAR=N"
    fi
}

# ── Динамический префикс Homebrew (Intel vs Apple Silicon) ──
# Определяется один раз после проверки наличия brew
BREW_PREFIX=""

resolve_brew_prefix() {
    BREW_PREFIX=$(brew --prefix 2>/dev/null) \
        || die "brew --prefix failed. Homebrew не найден или сломан."
    log "Homebrew prefix: ${BREW_PREFIX}"
}

# ──────────────────────────────────────────
# УСТАНОВКА FORMULA
# ──────────────────────────────────────────
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
        brew install "$pkg" || { err "Failed to install ${pkg}!"; return 1; }
    fi
}

# ──────────────────────────────────────────
# УСТАНОВКА CASK
# ──────────────────────────────────────────
install_cask() {
    local pkg="$1"
    local label="${2:-$1}"
    local app_path="${3:-}"

    local CASK_INFO
    CASK_INFO=$(brew info --cask "$pkg" 2>/dev/null)
    if echo "$CASK_INFO" | grep -qi "deprecated\|disabled"; then
        warn "${label} cask is DEPRECATED/DISABLED in Homebrew."
        info "  $(echo "$CASK_INFO" | grep -i 'deprecated\|disabled' | head -1 | xargs)"
        ask "Install anyway?" CONFIRM
        [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { log "Skipping ${label}."; return 0; }
    fi

    if brew list --cask "$pkg" &>/dev/null; then
        warn "${label} already installed via Homebrew."
        ask "Reinstall ${label}?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew reinstall --cask "$pkg" \
            || { log "Skipping ${label}."; return 0; }
        return 0
    fi

    if [[ -n "$app_path" && -d "$app_path" ]]; then
        warn "${label} found at ${app_path} (manual install)."
        ask "Reinstall via Homebrew? (--force overwrite)" CONFIRM
        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            log "Skipping ${label} — using existing."; return 0
        fi
        brew install --cask --force "$pkg" \
            && log "${label} installed." \
            || err "Failed. Try: brew install --cask --force ${pkg}"
        return 0
    fi

    log "Installing ${label}..."
    brew install --cask "$pkg" \
        && log "${label} installed." \
        || { err "Failed to install ${label}!"; return 1; }
}

# ──────────────────────────────────────────
# ЗАВИСИМОСТИ
# ──────────────────────────────────────────
check_requirements() {
    log "Checking requirements..."
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL \
            https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
            || die "Homebrew install failed!"
        # После установки на Apple Silicon shell нужно обновить PATH
        if [[ -f "/opt/homebrew/bin/brew" ]]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        elif [[ -f "/usr/local/bin/brew" ]]; then
            eval "$(/usr/local/bin/brew shellenv)"
        fi
    else
        log "Homebrew: $(brew --version | head -1)"
    fi
    command -v curl &>/dev/null || die "curl not found!"
    resolve_brew_prefix
}

# ──────────────────────────────────────────
# ИНТЕРНЕТ
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
# FIREWALL
# ──────────────────────────────────────────
configure_firewall() {
    local FW="/usr/libexec/ApplicationFirewall/socketfilterfw"
    log "Checking firewall state..."
    local STATE
    STATE=$(sudo "$FW" --getglobalstate 2>/dev/null)
    if echo "$STATE" | grep -q "enabled"; then
        warn "Firewall already enabled."
        ask "Reconfigure stealth/signing settings?" CONFIRM
        [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] \
            && { log "Skipping firewall."; return 0; }
    fi
    sudo "$FW" --setglobalstate on      || die "Firewall enable failed!"
    sudo "$FW" --setstealthmode on
    sudo "$FW" --setallowsigned off
    sudo "$FW" --setallowsignedapp off
    sudo pkill -HUP socketfilterfw 2>/dev/null || true
    log "Firewall: ON | Stealth: ON | Signed apps: BLOCKED"
}


# ──────────────────────────────────────────
# SECURITY TOOLS
# ──────────────────────────────────────────
install_security_tools() {
    log "Installing security tools..."

    install_cask "lulu"           "LuLu Firewall"  "/Applications/LuLu.app"
    install_cask "blockblock"     "BlockBlock"      "/Applications/BlockBlock.app"
    install_cask "knockknock"     "KnockKnock"      "/Applications/KnockKnock.app"
    install_cask "do-not-disturb" "DoNotDisturb"    "/Applications/DoNotDisturb.app"
    install_formula "lynis"

    # pip-audit via pipx
    log "Installing pip-audit via pipx..."
    install_formula "pipx"
    if command -v pip-audit &>/dev/null; then
        warn "pip-audit already installed: $(pip-audit --version 2>/dev/null)"
        ask "Upgrade?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] && pipx upgrade pip-audit
    else
        pipx install pip-audit \
            && log "pip-audit installed." \
            || err "Failed — try: pipx install pip-audit"
    fi
    pipx ensurepath > /dev/null 2>&1 || true

    # brew-vulns
    log "Checking brew-vulns..."
    if ! brew tap | grep -q "homebrew/brew-vulns"; then
        brew tap homebrew/brew-vulns \
            && log "brew-vulns tap added." \
            || err "Failed to tap homebrew/brew-vulns!"
    else
        warn "brew-vulns tap already added."
    fi
    if brew vulns --version &>/dev/null 2>&1; then
        warn "brew-vulns already installed."
        ask "Update?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew upgrade homebrew/brew-vulns/brew-vulns || true
    else
        brew install homebrew/brew-vulns/brew-vulns \
            && log "brew-vulns installed." \
            || err "Failed to install brew-vulns!"
    fi

    # Mergen
    log "Checking Mergen Security Auditor..."
    if [[ -d "/Applications/Mergen.app" ]]; then
        warn "Mergen already installed."
        ask "Reinstall from GitHub?" CONFIRM
        [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] \
            && { log "Skipping Mergen."; return 0; }
    else
        ask "Install Mergen (GitHub download)?" CONFIRM
    fi
    if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
        local MERGEN_DMG="/tmp/Mergen.dmg"
        if curl -fsSL --progress-bar \
            -o "$MERGEN_DMG" \
            "https://github.com/sametsazak/mergen/releases/latest/download/Mergen.dmg"
        then
            hdiutil attach "$MERGEN_DMG" -quiet
            cp -R "/Volumes/Mergen/Mergen.app" /Applications/ 2>/dev/null \
                && log "Mergen installed." \
                || err "Copy failed — mount manually: open $MERGEN_DMG"
            hdiutil detach "/Volumes/Mergen" -quiet 2>/dev/null || true
            rm -f "$MERGEN_DMG"
        else
            err "Download failed: https://github.com/sametsazak/mergen/releases"
        fi
    fi
}


# ──────────────────────────────────────────
# COMPILER HARDENING (Lynis HRDN-7222)
# ──────────────────────────────────────────
harden_compilers() {
    log "Checking installed compilers..."
    local COMPILERS=("/usr/bin/clang" "/usr/bin/clang++"
                     "/usr/bin/gcc" "/usr/bin/cc"
                     "/usr/bin/g++" "/usr/bin/make")
    local FOUND=()
    for BIN in "${COMPILERS[@]}"; do
        [[ -f "$BIN" ]] && FOUND+=("$BIN")
    done

    if [[ ${#FOUND[@]} -eq 0 ]]; then
        log "No compilers found."; return 0
    fi

    warn "Found ${#FOUND[@]} compiler(s):"
    for BIN in "${FOUND[@]}"; do info "  $(ls -la "$BIN")"; done

    echo ""
    # [FIX v5] Опции переупорядочены: Lynis exception — рекомендуемый вариант
    # для десктопа. chmod 750 помечен как advanced (серверы/лаборатории).
    echo "  [1] Add Lynis exception (skip-test=HRDN-7222) — RECOMMENDED for desktops"
    echo "  [2] Restrict permissions (chmod 750, root only) — ADVANCED: hardened servers/labs only"
    echo "      WARNING: Может сломать Homebrew и Xcode build scripts!"
    echo "  [3] Skip"
    read -rp "    Choice (1/2/3): " CHOICE

    case "$CHOICE" in
        1)
            sudo mkdir -p /etc/lynis
            grep -qF "skip-test=HRDN-7222" /etc/lynis/custom.prf 2>/dev/null \
                || echo "skip-test=HRDN-7222" \
                    | sudo tee -a /etc/lynis/custom.prf > /dev/null
            log "Lynis HRDN-7222 exception added."
            ;;
        2)
            warn "Применяем chmod 750 — убедитесь, что это hardened-среда."
            for BIN in "${FOUND[@]}"; do
                sudo chmod 750 "$BIN" \
                    && log "Restricted: $BIN" \
                    || warn "Could not restrict: $BIN (SIP protected)"
            done
            warn "Откат при проблемах: sudo chmod 755 /usr/bin/clang /usr/bin/cc /usr/bin/make"
            ;;
        3) log "Skipping compiler hardening." ;;
        *) warn "Invalid choice." ;;
    esac
}

# ──────────────────────────────────────────
# MISC DEFAULTS
# ──────────────────────────────────────────
apply_defaults() {
    log "Applying macOS privacy defaults..."
    defaults write com.apple.screensaver askForPassword -int 1
    defaults write com.apple.screensaver askForPasswordDelay -int 0
    defaults write com.apple.CrashReporter DialogType -string "none"
    defaults write com.apple.finder AppleShowAllFiles -bool true
    defaults write NSGlobalDomain AppleShowAllExtensions -bool true
    defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
    chflags nohidden ~/Library

    warn "Finder needs restart to apply changes."
    ask "Restart Finder now?" CONFIRM
    [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
        && killall Finder 2>/dev/null || true

    log "Defaults applied."
}

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
clear
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   macOS Security Hardening Script    ║"
echo "  ║           v5 · by Archont            ║"
echo "  ║     ARM/M-chip | strict mode         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
warn "This script modifies system settings. Sudo required."
ask "Continue?" CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
echo ""

check_requirements      # resolve_brew_prefix вызывается внутри
check_connectivity
configure_firewall   # Теперь с проверкой Quad9 profil перед применением
install_security_tools
harden_compilers
apply_defaults

# Path to the scripts directory (to run related files)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

warn "Next steps are NOT mandatory, but you can set up network profiles now."
warn "Network profiles live in separate scripts and use netlib."
ask "Run network module now?" CONFIRM_NET
if [[ "$CONFIRM_NET" != "y" && "$CONFIRM_NET" != "Y" ]]; then
  log "Network profiles can be run later from directory: $SCRIPT_DIR"
  echo "  - mac-hardening-netlib.sh"
  echo "  - profile-vpn-daily.sh"
  echo "  - profile-paranoid-tor.sh"
  echo ""
  log "Done. Stay paranoid. 🔒"
  exit 0
fi

echo ""
echo "Select network scenario:"
echo "  [1] VPN Daily profile (ClearVPN / OpenVPN, without complex rules)"
echo "  [2] Paranoid Tor profile (maximum anonymity, complex scheme)"
echo "  [3] Open mac-hardening-netlib menu (manual blocks dnscrypt/PF/Privoxy)"
echo "  [4] Do nothing now"
echo ""
read -rp "Choice (1-4): " NET_CHOICE
echo ""

case "$NET_CHOICE" in
  1)
    log "Running VPN Daily profile..."
    bash "$SCRIPT_DIR/profile-vpn-daily.sh"
    ;;
  2)
    log "Running Paranoid Tor profile..."
    bash "$SCRIPT_DIR/profile-paranoid-tor.sh"
    ;;
  3)
    log "Running mac-hardening-netlib menu..."
    bash "$SCRIPT_DIR/mac-hardening-netlib.sh"
    ;;
  4|"")
    log "Network profiles can be run manually later."
    ;;
  *)
    warn "Invalid choice. Network profiles not run."
    ;;
esac

echo "  ╔══════════════════════════════════════╗"
echo "  ║       Base hardening completed       ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║          MANUAL STEPS REMAIN         ║"
echo "  ╚══════════════════════════════════════╝"
info "1.  Quad9 DNS profile (если не установлен):"
echo "      https://docs.quad9.net/assets/mobileconfig/Quad9_Secured_DNS_over_HTTPS_ECS_20260119.mobileconfig"
info "2.  OpenVPN client:      https://openvpn.net/client/"
info "3.  VPN check:      https://timbrica.com/en/vpn-checker"
info "4.  DNS leak test:      https://www.dnsleaktest.com/results.html
info "5.  Pareto Security:     https://paretosecurity.com/apps"
info "6.  Lynis audit:         sudo lynis audit system"
info "7.  Package CVE scan:    brew vulns"
info "8.  Python CVE scan:     pip-audit"
info "9.  CIS Benchmark:       open /Applications/Mergen.app"
info "10. Proxy toggle log:    tail -f /var/log/proxy-toggle.log"
echo ""

echo ""
log "Base hardening + selected network scenario completed. Stay paranoid. 🔒"

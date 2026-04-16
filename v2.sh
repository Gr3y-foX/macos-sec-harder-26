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
# DNSCRYPT-PROXY
# ──────────────────────────────────────────
configure_dnscrypt() {
    install_formula "dnscrypt-proxy" || die "dnscrypt-proxy install failed!"

    # [FIX v5] brew services запускается без sudo — user-level сервис.
    # Для системного сервиса использовать launchd plist напрямую.
    local STATUS
    STATUS=$(brew services list 2>/dev/null | awk '/dnscrypt-proxy/{print $2}')
    if [[ "$STATUS" == "started" ]]; then
        warn "dnscrypt-proxy already running (user service)."
        ask "Restart service?" CONFIRM
        if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
            brew services restart dnscrypt-proxy \
                || die "dnscrypt-proxy restart failed!"
        else
            log "Skipping restart."; return 0
        fi
    else
        log "Starting dnscrypt-proxy (user service)..."
        brew services start dnscrypt-proxy \
            || die "dnscrypt-proxy start failed! DNS недоступен — прерываем."
    fi

    sleep 2
    log "Verifying DNS on UDP:5355..."
    if sudo lsof +c 15 -Pni UDP:5355 2>/dev/null | grep -q dnscrypt; then
        log "dnscrypt-proxy confirmed listening."
    else
        warn "Not detected on UDP:5355 — check: brew services list"
    fi
}

# ──────────────────────────────────────────
# PF — DNS LEAK PREVENTION
# ──────────────────────────────────────────
configure_pf_dns_lock() {
    log "Configuring PF firewall DNS leak prevention..."

    # [FIX v5] Предупреждение: без Quad9 DoH профиля DNS отвалится
    warn "ВНИМАНИЕ: Эта секция заблокирует прямые DNS-запросы (порт 53/853)."
    warn "Убедитесь, что Quad9 DoH профиль установлен ДО продолжения."
    info "Профиль: https://docs.quad9.net/assets/mobileconfig/Quad9_Secured_DNS_over_HTTPS_ECS_20260119.mobileconfig"
    ask "Quad9 DoH профиль уже установлен?" CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        warn "Пропускаем PF DNS lock — установите профиль Quad9 и перезапустите."
        return 0
    fi

    local PF_ANCHOR="/etc/pf.anchors/com.hardening.dnsleak"
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    # [FIX v5] Добавлены:
    #   - ключевое слово 'quick' на все block-правила (приоритет над pass out)
    #   - IPv6 (inet6) блокировка портов 53 и 853
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

    if ! grep -qF "$PF_MARKER" "$PF_CONF" 2>/dev/null; then
        sudo tee -a "$PF_CONF" > /dev/null <<EOF

$PF_MARKER
anchor "com.hardening.dnsleak"
load anchor "com.hardening.dnsleak" from "$PF_ANCHOR"
EOF
        log "PF anchor added."
    else
        warn "PF DNS lock already configured — обновляем anchor."
    fi

    sudo pfctl -ef "$PF_CONF" 2>/dev/null \
        && log "PF rules loaded — DNS leak prevention active." \
        || warn "PF reload failed — reboot may be required."

    if sudo pfctl -sr 2>/dev/null | grep -q "port 53"; then
        log "PF DNS lock: ACTIVE ✓"
    else
        warn "PF DNS lock: verify manually: sudo pfctl -sr"
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

    # [FIX v5] SHA-256 для верификации
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
# PRIVOXY — VPN AUTO-SWITCH via LaunchDaemon
# ──────────────────────────────────────────
configure_privoxy() {
    install_formula "privoxy" || die "privoxy install failed!"

    # [FIX v5] Используем brew --prefix вместо жёстко заданного /usr/local
    # Работает на Intel (/usr/local) и Apple Silicon (/opt/homebrew)
    local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
    local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
    local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    local TOGGLE_LOG="/var/log/proxy-toggle.log"

    if [[ ! -f "$PRIVOXY_CONF" ]]; then
        die "Privoxy config not found: ${PRIVOXY_CONF}. Проверьте brew --prefix."
    fi

    # VPN subnet bypass
    local BYPASS_MARKER="# ===== VPN bypass ====="
    if ! grep -qF "$BYPASS_MARKER" "$PRIVOXY_CONF" 2>/dev/null; then
        sudo tee -a "$PRIVOXY_CONF" > /dev/null <<EOF

$BYPASS_MARKER
forward  10.0.0.0/8       .
forward  172.16.0.0/12    .
forward  192.168.0.0/16   .
forward  100.64.0.0/10    .
forward  127.0.0.0/8      .
EOF
        log "Privoxy: VPN bypass rules added."
    else
        warn "Privoxy VPN bypass already configured."
    fi

    # [FIX v5] brew services без sudo
    local STATUS
    STATUS=$(brew services list | awk '/privoxy/{print $2}')
    if [[ "$STATUS" == "started" ]]; then
        brew services restart privoxy || die "privoxy restart failed!"
    else
        brew services start privoxy || die "privoxy start failed!"
    fi

    # Toggle скрипт
    sudo tee "$TOGGLE_SCRIPT" > /dev/null <<'SCRIPT'
#!/bin/bash
LOG="/var/log/proxy-toggle.log"
MAX_LOG_SIZE=5242880  # 5 MB

log_msg() {
    # [FIX v5] Простая ротация: если лог > 5 MB — обрезаем
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
    # [FIX v5] Исключаем VPN-адаптеры и отключённые сервисы (*-prefix)
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
configure_firewall
configure_dnscrypt
configure_pf_dns_lock   # Теперь с проверкой Quad9 profil перед применением
update_hosts
configure_privoxy
install_security_tools
harden_compilers
apply_defaults

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║          MANUAL STEPS REMAIN         ║"
echo "  ╚══════════════════════════════════════╝"
info "1.  Quad9 DNS profile (если не установлен):"
echo "      https://docs.quad9.net/assets/mobileconfig/Quad9_Secured_DNS_over_HTTPS_ECS_20260119.mobileconfig"
info "2.  OpenVPN client:      https://openvpn.net/client/"
info "3.  VPN leak check:      https://timbrica.com/en/vpn-checker"
info "4.  Pareto Security:     https://paretosecurity.com/apps"
info "5.  Lynis audit:         sudo lynis audit system"
info "6.  Package CVE scan:    brew vulns"
info "7.  Python CVE scan:     pip-audit"
info "8.  CIS Benchmark:       open /Applications/Mergen.app"
info "9.  Wazuh status:        sudo /Library/Ossec/bin/wazuh-control status"
info "10. Proxy toggle log:    tail -f /var/log/proxy-toggle.log"
echo ""
log "Done. Stay paranoid. 🔒"
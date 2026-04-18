#!/bin/bash
#
# Foxhole-macos — macOS Advanced Security Hardening Script
#
# Version: 0.15 (2026)
# Author:  Gr3y-foX
# Based on: drduh/macOS-Security-and-Privacy-Guide (MIT)
# License: GNU GPL v3 — see LICENSE for details
#
# Overview:
#   Base hardening installer for macOS (Intel + Apple Silicon).
#   Focuses on local system security and safe defaults, without
#   breaking basic network connectivity.
#
# Includes (via Homebrew / casks where applicable):
#   - Objective-See tools (LuLu, BlockBlock, KnockKnock, Do Not Disturb)
#   - lynis, pipx + pip-audit, brew-vulns, Mergen (optional)
#   - dnscrypt-proxy, StevenBlack hosts blocklist (via netlib / profiles)
#
# Notes for v0.15:
#   - Stricter error handling and safer defaults
#   - Fixed brew service handling and checks

# Do not run as root
if [[ "$EUID" -eq 0 ]]; then
    echo "Do not run as root. Homebrew will break."; exit 1
fi


# ── Strict mode ──────────────────────────────────────────
# set -u: error when accessing an undefined variable
# set -o pipefail: error if any part of the pipe fails
# DO NOT use set -e globally — instead, explicitly
# check critical commands using || { err "..."; exit 1; }
set -uo pipefail

# Global trap only for uncaught signals — not for ERR
# (the original 'continue' trap, which hid errors, has been removed)
trap 'err "Interrupted at line $LINENO."; exit 1' INT TERM

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# Cancel with an error message
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

# ── Dynamic Homebrew prefix (Intel vs Apple Silicon) ──  
# Determined once after checking for brew
BREW_PREFIX=""

resolve_brew_prefix() {
    BREW_PREFIX=$(brew --prefix 2>/dev/null) \
        || die "brew --prefix failed. Homebrew not found or broken."
    log "Homebrew prefix: ${BREW_PREFIX}"
}

# ──────────────────────────────────────────
# INSTALL FORMULA
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
# INSTALL CASK
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
# DEPENDENCIES
# ──────────────────────────────────────────
check_requirements() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 1/7: Requirements Check ]     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    log "Checking requirements..."
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL \
            https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
            || die "Homebrew install failed!"
        # After installation on Apple Silicon, shell needs PATH update
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
#  INTERNET
# ──────────────────────────────────────────
check_connectivity() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 2/7: Connectivity Check ]     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    log "Checking connectivity..."
    if ! curl -fsSL --max-time 8 https://formulae.brew.sh > /dev/null 2>&1; then
        err "No internet or DNS broken!"
        info "Quick fix: sudo networksetup -setdnsservers Wi-Fi 1.1.1.1"
        exit 1
    fi
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   ✓  Internet connectivity OK        ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""
}

# ──────────────────────────────────────────
#  FIREWALL
# ──────────────────────────────────────────
configure_firewall() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 3/7: Firewall Config ]        ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
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
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   ✓  Firewall configured             ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""
}

# ──────────────────────────────────────────
# SECURITY TOOLS — STATUS CHECK
# ──────────────────────────────────────────

# List of cask applications to test
SECURITY_CASKS=(
  "lulu"
  "blockblock"
  "knockknock"
  "do-not-disturb"
  "OverSight"
  "pareto-security"
)

# List of formula-checking tools
SECURITY_FORMULAS=(
  "lynis"
  "dnscrypt-proxy"
  "privoxy"
)

# ──────────────────────────────────────────
# OVERSIGHT — install / launch / login item
# ──────────────────────────────────────────
OVERSIGHT_URL="https://objective-see.org/products/downloads.html"
OVERSIGHT_APP="/Applications/OverSight.app"
OVERSIGHT_INSTALLER_ZIP="/tmp/OverSight.zip"

# ──────────────────────────────────────────
# OVERSIGHT — install / launch / login item
# ──────────────────────────────────────────
OVERSIGHT_URL="https://objective-see.org/products/downloads.html"
OVERSIGHT_APP="/Applications/OverSight.app"
OVERSIGHT_INSTALLER_ZIP="/tmp/OverSight.zip"

install_oversight() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 4/7: OverSight Config ]       ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    log "Checking OverSight (mic/webcam monitor)..."

  # ── Check: Is it already installed? ──
  if [[ -d "$OVERSIGHT_APP" ]]; then
    local INSTALLED_VER
    INSTALLED_VER=$(defaults read "${OVERSIGHT_APP}/Contents/Info" \
      CFBundleShortVersionString 2>/dev/null || echo "unknown")
    warn "OverSight already installed: v${INSTALLED_VER}"
    ask "Reinstall / upgrade OverSight?" CONFIRM_OS
    if [[ "$CONFIRM_OS" != "y" && "$CONFIRM_OS" != "Y" ]]; then
      log "Skipping OverSight install — checking run status..."
      _oversight_ensure_running
      return 0
    fi
  else
    ask "Install OverSight (mic/webcam monitor by Objective-See)?" CONFIRM_OS
    if [[ "$CONFIRM_OS" != "y" && "$CONFIRM_OS" != "Y" ]]; then
      log "Skipping OverSight."
      return 0
    fi
  fi

  # ── Download ──
  log "Downloading OverSight..."
  info "Note: OverSight has no Homebrew cask — downloading from objective-see.org"

  # Get direct zip link (parse downloads page)
  local DOWNLOAD_URL
  DOWNLOAD_URL=$(curl -fsSL "$OVERSIGHT_URL" 2>/dev/null \
    | grep -oE 'https://[^"]+OverSight[^"]+\.zip' \
    | head -1)

  if [[ -z "$DOWNLOAD_URL" ]]; then
    warn "Auto-detect failed — using hardcoded fallback URL."
    DOWNLOAD_URL="https://objective-see.org/downloads/OverSight.zip"
  fi

  info "URL: ${DOWNLOAD_URL}"

  if ! curl -fsSL "$DOWNLOAD_URL" -o "$OVERSIGHT_INSTALLER_ZIP"; then
    err "Download failed. Visit manually: ${OVERSIGHT_URL}"
    return 1
  fi

  # SHA-1 check (current version 2.4.0)
  local EXPECTED_SHA1="EBBD36EE98A821A677AE32F16A7097ACC64DE9F9"
  local ACTUAL_SHA1
  ACTUAL_SHA1=$(shasum -a 1 "$OVERSIGHT_INSTALLER_ZIP" | awk '{print toupper($1)}')
  info "SHA-1 expected: ${EXPECTED_SHA1}"
  info "SHA-1 actual:   ${ACTUAL_SHA1}"

  if [[ "$ACTUAL_SHA1" != "$EXPECTED_SHA1" ]]; then
    err "SHA-1 mismatch! Archive may be corrupted or tampered."
    err "Aborting OverSight install."
    rm -f "$OVERSIGHT_INSTALLER_ZIP"
    return 1
  fi
  log "SHA-1 verified ✓"

  # ── Extract and run installer ──
  local UNZIP_DIR="/tmp/OverSight_install"
  rm -rf "$UNZIP_DIR"
  mkdir -p "$UNZIP_DIR"

  unzip -q "$OVERSIGHT_INSTALLER_ZIP" -d "$UNZIP_DIR" \
    || { err "Failed to unzip OverSight archive."; return 1; }

  local INSTALLER_APP
  INSTALLER_APP=$(find "$UNZIP_DIR" -name "OverSight_Installer.app" | head -1)

  if [[ -z "$INSTALLER_APP" ]]; then
    err "OverSight_Installer.app not found in archive."
    return 1
  fi

  warn "Opening OverSight installer — follow on-screen prompts."
  warn "Click 'Install' in the installer window."
  open -W "$INSTALLER_APP"

  # ── Wait for /Applications/OverSight.app to appear ──
  local TIMEOUT=60
  local COUNT=0
  while [[ ! -d "$OVERSIGHT_APP" && $COUNT -lt $TIMEOUT ]]; do
    sleep 1
    (( COUNT++ ))
  done

  if [[ -d "$OVERSIGHT_APP" ]]; then
    log "OverSight installed successfully ✓"
  else
    warn "OverSight.app not found after installer — check manually."
  fi

  # Cleanup
  rm -f "$OVERSIGHT_INSTALLER_ZIP"
  rm -rf "$UNZIP_DIR"

  # ── Check and run ──
  _oversight_ensure_running
}

# ──────────────────────────────────────────
# OVERSIGHT — ensure running + Login Item
# ──────────────────────────────────────────
_oversight_ensure_running() {
  if [[ ! -d "$OVERSIGHT_APP" ]]; then
    warn "OverSight.app not found — skipping run check."
    return 1
  fi

  # Check: is it running?
  if pgrep -x "OverSight" &>/dev/null; then
    log "OverSight: already running ✓"
  else
    warn "OverSight: not running."
    ask "Launch OverSight now?" CONFIRM_LAUNCH
    if [[ "$CONFIRM_LAUNCH" == "y" || "$CONFIRM_LAUNCH" == "Y" ]]; then
      open "$OVERSIGHT_APP" \
        && log "OverSight launched." \
        || warn "Failed to launch OverSight."
      sleep 2
    fi
  fi

  # Check: is it in Login Items? (via osascript)
  local LOGIN_CHECK
  LOGIN_CHECK=$(osascript -e \
    'tell application "System Events" to get the name of every login item' \
    2>/dev/null || echo "")

  if echo "$LOGIN_CHECK" | grep -qi "oversight"; then
    log "OverSight: Login Item present ✓"
  else
    warn "OverSight: NOT in Login Items."
    ask "Add OverSight to Login Items (auto-start at login)?" CONFIRM_LI
    if [[ "$CONFIRM_LI" == "y" || "$CONFIRM_LI" == "Y" ]]; then
      osascript -e \
        "tell application \"System Events\" to make login item \
         at end with properties {path:\"${OVERSIGHT_APP}\", hidden:false}" \
        2>/dev/null \
        && log "OverSight added to Login Items ✓" \
        || warn "Failed via osascript — add manually: System Settings → General → Login Items"
    fi
  fi
}

check_security_tools_status() {
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║       Security Tools Status Check        ║"
  echo "  ╠══════════════════════════════════════════╣"
  echo "  ║  checking installed versions...          ║"
  echo "  ╚══════════════════════════════════════════╝"

  # ── 1. Homebrew formulas ──────────────────
  info "── Homebrew formulas ──"
  for pkg in "${SECURITY_FORMULAS[@]}"; do
    if brew list --formula --versions "$pkg" &>/dev/null; then
      local INSTALLED_VER
      INSTALLED_VER=$(brew list --formula --versions "$pkg" | awk '{print $2}')
      local LATEST_VER
      LATEST_VER=$(brew info --json=v1 "$pkg" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['versions']['stable'])" \
        2>/dev/null || echo "unknown")

      if [[ "$INSTALLED_VER" == "$LATEST_VER" ]]; then
        log "  ${pkg}: ${INSTALLED_VER} ✓ (up to date)"
      else
        warn "  ${pkg}: ${INSTALLED_VER} → update available: ${LATEST_VER}"
        ask "    Upgrade ${pkg} now?" CONFIRM_UPD
        if [[ "$CONFIRM_UPD" == "y" || "$CONFIRM_UPD" == "Y" ]]; then
          brew upgrade "$pkg" \
            && log "  ${pkg} upgraded to ${LATEST_VER}" \
            || warn "  brew upgrade ${pkg} failed"
        else
          log "  Skipping upgrade of ${pkg}."
        fi
      fi
    else
      info "  ${pkg}: not installed"
    fi
  done

  # ── 2. Homebrew casks ────────────────────
  info "── Homebrew casks ──"
  for cask in "${SECURITY_CASKS[@]}"; do
    if brew list --cask "$cask" &>/dev/null 2>&1; then
      local CASK_VER
      CASK_VER=$(brew list --cask --versions "$cask" 2>/dev/null | awk '{print $2}')
      local CASK_LATEST
      CASK_LATEST=$(brew info --cask --json=v2 "$cask" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['casks'][0]['version'])" \
        2>/dev/null || echo "unknown")

      if [[ "$CASK_VER" == "$CASK_LATEST" ]]; then
        log "  ${cask}: ${CASK_VER} ✓ (up to date)"
      else
        warn "  ${cask}: ${CASK_VER} → update available: ${CASK_LATEST}"
        ask "    Upgrade ${cask} now?" CONFIRM_CASK
        if [[ "$CONFIRM_CASK" == "y" || "$CONFIRM_CASK" == "Y" ]]; then
          brew upgrade --cask "$cask" \
            && log "  ${cask} upgraded" \
            || warn "  brew upgrade --cask ${cask} failed"
        else
          log "  Skipping upgrade of ${cask}."
        fi
      fi
    else
      info "  ${cask}: not installed"
    fi
  done

    # ── 5. brew-vulns ────────────────────────
  info "── brew-vulns ──"
  if brew list --formula "brew-vulns" &>/dev/null 2>&1; then
    local BRWV_VER
    BRWV_VER=$(brew list --formula --versions "brew-vulns" \
      | awk '{print $2}')
    local BRWV_LATEST
    BRWV_LATEST=$(brew info --json=v1 "brew-vulns" 2>/dev/null \
      | python3 -c \
        "import sys,json; d=json.load(sys.stdin); \
         print(d[0]['versions']['stable'])" \
      2>/dev/null || echo "unknown")

    if [[ "$BRWV_VER" == "$BRWV_LATEST" ]]; then
      log "  brew-vulns: ${BRWV_VER} ✓ (up to date)"
    else
      warn "  brew-vulns: ${BRWV_VER} → update available: ${BRWV_LATEST}"
      ask "    Upgrade brew-vulns now?" CONFIRM_BV
      if [[ "$CONFIRM_BV" == "y" || "$CONFIRM_BV" == "Y" ]]; then
        brew upgrade "brew-vulns" \
          && log "  brew-vulns upgraded to ${BRWV_LATEST}" \
          || warn "  brew upgrade brew-vulns failed"
      fi
    fi

    # Check: Is it actually possible to call
    if command -v brew-vulns &>/dev/null; then
      log "  brew-vulns: binary accessible ✓"
    else
      warn "  brew-vulns installed but binary not in PATH"
      info "    Fix: brew link brew-vulns"
    fi
  else
    info "  brew-vulns: not installed"
    ask "  Install brew-vulns now?" CONFIRM_BVI
    if [[ "$CONFIRM_BVI" == "y" || "$CONFIRM_BVI" == "Y" ]]; then
      brew install brew-vulns \
        && log "  brew-vulns installed ✓" \
        || warn "  brew install brew-vulns failed"
    fi
  fi
  echo ""

  # ── 6. pip-audit (pipx) — детальная проверка ─
  info "── pip-audit (pipx) ──"
  if command -v pip-audit &>/dev/null; then
    local PIPAUDIT_VER
    PIPAUDIT_VER=$(pip-audit --version 2>/dev/null | awk '{print $2}')
    log "  pip-audit: v${PIPAUDIT_VER} ✓"

    # Check the latest version via pipx
    local PIPAUDIT_LATEST
    PIPAUDIT_LATEST=$(pipx runpip pip-audit list --outdated 2>/dev/null \
      | grep "^pip-audit" | awk '{print $3}' || echo "")

    if [[ -n "$PIPAUDIT_LATEST" ]]; then
      warn "  pip-audit: update available → ${PIPAUDIT_LATEST}"
      ask "  Upgrade pip-audit?" CONFIRM_PA
      if [[ "$CONFIRM_PA" == "y" || "$CONFIRM_PA" == "Y" ]]; then
        pipx upgrade pip-audit \
          && log "  pip-audit upgraded ✓" \
          || warn "  pipx upgrade pip-audit failed"
      fi
    else
      log "  pip-audit: up to date ✓"
    fi
  else
    info "  pip-audit: not installed"
    ask "  Install pip-audit via pipx?" CONFIRM_PAI
    if [[ "$CONFIRM_PAI" == "y" || "$CONFIRM_PAI" == "Y" ]]; then
      if ! command -v pipx &>/dev/null; then
        brew install pipx && pipx ensurepath > /dev/null 2>&1 || true
      fi
      pipx install pip-audit \
        && log "  pip-audit installed ✓" \
        || warn "  pipx install pip-audit failed"
    fi
  fi
  echo ""

  # ── 7. Mergen (GUI — CIS Benchmark) ──────
  info "── Mergen (CIS Benchmark assistant) ──"
  local MERGEN_APP="/Applications/Mergen.app"

  if [[ -d "$MERGEN_APP" ]]; then
    local MERGEN_VER
    MERGEN_VER=$(defaults read \
      "${MERGEN_APP}/Contents/Info" \
      CFBundleShortVersionString 2>/dev/null || echo "unknown")
    log "  Mergen: v${MERGEN_VER} installed ✓"

    # Check if it's running
    if pgrep -x "Mergen" &>/dev/null; then
      log "  Mergen: running ✓"
    else
      info "  Mergen: not running (GUI app — launch manually)"
      ask "  Launch Mergen now for a quick CIS check?" CONFIRM_MRG
      if [[ "$CONFIRM_MRG" == "y" || "$CONFIRM_MRG" == "Y" ]]; then
        open "$MERGEN_APP" \
          && log "  Mergen launched ✓" \
          || warn "  Failed to launch Mergen"
      fi
    fi

    # Mergen should not be in Login Items — this is an on-demand tool
    local LI_MERGEN
    LI_MERGEN=$(osascript -e \
      'tell application "System Events" to get the name of every login item' \
      2>/dev/null || echo "")
    if echo "$LI_MERGEN" | grep -qi "mergen"; then
      warn "  Mergen is in Login Items — not recommended (on-demand tool)"
      ask "  Remove Mergen from Login Items?" CONFIRM_MLI
      if [[ "$CONFIRM_MLI" == "y" || "$CONFIRM_MLI" == "Y" ]]; then
        osascript -e \
          'tell application "System Events" to delete login item "Mergen"' \
          2>/dev/null \
          && log "  Mergen removed from Login Items ✓" \
          || warn "  Remove manually: System Settings → General → Login Items"
      fi
    fi

  else
    info "  Mergen: not installed"
    info "  Download: https://github.com/km-sharifian/Mergen/releases"
    ask "  Open Mergen releases page in browser?" CONFIRM_MRGD
    if [[ "$CONFIRM_MRGD" == "y" || "$CONFIRM_MRGD" == "Y" ]]; then
      open "https://github.com/km-sharifian/Mergen/releases" \
        && log "  Opening Mergen releases page..." \
        || warn "  open command failed"
    fi
  fi
  echo ""

  # ── 3. LaunchAgents / LaunchDaemons ─────
  info "── LaunchAgents & LaunchDaemons (security-related) ──"

  local LAUNCH_DIRS=(
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
    "${HOME}/Library/LaunchAgents"
  )

  # Patterns for Objective-See + our hardening
  local PATTERNS=(
    "com.objective-see"
    "com.hardening"
    "com.dnscrypt"
    "at.obdev.littlesnitch"
    "com.privoxy"
    "com.lulu"
    "com.blockblock"
    "com.oversight"
  )

  local FOUND_ANY=false

  for DIR in "${LAUNCH_DIRS[@]}"; do
    [[ -d "$DIR" ]] || continue
    for PATTERN in "${PATTERNS[@]}"; do
      # shellcheck disable=SC2045
      for PLIST in $(ls "$DIR"/${PATTERN}*.plist 2>/dev/null); do
        FOUND_ANY=true
        local LABEL
        LABEL=$(basename "$PLIST" .plist)
        local STATUS

        # Check via launchctl
        if launchctl list "$LABEL" &>/dev/null 2>&1; then
          local PID
          PID=$(launchctl list "$LABEL" 2>/dev/null | awk '/\"PID\"/{print $3}' | tr -d ',')
          if [[ -n "$PID" && "$PID" != "0" ]]; then
            STATUS="${GREEN}RUNNING (PID ${PID})${NC}"
          else
            STATUS="${YELLOW}LOADED / not running${NC}"
          fi
        else
          STATUS="${RED}NOT LOADED${NC}"
        fi

        echo -e "  [$(basename "$DIR")] ${LABEL}"
        echo -e "    └─ status: ${STATUS}"
        echo -e "    └─ plist:  ${PLIST}"
        echo ""
      done
    done
  done

  if [[ "$FOUND_ANY" == false ]]; then
    info "  No security-related LaunchAgents/Daemons found."
  fi

  echo ""
  info "── Objective-See tools running processes ──"
  local OBJ_SEE_PROCS=(
    "LuLu"
    "BlockBlock"
    "KnockKnock"
    "DoNotDisturb"
    "OverSight"
  )
  for PROC in "${OBJ_SEE_PROCS[@]}"; do
    if pgrep -x "$PROC" &>/dev/null; then
      log "  ${PROC}: running ✓"
    else
      info "  ${PROC}: not running"
    fi
  done

  echo ""
}

# ──────────────────────────────────────────
# SECURITY TOOLS
# ──────────────────────────────────────────
install_security_tools() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 4/7: Security Tools ]         ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    log "Security tools check & install..."
    echo ""

    # ── First, let's check what's already there ──
    check_security_tools_status

    ask "Proceed with installing/updating security tools?" CONFIRM_INST
    [[ "$CONFIRM_INST" != "y" && "$CONFIRM_INST" != "Y" ]] && {
        log "Skipping security tools installation."
        return 0
    }

    install_cask "lulu"           "LuLu Firewall"  "/Applications/LuLu.app"
    install_cask "blockblock"     "BlockBlock"      "/Applications/BlockBlock.app"
    install_cask "knockknock"     "KnockKnock"      "/Applications/KnockKnock.app"
    install_cask "do-not-disturb" "DoNotDisturb"    "/Applications/DoNotDisturb.app"
    install_formula "lynis"
    install_oversight

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
    # [FIX v5] Options have been reordered: Lynis exception — recommended option
    # for desktops. chmod 750 is marked as "advanced" (servers/labs).
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
  echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 6/7: macOS Defaults ]         ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
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

# ──────────────────────────────────────────
# POWER MANAGEMENT (pmset)
# ──────────────────────────────────────────
harden_power_management() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 7/7: Power Management ]       ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    log "Checking power management (pmset)..."

  # Show current values
  info "Current pmset settings (subset for AC/Battery):"
  pmset -g | sed 's/^/  /'

  echo ""
  echo "Recommended baseline (CIS-style):"
  echo "  - System sleep:      15 minutes"
  echo "  - Display sleep:     10 minutes"
  echo "  - Wake for network:  disabled (womp 0)"
  echo ""

  ask "Apply these pmset settings?" CONFIRM_PM
  if [[ "$CONFIRM_PM" != "y" && "$CONFIRM_PM" != "Y" ]]; then
    log "Skipping pmset baseline."
    return 0
  fi

  # Apply to all power sources (-a)
  # sleep 15, displaysleep 10, womp 0
  if sudo pmset -a sleep 15 displaysleep 10 womp 0; then
    log "pmset baseline applied: sleep=15, displaysleep=10, womp=0"
  else
    err "pmset command failed. Check 'sudo pmset -g' manually."
  fi
}

# ──────────────────────────────────────────
# GATEKEEPER & FILEVAULT CHECKS
# ──────────────────────────────────────────
check_gatekeeper_filevault() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   [ MODULE 8/8: Gatekeeper & FileVault ] ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    log "Checking Gatekeeper and FileVault status..."

  # Gatekeeper
  local GK_STATUS
  if GK_STATUS=$(spctl --status 2>/dev/null); then
    info "Gatekeeper: $GK_STATUS"
    if echo "$GK_STATUS" | grep -qi "disabled"; then
      warn "Gatekeeper is DISABLED."
      ask "Enable Gatekeeper (spctl --master-enable)?" CONFIRM_GK
      if [[ "$CONFIRM_GK" == "y" || "$CONFIRM_GK" == "Y" ]]; then
        sudo spctl --master-enable && log "Gatekeeper enabled."
      else
        warn "Gatekeeper left disabled by user choice."
      fi
    fi
  else
    warn "Unable to determine Gatekeeper status."
  fi

  # FileVault
  if command -v fdesetup &>/dev/null; then
    local FV_STATUS
    FV_STATUS=$(fdesetup status 2>/dev/null || true)
    info "FileVault: $FV_STATUS"
    if echo "$FV_STATUS" | grep -qi "FileVault is Off"; then
      warn "FileVault is OFF."
      info "Enable via: System Settings → Privacy & Security → FileVault."
      # Here it's better not to enable FileVault automatically, only a recommendation.
    fi
  else
    warn "fdesetup not found – cannot check FileVault."
  fi
}

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
clear
echo ""
echo "  ░██████████                      ░██                   ░██            "
echo "  ░██                              ░██                   ░██            "
echo "  ░██         ░███████  ░██    ░██ ░████████   ░███████  ░██  ░███████   "
echo "  ░█████████ ░██    ░██  ░██  ░██  ░██    ░██ ░██    ░██ ░██ ░██    ░██  "
echo "  ░██        ░██    ░██  ░██  ░██  ░██    ░██ ░██    ░██ ░██ ░██         "
echo "  ░██         ░███████  ░██    ░██ ░██    ░██  ░███████  ░██  ░███████   "
echo ""  
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     macOS Security Hardening Script      ║"
echo "  ║            v0.16  ·  by Gr3y-foX         ║"
echo "  ║       ARM/M-chip  |  strict mode         ║"
echo "  ╠══════════════════════════════════════════╣"
echo "  ║  status: [ARMED]  |  mode: interactive   ║"
echo "  ╠══════════════════════════════════════════╣"
echo "  ║  [!] Unauthorized use is prohibited.     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
warn "This script modifies system settings. Sudo required."
ask "Continue?" CONFIRM
[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted by user."; exit 0; }
echo ""

check_requirements      # resolve_brew_prefix is called within
check_connectivity
configure_firewall      # Now, check the Quad9 profile before use
install_security_tools
harden_compilers
apply_defaults
harden_power_management
check_gatekeeper_filevault

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
    bash "$SCRIPT_DIR/vpn_daily.sh"
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

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║        Base hardening complete       ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

echo "  Additional manual steps (recommended):"
echo ""

# DNS & VPN
info "DNS & VPN"
echo "  1. Quad9 DNS profile (if not installed):"
echo "       https://docs.quad9.net/assets/mobileconfig/Quad9_Secured_DNS_over_HTTPS_ECS_20260119.mobileconfig"
info "  2. OpenVPN client:"
echo "       https://openvpn.net/client/"
info "  3. VPN check:"
echo "       https://timbrica.com/en/vpn-checker"
info "  4. DNS leak test:"
echo "       https://www.dnsleaktest.com/results.html"
echo ""

# Audits & scanners
info "Audits & scanners"
info "  5. Pareto Security (GUI checks):"
echo "       https://paretosecurity.com/apps"
info "  6. Lynis system audit:"
echo "       sudo lynis audit system"
info "  7. Homebrew package CVE scan:"
echo "       brew vulns"
info "  8. Python dependency CVE scan:"
echo "       pip-audit"
echo ""

# Tools & extras
info "Tools & extras"
info "  9. CIS benchmark assistant (Mergen):"
echo "       open /Applications/Mergen.app"
info " 10. Proxy toggle log (Privoxy/VPN autoswitch):"
echo "       tail -f /var/log/proxy-toggle.log"
echo ""

info "Base hardening + selected network scenario completed. Stay paranoid. 🔒"
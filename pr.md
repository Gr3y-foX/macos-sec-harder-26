# macOS Hardening Helper (v0.16) for Apple Silicon

> Opinionated, interactive macOS hardening helper inspired by  
> [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).

This script provides a reproducible way to apply many of the practices from the guide on modern Apple Silicon macOS, with additional automation around security tooling, Objective-See integration, and optional network privacy profiles (VPN / Tor).

The design goal is:

- **No “magic one‑click hardening”** – the user is always asked before impactful changes.
- **Reproducibility** – changes are implemented as shell logic, not manual click-through steps.
- **Transparency** – clear logging, no hidden behavior, no automatic FileVault enablement.

---

## 1. Features Overview

### 1.1 Base System Hardening

- Enforces strict shell behavior (`set -uo pipefail`, error traps, colored log output).
- Checks and bootstraps **Homebrew** safely (no root, proper `brew --prefix`, shell env setup).
- Configures the built-in **macOS Application Firewall**:
  - Enables the firewall globally.
  - Enables **stealth mode**.
  - Disables “allow signed” and “allow signed app” shortcuts to enforce explicit rules.
- Checks **Gatekeeper** status and offers to enable it if disabled.
- Checks **FileVault** status:
  - Recommends enabling if off.
  - Does **not** enable FileVault automatically (user must do it in System Settings).

### 1.2 Privacy Defaults

Applies a minimal, opinionated set of macOS defaults (all changes are logged):

- Require password immediately after screensaver / sleep.
- Disable Crash Reporter dialogs.
- Show hidden files and file extensions in Finder.
- Disable saving new documents to iCloud by default.
- Unhide `~/Library` for easier inspection and troubleshooting.

All changes are optional and can be skipped by the user.

### 1.3 Security Tooling Orchestration

The script implements a lightweight “security tooling orchestrator” on top of Homebrew and pipx:

- **Homebrew formulas:**
  - `lynis` — system audit.
  - `dnscrypt-proxy` — DNS privacy and integrity.
  - `privoxy` — privacy‑oriented HTTP proxy (used in network profiles).

- **Homebrew casks (Objective-See & friends):**
  - `LuLu` (firewall)
  - `BlockBlock`
  - `KnockKnock`
  - `DoNotDisturb`
  - `OverSight`
  - `pareto-security` (status checks)

For each formula/cask, the script:

- Checks if it is installed.
- Shows installed vs latest version.
- Offers to upgrade if an update is available.

### 1.4 Objective‑See Integration (OverSight)

OverSight is intentionally handled more carefully:

- Detects existing `/Applications/OverSight.app` and reads its version.
- If not installed, offers to:
  - Download OverSight from the official Objective‑See site.
  - Parse the downloads page for the current ZIP URL.
  - Verify the installer `.zip` against a known SHA‑1 (to detect tampering).
  - Extract and run `OverSightInstaller.app` with clear user prompts.
- After installation, it:
  - Verifies that `OverSight.app` exists in `/Applications`.
  - Checks whether OverSight is running and offers to launch it.
  - Checks and manages OverSight’s Login Item via AppleScript:
    - Adds to Login Items if missing.
    - Keeps the user in control of auto‑start.

### 1.5 Vulnerability & Dependency Scanning

The script encourages regular vulnerability scanning of packages and dependencies:

- **Homebrew package CVEs:**
  - Integrates `brew-vulns` tap and formula.
  - Installs or updates `brew-vulns`.
  - Warns if the binary is not in `PATH` and suggests how to fix it.

- **Python dependency CVEs:**
  - Installs **pipx** when needed.
  - Installs or upgrades **pip-audit** via pipx.
  - Checks for outdated pip-audit versions and offers to upgrade.
  - Encourages running `pip-audit` against Python environments.

---

## 2. CIS & Power Management

### 2.1 CIS-Style pmset Baseline

For mobile and desktop use (not hardened servers), the script:

- Displays current `pmset -g` values for transparency.
- Offers to apply a CIS‑style baseline:
  - `sleep` = 15 minutes
  - `displaysleep` = 10 minutes
  - `womp` = 0 (Wake on network disabled)

The user can accept or decline this baseline. On hardened server/lab setups, it is explicitly marked as optional and potentially undesirable.

### 2.2 Compiler Hardening (Advanced)

The script includes optional logic for compiler hardening:

- Detects the presence of system compilers (`clang`, `gcc`, `cc`, `make`).
- Provides an **advanced** mode (explicitly marked as such) which:
  - May restrict permissions on compiler binaries (e.g., `chmod 750`) for lab/server use.
  - Adds a Lynis exception (`skip-test=HRDN-7222`) for desktop machines, where this measure is overkill.

This is **not** enabled silently and is clearly labeled as advanced / lab‑only.

---

## 3. Network Privacy Modules (Modular Design)

The hardening script is designed to be modular. Network profiles are kept in separate helper scripts and can be run on demand.

### 3.1 Module Layout (Concept)

Suggested structure:

- `mac-hardening-install.sh`  
  Base hardening and interactive launcher for modules.

- `mac-hardening-netlib.sh`  
  Shared functions for network profiles (dnscrypt, PF rules, Privoxy, etc).

- `profile-vpn-daily.sh`  
  “Daily driver” VPN profile with reasonable privacy and low friction.

- `profile-paranoid-tor.sh`  
  High‑privacy Tor‑centric profile with stricter assumptions and trade‑offs.

The main script offers to run these modules at the end of the base hardening phase, or they can be invoked manually later.

---

## 4. VPN Daily Profile Module (Concept)

**File:** `profile-vpn-daily.sh`

Goal: reasonable privacy and security for everyday use without breaking too many workflows.

### 4.1 Core Ideas

- Require a trusted VPN client:
  - Example: OpenVPN, WireGuard, or a reputable first‑party macOS client.
- Integrate with the rest of the hardening ecosystem:
  - Ensure macOS Application Firewall is enabled.
  - Leverage `dnscrypt-proxy` or provider’s DNS to avoid leaks.
- Provide simple checks:
  - External IP/VPN status check (`curl` to a trusted endpoint).
  - DNS leak test (opening well‑known test sites in the browser).
  - Optional logging via Privoxy / proxy toggles.

### 4.2 Typical Workflow

1. User starts the VPN Daily profile script.
2. Script checks:
   - Is the VPN client installed?
   - Is the connection up? (Basic IP + DNS checks)
3. Script optionally:
   - Launches the VPN client if not running.
   - Configures system DNS toward:
     - Trusted resolver (e.g., Quad9), and/or
     - Local `dnscrypt-proxy` if installed.
4. Script prints clear “safe to use / not safe to use” status and links to DNS/IP leak tests.

No VPN provider is hardcoded; the module is meant to be adapted to the user’s provider of choice.

---

## 5. Paranoid Tor Profile Module (Concept)

**File:** `profile-paranoid-tor.sh`

Goal: maximize network anonymity at the cost of convenience and performance.

### 5.1 Threat Model

- Assumes the user is willing to:
  - Accept slower connections.
  - Compartmentalize activities into Tor‑only contexts.
  - Respect strict “no direct clearnet from this profile” rules.

### 5.2 Core Ideas

- Use Tor (or Tor Browser Bundle) as the primary egress:
  - Optionally route traffic through local SOCKS proxy exposed by Tor.
- Integrate with Privoxy / dnscrypt‑proxy where appropriate:
  - HTTP proxying via Privoxy → Tor.
  - DNS handled by Tor / dnscrypt to minimize leaks.
- Tight firewall rules:
  - Limit outbound traffic to Tor and local proxies.
  - Optionally block all non‑Tor outbound connections from selected network interfaces or user contexts.

### 5.3 Typical Workflow

1. User starts the Paranoid Tor profile script.
2. Script checks:
   - Is Tor/Tor Browser installed?
   - Is Privoxy installed (if using Privoxy + Tor chain)?
3. Script:
   - Starts Tor/Privoxy if needed.
   - Adjusts system / application proxy settings to route selected traffic via Tor.
   - Optionally adds stricter PF rules or app‑level constraints (conceptual; exact rules depend on user’s environment and risk tolerance).
4. Script prints:
   - Which interfaces/ports are restricted.
   - Which applications are expected to use Tor‑only paths.
   - How to revert back to a normal profile.

The Tor profile is intentionally designed as an **opt‑in “mode”**, not something that silently rewires the entire system without the user’s consent.

---

## 6. LaunchAgents, Daemons, and Objective‑See Processes

The script inspects relevant LaunchAgents/LaunchDaemons and running processes:

- Scans for security‑relevant `LaunchAgents` / `LaunchDaemons`, e.g.:
  - `com.objective-see.*`
  - `com.lulu`, `com.blockblock`, `com.oversight`, `com.privoxy`, etc.
- For each detected item:
  - Shows whether it is loaded and/or running.
  - Prints basic status (running / loaded but not running / not loaded).
- Performs a lightweight process check for Objective‑See tools:
  - `LuLu`, `BlockBlock`, `KnockKnock`, `DoNotDisturb`, `OverSight`.

This is meant as a quick status overview, not a full EDR.

---

## 7. Usage

### 7.1 Prerequisites

- Modern macOS on Apple Silicon.
- Interactive shell (script is heavily interactive).
- Administrator account with `sudo` rights.
- Internet connectivity for retrieving tools and updates.

### 7.2 Running

```bash
# do not run as root
chmod +x mac-hardening-install.sh
./mac-hardening-install.sh
```

You will be prompted before any impactful change:

- Enabling firewall or Gatekeeper.
- Installing/updating security tools.
- Applying `pmset` baselines.
- Running VPN / Tor profiles.

At the end of the base hardening phase, the script will offer to:

- Run the **VPN Daily profile** module.
- Run the **Paranoid Tor profile** module.
- Open the **network menu** to manage and test DNS/Privoxy/filters.

You can safely decline and run these modules manually later.

---

## 8. Philosophy and Caveats

- **No automatic FileVault activation**: enabling full‑disk encryption is a user decision with backup/operational implications.
- **No blind compiler lockdown**: compiler permission changes are marked as advanced and are opt‑in.
- **No hardcoded VPN provider**: the VPN profile is a framework; the user must plug in their own provider and config.
- **Tor profile breaks convenience by design**: it is meant for high‑privacy, not “pretty good” anonymous browsing while logged into personal accounts.

This project is meant to complement, not replace, the  
[macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).  
It encodes selected recommendations into a reproducible workflow and adds practical tooling around:

- Objective‑See products,
- Lynis / brew-vulns / pip-audit,
- CIS‑style `pmset`,
- and optional VPN/Tor‑based network profiles.
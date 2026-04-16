# macOS Security Hardening 2026

Advanced hardening toolkit for macOS (Intel + Apple Silicon) inspired by [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).

- Warning: This project is made by student of cybersecurity. its not enterprise level, dont gurantee any "full security" or "100% protection" or "Paranoid mode safe". Please use it at your own risk. If u has any recommendation or feedback, please let me know, its deeply appretiated.

The goal is a **safe, modular setup**:

- One **base installer** that hardens the system without breaking network connectivity.
- A **network library** with reusable functions for DNS / PF / proxy hardening.
- Separate **profiles** for different threat models (e.g. everyday VPN vs. paranoid Tor routing).

> ⚠️ This project is for power users and security practitioners.  
> Misusing PF, DNS, and proxy configuration can break your network.  
> Read the docs and test on a non‑production machine first.
> Author dont hold any responsibility for any damage caused by this script, or usage of this script out of safe environment.

---

## Features

### Base hardening

The base installer (`mac-hardening-install.sh`) focuses on **local system security** and avoids risky network changes:

- Homebrew bootstrap and sanity checks.
- macOS Application Firewall configuration (socketfilterfw):
  - Enables firewall.
  - Enables stealth mode.
  - Disables auto‑allowing signed apps.
- Security tooling install (via Homebrew / casks):
  - Objective‑See tools (LuLu, BlockBlock, KnockKnock, Do Not Disturb).
  - `lynis` for system audits.
  - `pipx` + `pip-audit` (Python dependency CVE scanning).
  - `brew-vulns` (Homebrew package CVE scanning).
  - Optional: Mergen (CIS benchmark GUI).
- Optional compiler hardening:
  - Adjusts permissions or adds Lynis exceptions for HRDN‑7222.
- Privacy‑oriented defaults:
  - Password on screensaver resume.
  - No GUI crash reporter dialogs.
  - Show hidden files and all extensions.
  - Disable “save new documents to iCloud” by default.

The base installer **does not**:

- Touch `/etc/pf.conf`.
- Change system proxies.
- Start custom DNS or HTTP proxies by default.

This separation keeps the “first run” as safe as possible.

---

## Network hardening architecture

Network features are split into:

1. A **netlib**: `mac-hardening-netlib.sh` – low‑level functions (DNSCrypt, PF, Privoxy, hosts).  
2. **Profiles** that call netlib with a specific threat model (e.g. `profile-vpn-daily.sh`). [file:73]

### mac-hardening-netlib.sh

Reusable building blocks (functions) include:

- `install_dnscrypt`, `enable_dnscrypt`, `disable_dnscrypt`  
  Install and control `dnscrypt-proxy` as a user‑level service (no `sudo brew services`).  
  Used to provide encrypted DNS on localhost (e.g. 127.0.0.1:5355).

- PF DNS leak lock:
  - `prepare_pf_dns_lock_anchor`  
    Writes PF anchor (`/etc/pf.anchors/com.hardening.dnsleak`) with rules that:
    - Allow DNS over HTTPS from `127.0.0.1` / `::1` to ports 443/8443.
    - Block direct DNS (ports 53/853) for IPv4 and IPv6.
  - `enable_pf_dns_lock`  
    Appends a marker + anchor load block into `/etc/pf.conf` and reloads PF.
  - `disable_pf_dns_lock`  
    Removes the marker and anchor from PF and reloads a clean configuration.

- `/etc/hosts` blocklist:
  - `update_hosts_blocklist`  
    Integrates the StevenBlack hosts file under a clear marker, preserves existing entries above it, and logs SHA‑256 of the downloaded list for manual verification.
  - `disable_hosts_blocklist`  
    Removes the blocklist section by marker while keeping the original hosts entries.

- Privoxy:
  - `install_privoxy`  
    Installs Privoxy and validates its config path using `brew --prefix`.
  - `configure_privoxy_vpn_bypass`  
    Adds forwarding rules so private/VPN ranges bypass the proxy.
  - `enable_privoxy_vpn_autoswitch`  
    Creates a `proxy-toggle.sh` script and LaunchDaemon that:
    - Detects VPN presence via `utun` interfaces.
    - Turns system HTTP/HTTPS proxy ON (127.0.0.1:8118) when no VPN is active.
    - Turns proxy OFF when a VPN is active.
    - Implements simple log rotation for `/var/log/proxy-toggle.log`.
  - `disable_privoxy_autoswitch`  
    Unloads and removes the LaunchDaemon and toggle script.

- Global reset:
  - `reset_net_hardening`  
    Convenience helper that attempts to:
    - Stop `dnscrypt-proxy`.
    - Disable PF DNS lock.
    - Disable Privoxy auto‑switch.
    - Clear system HTTP/HTTPS proxy settings across all network services.

This file can be executed directly (it has its own menu) or, more typically, `source`d from profile scripts. [file:73]

---

## Profiles

Profiles define **how** to use netlib for a specific threat model.

### VPN Daily (`profile-vpn-daily.sh`)

Threat model: everyday user with a commercial VPN (e.g. ClearVPN, OpenVPN) who just wants “turn on VPN and forget”.

Design goals:

- No PF kill‑switches by default.
- No `/etc/pf.conf` manipulation.
- No Privoxy auto‑proxy for non‑technical users.
- Keep DNS changes minimal and reversible.

Menu actions:

- **[1] Without VPN:** install + enable `dnscrypt-proxy`
  - `dnscrypt-proxy` runs as a user service and acts as local encrypted DNS.
  - Useful when browsing on regular Wi‑Fi without a VPN.

- **[2] With VPN:** disable `dnscrypt-proxy`
  - Lets the VPN client fully control DNS (recommended for simpler setups).
  - Avoids conflicts between system DNS and VPN‑pushed resolvers.

- **[3] Usage & DNS‑leak guidance**
  - Explains how to:
    - Use ClearVPN/OpenVPN with this profile.
    - Test VPN and DNS leaks via online tools (ipleak.net, dnsleaktest.com, etc.).

- **[4] Reset**
  - Calls `reset_net_hardening` from netlib to undo DNS/proxy changes.

- **[5] Exit**

This profile is intentionally **non‑destructive** and aims to be safe for non‑experts.

> Planned: a separate `profile-paranoid-tor.sh` that uses PF DNS lock, Privoxy→Tor, and stronger traffic constraints. This profile is not meant for casual users.

---

## Usage

### 1. Base install

```bash
git clone https://github.com/Gr3y-foX/macos-sec-harder-26.git
cd macos-sec-harder-26

# Run base installer (not as root)
bash mac-hardening-install.sh
```

The installer will:

- Check for Homebrew and curl.
- Install/update security tools.
- Configure firewall and privacy defaults.
- Offer to continue into network hardening.

### 2. Network hardening & profiles

After base install, you can:

- Let the installer launch a profile right away, or
- Run them later:

```bash
# Netlib menu (advanced, manual blocks)
bash mac-hardening-netlib.sh

# Everyday VPN profile (ClearVPN/OpenVPN)
bash profile-vpn-daily.sh

# (Future) Paranoid Tor profile
bash profile-paranoid-tor.sh
```

---

## Requirements

- macOS with zsh/bash.
- Non‑root user with `sudo` privileges.
- Stable internet connection.
- Homebrew (installer will offer to install it if missing).

---

## Warnings & disclaimers

- PF and DNS changes can break connectivity if misconfigured.  
  Use the **VPN Daily** profile for non‑experts and only experiment with PF‑based DNS lock or kill‑switches when you understand the implications.
- This project is **not** a magic “secure my Mac” button. It’s a toolkit for building opinionated security baselines.
- Always keep backups and test on a non‑critical machine first.

---

## Roadmap

- Finalize `profile-paranoid-tor.sh` (Tor routing, Privoxy integration, PF‑based DNS lock).
- Add automated checks:
  - DNS leak tests.
  - Basic connectivity tests after applying profiles.
- Improve logging and dry‑run options for all scripts.
- Add versioning and changelog per macOS release.
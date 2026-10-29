# Patchbar

A small shield in your Mac's menu bar. It shows what's out of date and which security holes are being actively exploited, and fixes them in one click.

![menu bar](https://img.shields.io/badge/macOS-menu%20bar-black)

## Install (one line)

Paste into Terminal:

```bash
git clone https://github.com/wpvip-awesomeface/patchbar ~/.patchbar && ~/.patchbar/install.sh
```

This installs [SwiftBar](https://swiftbar.app) (the free app that hosts menu bar plugins), `osv-scanner` and `mas` through Homebrew, and starts the first scan. Needs [Homebrew](https://brew.sh).

Use `install.sh --minimal` to skip the optional tools.

## What you get

- **Shield icon**: red `3·82` means 3 actively exploited bugs with a fix waiting, and 82 updates total.
- **Update everything**: one click runs every update (except macOS) in Terminal, then re-scans.
- **Per-section and per-app buttons**: covers macOS, Homebrew, App Store, global npm and Python.
- **Hold ⌥ Option** while the menu is open to copy a command instead of running it.
- **Actively exploited**: [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list, matched to apps on your Mac. Each match is marked "update pending" or "you look patched".
- **Vulnerable project deps**: checks lockfiles in your code folders with [OSV.dev](https://osv.dev) (GitHub Advisories, NVD, npm, PyPI, Packagist). Shows critical and high issues only.

Scans run in the background every 6 hours. The menu opens instantly.

## Suspicious-update check

Before any npm or Python update button installs anything, Patchbar checks each new version against the one you have (usually under 15 seconds):

- **Red flags** (Patchbar pauses and asks): new or changed install scripts, a Python package that now ships only source code (so pip would run its setup code), a publisher who wasn't a maintainer before, a lost provenance attestation, new obfuscated code or `.pth` startup files, code that newly runs shell commands or `eval`s strings, new hard-coded IP addresses or webhook hosts, or an [OSV](https://osv.dev) malicious-package advisory (`MAL-…`).
- **Heads-ups** (shown, no pause): new maintainers, a big size jump, a release under 48 hours old, deprecation notices, new network or base64 code.

When something is flagged you choose: press Enter to install the rest and skip the flagged ones, `a` to install everything anyway, or `n` to install nothing. Patchbar installs the exact versions it checked.

Run it by hand: `~/.patchbar/vet.py --check-only npm typescript@6.0.3 pypi requests@2.31.0`

It uses public registry data only (registry.npmjs.org, pypi.org, api.osv.dev). Package files are read in memory and never run.

## Settings

In the menu, under **Patchbar**:

- **Choose code folders to check…**
- **Open settings file** (`~/.config/patchbar/config.json`):

```json
{ "project_roots": ["/Users/you/code"], "kev_days": 45, "skip": ["docker-desktop"] }
```

- **Update Patchbar**: pulls the latest version.
- **Uninstall Patchbar…**: removes the plugin and its cache.

## Privacy

Everything runs on your Mac. The only outside requests are the CISA feed, OSV.dev (package names and versions only), each package manager's normal update check, and the public npm and PyPI registries for the suspicious-update check.

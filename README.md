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

Everything runs on your Mac. The only outside requests are the CISA feed, OSV.dev (package names and versions only), and each package manager's normal update check.

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
- **Per-section and per-app buttons**: covers macOS, Homebrew, App Store, and the global packages of every Python and Node on your Mac.
- **Every Python and Node, each kept separately**: see below.
- **Hold ⌥ Option** while the menu is open to copy a command instead of running it.
- **Actively exploited**: [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list, matched to apps on your Mac. Each match is marked "update pending" or "you look patched". Apple bugs only count as pending when a macOS, Safari or security update is waiting (not Xcode or Command Line Tools).
- **Vulnerable project deps**: checks lockfiles in your code folders with [OSV.dev](https://osv.dev) (GitHub Advisories, NVD, npm, PyPI, Packagist). Shows critical and high issues only.

Scans run in the background every 6 hours. The menu opens instantly.

## Every Python and Node install

Most Macs end up with several copies of Python and Node: Apple's, Homebrew's, plus pyenv, nvm, uv, conda, fnm, Volta or asdf versions. Patchbar finds them all and treats each one on its own:

- **Its own section**, e.g. "Python · pyenv 3.12.3 (your default)". "Your default" is what a new Terminal window runs.
- **Updates pinned to that install.** Each button calls that exact interpreter (or puts that node first on `PATH`), so an update never lands in a different Python than the one that was checked.
- **Managed installs are left alone.** Homebrew's and Apple's Pythons, conda and Volta are updated by their own tools, so Patchbar never runs pip or npm on them. (Homebrew node's own npm is left to Homebrew too.)
- **Review first.** Updates that can break other packages stay out of "Update everything": packages that must move together (torch/torchvision/torchaudio, tensorflow, jax…), an update another installed package doesn't allow (e.g. `torch` needs `setuptools<82`), and anything `pip check` already flags. Each gets its own button with the reason.
- **Python & Node installs** menu lists every copy, where it lives, whether it's past end of support, and a safe tip when there is one (a newer patch release for your pyenv/nvm version, or a Homebrew Python nothing depends on). Tips are copy-only. Patchbar never uninstalls anything.

Several versions side by side is normal (projects pin versions), so nothing is flagged as a problem just for existing.

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

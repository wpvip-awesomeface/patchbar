#!/usr/bin/env python3
"""Patchbar scanner: collects outdated software + known vulnerabilities into one JSON file.

Sources:
  - macOS system updates (softwareupdate)
  - Homebrew formulae + casks (brew outdated)
  - Mac App Store apps (mas outdated)
  - Global npm packages (npm outdated -g)
  - Python packages for the active python3 (pip list --outdated)
  - Project lockfile vulnerabilities (osv-scanner -> OSV.dev, includes GHSA/NVD data)
  - CISA Known Exploited Vulnerabilities, matched against installed apps/tools

Writes ~/Library/Caches/patchbar/state.json. Safe to run repeatedly; no updates are applied.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOME = Path.home()
CACHE = HOME / "Library/Caches/patchbar"
STATE = CACHE / "state.json"
CONFIG = HOME / ".config/patchbar/config.json"

# Menu bar apps get a bare PATH, so add the usual places package managers live.
_nvm = sorted((HOME / ".nvm/versions/node").glob("*/bin"))
os.environ["PATH"] = ":".join([
    str(HOME / ".safe-npm/bin"),
    "/opt/homebrew/bin", "/opt/homebrew/sbin",
    *([str(_nvm[-1])] if _nvm else []),
    str(HOME / ".volta/bin"),
    str(HOME / ".pyenv/shims"),
    "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    os.environ.get("PATH", ""),
])
os.environ.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")

DEFAULT_CONFIG = {
    # Folders scanned for lockfiles (package-lock, pnpm-lock, composer.lock, requirements, etc.).
    # Common code folders; only the ones that exist are scanned. Override in ~/.config/patchbar/config.json.
    "project_roots": [str(HOME / d) for d in (
        "Developer", "code", "Code", "Projects", "projects", "src", "Sites", "GitHub", "Documents/GitHub",
        "Desktop/_projects", "Desktop/_tools")],
    "kev_days": 45,
    "skip": [],  # package names to ignore, e.g. ["docker-desktop"]
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG.exists():
        cfg.update(json.loads(CONFIG.read_text()))
    return cfg


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.stdout, p.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return "", f"error: {e}"


def item(name, current, latest, update_cmd, severity="update"):
    return {"name": name, "current": current or "?", "latest": latest or "?", "cmd": update_cmd, "severity": severity}


def scan_macos():
    out, _ = run(["softwareupdate", "-l"], timeout=180)
    items = []
    for label, title in re.findall(r"\* Label: (.+)\n\s+Title: ([^,]+)", out):
        security = bool(re.search(r"security|rapid", label, re.I))
        items.append(item(title.strip(), "", label.strip(),
                          "open x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
                          "security" if security else "update"))
    return items


def scan_brew():
    out, _ = run(["brew", "outdated", "--json=v2", "--greedy-auto-updates"])
    if not out:
        return []
    data = json.loads(out)
    items = []
    for f in data.get("formulae", []):
        if f.get("pinned"):
            continue
        items.append(item(f["name"], ",".join(f["installed_versions"]), f["current_version"], f"brew upgrade {f['name']}"))
    for c in data.get("casks", []):
        items.append(item(c["name"], ",".join(c["installed_versions"]), c["current_version"], f"brew upgrade --cask {c['name']}"))
    return items


def scan_mas():
    out, _ = run(["mas", "outdated"])
    items = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.+?)\s+\((\S+)\s+->\s+(\S+)\)", line)
        if m:
            items.append(item(m[2], m[3], m[4], f"mas upgrade {m[1]}"))
    return items


def scan_npm():
    out, _ = run(["npm", "outdated", "-g", "--json"])
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return []
    return [item(n, v.get("current"), v.get("latest"), f"npm install -g {n}@latest") for n, v in data.items()
            if v.get("current") != v.get("latest")]


def scan_pip():
    out, _ = run(["python3", "-m", "pip", "list", "--outdated", "--format=json", "--disable-pip-version-check"], timeout=180)
    try:
        data = json.loads(out or "[]")
    except json.JSONDecodeError:
        return []
    return [item(p["name"], p["version"], p["latest_version"], f"python3 -m pip install -U {p['name']}") for p in data]


SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def scan_osv(roots):
    roots = [r for r in roots if Path(r).is_dir()]
    if not roots:
        return []
    out, _ = run(["osv-scanner", "scan", "source", "-r", "--format", "json", *roots], timeout=600)
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return []
    found = {}
    for res in data.get("results") or []:
        src = res["source"]["path"]
        if any(part in src for part in ("/node_modules/", "/vendor/", "/.worktrees/", "/.git/")):
            continue
        project = Path(src).parent.name
        for pkg in res.get("packages") or []:
            name = pkg["package"]["name"]
            ver = pkg["package"].get("version", "")
            for g in pkg.get("groups") or []:
                sev = (g.get("max_severity") or "")
                try:
                    score = float(sev)
                    label = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
                except ValueError:
                    label = sev.upper() or "UNKNOWN"
                ids = g.get("aliases") or g.get("ids") or []
                cve = next((i for i in ids if i.startswith("CVE-")), ids[0] if ids else "?")
                key = (project, name, cve)
                found[key] = {
                    "name": f"{name} {ver}", "project": project, "id": cve, "severity": label,
                    "url": f"https://osv.dev/vulnerability/{(g.get('ids') or [cve])[0]}",
                    "dir": str(Path(src).parent),
                }
    return sorted(found.values(), key=lambda v: -SEV_RANK.get(v["severity"], 0))


def installed_names():
    names = set()
    for app_dir in ["/Applications", str(HOME / "Applications")]:
        if os.path.isdir(app_dir):
            names |= {a[:-4].lower() for a in os.listdir(app_dir) if a.endswith(".app")}
    out, _ = run(["brew", "list", "-1", "--formula"])
    names |= {n.lower() for n in out.split()}
    out, _ = run(["brew", "list", "-1", "--cask"])
    names |= {n.lower().replace("-", " ") for n in out.split()}
    names |= {"macos", "safari", "webkit"}
    return names


def scan_kev(days):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "patchbar"}), timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        return [{"name": "CISA KEV feed unreachable", "id": "", "severity": "INFO", "url": url, "error": str(e)}]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    have = installed_names()
    hits = []
    for v in data.get("vulnerabilities", []):
        if v["dateAdded"] < cutoff:
            continue
        product = v["product"].lower()
        vendor = v["vendorProject"].lower()
        words = [w for w in re.split(r"[^a-z0-9]+", product) if len(w) > 2]
        match = (product in have or any(product in n or n == product for n in have)
                 or (vendor == "apple" and any(w in ("macos", "safari", "webkit", "multiple") for w in words))
                 or any(w in have for w in words if w not in {"server", "windows", "office", "multiple", "products"}))
        if match:
            hits.append({
                "name": f"{v['vendorProject']} {v['product']}", "id": v["cveID"], "severity": "EXPLOITED",
                "title": v["vulnerabilityName"], "added": v["dateAdded"], "due": v.get("dueDate"),
                "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            })
    return sorted(hits, key=lambda h: h["added"], reverse=True)


def main():
    cfg = load_config()
    CACHE.mkdir(parents=True, exist_ok=True)
    lock = CACHE / "scan.lock"
    if lock.exists() and time.time() - lock.stat().st_mtime < 900:
        print("scan already running")
        return
    lock.touch()
    try:
        skip = set(cfg["skip"])
        steps = {
            "macOS": scan_macos, "Homebrew": scan_brew, "App Store": scan_mas,
            "npm (global)": scan_npm, "Python": scan_pip,
        }
        state = {"scanned_at": datetime.now().isoformat(timespec="seconds"), "updates": {}, "vulns": {}}
        needs = {"Homebrew": "brew", "App Store": "mas", "npm (global)": "npm", "Python": "python3"}
        state["missing"] = {}
        for label, fn in steps.items():
            tool = needs.get(label)
            if tool and not shutil.which(tool):
                state["missing"][label] = tool
                state["updates"][label] = []
                continue
            try:
                state["updates"][label] = [i for i in fn() if i["name"] not in skip]
            except Exception as e:
                state["updates"][label] = [{"name": f"scan failed: {e}", "current": "", "latest": "", "cmd": "", "severity": "error"}]
        state["vulns"]["Exploited in the wild (CISA KEV)"] = scan_kev(cfg["kev_days"])
        if shutil.which("osv-scanner"):
            state["vulns"]["Project dependencies (OSV)"] = scan_osv(cfg["project_roots"])
        else:
            state["missing"]["Project dependencies"] = "osv-scanner"
        tmp = STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE)
        print(f"wrote {STATE}")
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())

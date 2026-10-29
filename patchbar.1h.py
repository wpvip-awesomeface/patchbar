#!/usr/bin/env python3
# <swiftbar.title>Patchbar</swiftbar.title>
# <swiftbar.desc>Outdated software + known vulnerabilities on this Mac.</swiftbar.desc>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideDisablePlugin>true</swiftbar.hideDisablePlugin>
"""SwiftBar plugin: reads the cached scan and renders the menu. Kicks off a background scan when stale."""
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HOME = Path.home()
STATE = HOME / "Library/Caches/patchbar/state.json"
# SwiftBar runs a symlink of this file; resolve to find scan.py next to the real one.
SCAN = Path(os.path.realpath(__file__)).parent / "scan.py"
COPY = SCAN.parent / "copy.sh"
VET = SCAN.parent / "vet.py"
REPO = SCAN.parent
BREW_PATH = "/opt/homebrew/bin:/usr/local/bin"
STALE_SECONDS = 6 * 3600
MAX_ROWS = 25


def esc(s):
    return str(s).replace("|", "/")


def start_scan():
    subprocess.Popen(["/usr/bin/python3", str(SCAN)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)


RUN_DIR = HOME / "Library/Caches/patchbar/run"


def term(cmd):
    """Open cmd in a new Terminal window.

    SwiftBar's terminal=true types the command into Terminal, which cuts off long lines and leaves the
    shell stuck on an open quote. A .command script file avoids typing and quoting entirely.
    """
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    script = RUN_DIR / f"{hashlib.sha1(cmd.encode()).hexdigest()[:12]}.command"
    if not script.exists():
        script.write_text(
            "#!/bin/zsh -l\n"
            "clear\n"
            f"echo {shlex.quote('Patchbar running: ' + cmd)}\n"
            "echo\n"
            f"{cmd}\n"
            "echo\n"
            "echo 'Done. Patchbar is re-scanning in the background; the menu updates in a few minutes.'\n"
            f"(/usr/bin/python3 {shlex.quote(str(SCAN))} >/dev/null 2>&1 &)\n"
        )
        script.chmod(0o755)
    return f"bash=/usr/bin/open param1={script} terminal=false refresh=false"


def copy(cmd):
    return f'bash={COPY} param1="{cmd}" terminal=false refresh=false'


def action(text, cmd, extra="", run=None):
    """A row that runs cmd (or its vetted form, run) in Terminal; holding Option swaps it for a copy row."""
    print(f"{text} | {term(run or cmd)}{extra}")
    depth = text[:len(text) - len(text.lstrip("-"))]
    label = cmd if len(cmd) <= 60 else cmd[:57] + "…"
    print(f"{depth}Copy: {esc(label)} | {copy(cmd)} alternate=true sfimage=doc.on.clipboard")


VET_ECO = {"npm (global)": "npm", "Python": "pypi"}


def vetted(label, items, cmd):
    """npm and pip updates go through vet.py, which checks the new versions for red flags, then installs them."""
    eco = VET_ECO.get(label)
    pkgs = [f"{i['name']}@{i['current']}" for i in items if i.get("cmd")]
    if not eco or not cmd or not pkgs:
        return cmd
    return " ".join(["/usr/bin/python3", shlex.quote(str(VET)), eco, *map(shlex.quote, pkgs)])


def section_cmd(label, items):
    """One command that updates everything in a section."""
    names = [i["name"] for i in items if i.get("cmd")]
    if not names:
        return ""
    if label == "Homebrew":
        return "brew upgrade"
    if label == "App Store":
        return "mas upgrade"
    if label == "npm (global)":
        return "npm install -g " + " ".join(f"{n}@latest" for n in names)
    if label == "Python":
        return "python3 -m pip install -U " + " ".join(names)
    return " ; ".join(i["cmd"] for i in items if i.get("cmd"))


def main():
    shutil.rmtree(RUN_DIR, ignore_errors=True)  # rebuilt below from the current scan
    if not STATE.exists():
        start_scan()
        print("| sfimage=shield")
        print("---")
        print("First scan running (a few minutes)… | color=gray")
        print("Refresh | refresh=true")
        return

    st = json.loads(STATE.read_text())
    age = time.time() - STATE.stat().st_mtime
    if age > STALE_SECONDS:
        start_scan()

    updates = st["updates"]
    missing = st.get("missing", {})
    kev = st["vulns"].get("Exploited in the wild (CISA KEV)", [])
    # A KEV hit only counts as "act now" if a matching update is actually pending on this Mac.
    pending = {i["name"].lower(): i for items in updates.values() for i in items}
    label_of = {id(i): label for label, items in updates.items() for i in items}
    for k in kev:
        words = [w for w in k["name"].lower().replace("group", "").split() if len(w) > 2]
        if k["name"].startswith("Apple"):
            k["fix"] = updates.get("macOS") and updates["macOS"][0]
        else:
            k["fix"] = next((pending[w] for w in words if w in pending), None)
    kev_real = [k for k in kev if k.get("severity") == "EXPLOITED" and k.get("fix")]
    osv = st["vulns"].get("Project dependencies (OSV)", [])
    n_updates = sum(len(v) for v in updates.values())
    security_os = [i for i in updates.get("macOS", []) if i["severity"] == "security"]

    by_dir = defaultdict(lambda: defaultdict(int))
    for v in osv:
        by_dir[v["dir"]][v["severity"]] += 1
    critical_projects = sorted(
        ((d, c) for d, c in by_dir.items() if c["CRITICAL"] or c["HIGH"]),
        key=lambda x: (-x[1]["CRITICAL"], -x[1]["HIGH"]))

    # Menu bar title: one glyph per problem type, only when nonzero.
    #   flame = exploited bug with a fix waiting, ladybug = projects with critical deps, arrow = updates.
    crit_projects = [d for d, c in critical_projects if c["CRITICAL"]]
    parts = []
    if kev_real or security_os:
        parts.append(f":flame.fill: {len(kev_real) + len(security_os)}")
    if crit_projects:
        parts.append(f":ladybug.fill: {len(crit_projects)}")
    if n_updates:
        parts.append(f":arrow.down.circle: {n_updates}")
    color = " sfcolor=#e5484d color=#e5484d" if kev_real or security_os else ""
    tip = (f"{len(kev_real)} exploited bugs with a fix waiting · {len(crit_projects)} projects with critical "
           f"dependency vulnerabilities · {n_updates} updates")
    if parts:
        print(f"{'  '.join(parts)} | symbolize=true tooltip={tip}{color}")
    else:
        print("| sfimage=checkmark.shield tooltip=All clear")
    print("---")

    when = datetime.fromisoformat(st["scanned_at"]).strftime("%b %-d, %-I:%M %p")
    print(f"Last scan: {when} | color=gray size=12")
    lock = STATE.parent / "scan.lock"
    if lock.exists() and time.time() - lock.stat().st_mtime < 900:
        print("Scanning now… the menu updates when it finishes | color=gray size=12 sfimage=hourglass")
    print("Scan now | bash=/usr/bin/python3 param1=" + str(SCAN) + " terminal=false refresh=true sfimage=arrow.clockwise")
    print("---")

    print(f"Actively exploited · {len(kev_real)} need patching | sfimage=flame.fill sfcolor=#e5484d")
    if not kev:
        print("--Nothing matching your apps in the last 45 days | color=gray")
    for k in kev:
        fix = k.get("fix")
        status = "update pending" if fix else "you look patched"
        print(f"--{esc(k['name'])} · {k['id']} · {status} | href={k['url']} color={'#e5484d' if fix else 'gray'}")
        if fix:
            action(f"----Patch now: {esc(fix['name'])} → {esc(fix['latest'])}", fix["cmd"], " sfimage=bolt.fill",
                   vetted(label_of.get(id(fix)), [fix], fix["cmd"]))
        if k.get("title"):
            print(f"----{esc(k['title'])} | color=gray size=12")
            print(f"----Added {k['added']} · CISA patch-by {k.get('due')} | color=gray size=12")
        print(f"----Read advisory | href={k['url']}")
    print("--CISA KEV catalog | href=https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

    print("---")
    # macOS updates need a restart, so they stay out of the one-click "everything" run.
    sections = [(l, i, section_cmd(l, i)) for l, i in updates.items() if l != "macOS"]
    everything = " ; ".join(c for _, _, c in sections if c)
    if everything:
        action(f"Update everything ({n_updates - len(updates.get('macOS', []))})", everything,
               " sfimage=bolt.circle.fill sfcolor=#30a46c", " ; ".join(vetted(l, i, c) for l, i, c in sections if c))
    print("Hold ⌥ Option to copy commands instead of running them | color=gray size=11")
    print(f"Updates ({n_updates}) | sfimage=arrow.down.circle")
    for label, items in updates.items():
        icon = {"macOS": "apple.logo", "Homebrew": "mug", "App Store": "bag", "npm (global)": "shippingbox",
                "Python": "chevron.left.forwardslash.chevron.right"}.get(label, "app")
        print(f"--{label} ({len(items)}) | sfimage={icon}")
        if not items:
            if label in missing:
                print(f"----Not set up: needs {missing[label]} | color=gray")
                if missing[label] in ("mas",) and shutil.which("brew", path=BREW_PATH):
                    action(f"----Set it up", f"brew install {missing[label]}", " sfimage=plus.circle")
            else:
                print("----Up to date | color=gray")
            continue
        cmd = section_cmd(label, items)
        if cmd:
            action(f"----Update all {label}", cmd, " sfimage=bolt.fill", vetted(label, items, cmd))
            print("---------")
        for i in items[:MAX_ROWS]:
            color = " color=#e5484d" if i["severity"] == "security" else ""
            action(f"----{esc(i['name'])}  {esc(i['current'])} → {esc(i['latest'])}", i["cmd"], color,
                   vetted(label, [i], i["cmd"]))
        if len(items) > MAX_ROWS:
            print(f"----…and {len(items) - MAX_ROWS} more (Update all covers them) | color=gray")

    print("---")
    print(f"Vulnerable project deps · {len(crit_projects)} critical, {len(critical_projects) - len(crit_projects)} high-only | sfimage=ladybug")
    if "Project dependencies" in missing:
        print("--Not set up: needs osv-scanner | color=gray")
        action("--Set it up", "brew install osv-scanner", " sfimage=plus.circle")
    elif not critical_projects:
        print("--No critical/high issues in lockfiles | color=gray")
    for d, c in critical_projects[:MAX_ROWS]:
        rel = d.replace(str(HOME) + "/", "~/")
        print(f"--{esc(Path(d).name)}  {c['CRITICAL']} critical · {c['HIGH']} high | {term('cd ' + repr(d) + ' && osv-scanner scan source .')}")
        print(f"----{esc(rel)} | color=gray size=12")
        print(f"----Open folder | bash=/usr/bin/open param1={d} terminal=false")
        print(f"----Fix with npm audit | {term('cd ' + repr(d) + ' && npm audit fix')}")
    print("--Severity data: OSV.dev (GitHub Advisories, NVD, PyPI, npm) | color=gray size=12")

    print("---")
    print("Patchbar | sfimage=gearshape")
    action("--Update Patchbar", f"git -C {REPO} pull --ff-only", " sfimage=arrow.triangle.2.circlepath")
    print(f"--Choose code folders to check… | bash={REPO / 'settings.sh'} param1=folders terminal=false refresh=false sfimage=folder")
    print(f"--Open settings file | bash={REPO / 'settings.sh'} param1=open terminal=false refresh=false sfimage=slider.horizontal.3")
    print(f"--Uninstall Patchbar… | bash={REPO / 'uninstall.sh'} terminal=true refresh=false sfimage=trash")


if __name__ == "__main__":
    main()

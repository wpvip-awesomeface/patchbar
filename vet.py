#!/usr/bin/env python3
"""Patchbar vet: a quick "is this update suspicious?" check before npm or pip installs anything.

Usage: vet.py [--check-only] npm name@installed ... [pypi name@installed ...]
       (name@installed..target checks a specific version instead of the latest)

For each package it compares the installed version with the newest one, using public registry data:
  - new or changed install scripts (npm preinstall/install/postinstall), or a PyPI release that only
    ships source (so pip would run its setup code)
  - a publisher who wasn't a maintainer before
  - a lost provenance attestation (earlier version had one, the new one doesn't)
  - new obfuscated code, new .pth startup files, or code that first starts running commands,
    eval'ing strings, dumping env vars, or talking to odd hosts
  - a big unexplained size jump, a very fresh release, a deprecation notice
  - an OSV malicious-package advisory (MAL-...) for the new version

Then it installs the exact versions it checked. Red flags pause and ask first.
Package files are read in memory only; nothing from them is written to disk or run.
"""
import io
import json
import re
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

DEADLINE = 30          # seconds for the whole check
MAX_DOWNLOAD = 30 << 20  # skip the code diff for archives bigger than this
MAX_FILE = 4 << 20     # read at most this much of any one file
FRESH_HOURS = 48
RED, WARN = "red", "warn"
C = {"red": "\033[31m", "warn": "\033[33m", "ok": "\033[32m", "dim": "\033[2m", "b": "\033[1m", "0": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

# Behaviours that are a red flag when a package didn't do them before but does now.
JS_PATTERNS = {
    "runs shell commands (child_process)": (RED, r"\bchild_process\b|\bexecSync\s*\(|\bspawnSync\s*\("),
    "evaluates code from strings (eval / new Function)": (RED, r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\("),
    "decodes base64 blobs": (WARN, r"Buffer\.from\([^)]{0,300}['\"]base64['\"]|\batob\s*\("),
    "reads the whole environment (process.env)": (WARN, r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries)\(\s*process\.env\s*\)"),
    "opens network connections": (WARN, r"require\(\s*['\"](?:node:)?(?:https?|net|dgram|tls)['\"]\s*\)|from\s+['\"](?:node:)?(?:https?|net|dgram|tls)['\"]"),
    "touches credential files (.npmrc, .ssh, cloud keys)": (WARN, r"\.npmrc|\.ssh/|id_rsa|\.aws/credentials|\.config/gcloud|\.kube/config"),
}
PY_PATTERNS = {
    "runs shell commands (subprocess / os.system)": (RED, r"\bsubprocess\b|\bos\.(?:system|popen|exec[lv]p?e?)\s*\("),
    "evaluates code from strings (exec / eval)": (RED, r"(?<![\w.])(?:exec|eval)\s*\(|\bcompile\s*\([^)]*['\"]exec['\"]"),
    "decodes base64 blobs": (WARN, r"\bb64decode\s*\(|\bbase64\.decodebytes\s*\("),
    "reads the whole environment (os.environ)": (WARN, r"dict\(\s*os\.environ\s*\)|os\.environ\.(?:items|copy)\s*\(\)"),
    "opens network connections": (WARN, r"\bimport\s+(?:socket|requests|httpx|urllib3)\b|\burllib\.request\b|\bhttp\.client\b"),
    "touches credential files (.ssh, .pypirc, cloud keys)": (WARN, r"\.pypirc|\.ssh/|id_rsa|\.aws/credentials|\.config/gcloud|\.kube/config"),
}
# Hosts that legitimate packages almost never hard-code but exfiltration loves.
ODD_HOSTS = (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|discord(?:app)?\.com/api/webhooks|webhook\.site|"
             r"pastebin\.com|ngrok(?:-free)?\.(?:io|app)|transfer\.sh|oast(?:ify)?\.\w+|burpcollaborator|"
             r"requestbin|pipedream\.net|api\.telegram\.org/bot")
OBFUSCATED = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
HEX_ESC = re.compile(r"\\x[0-9a-fA-F]{2}")
JS_EXT = (".js", ".cjs", ".mjs", ".jsx", ".sh")
PY_EXT = (".py", ".pth", ".sh")
COMPILED_JS = {k: (lvl, re.compile(p)) for k, (lvl, p) in JS_PATTERNS.items()}
COMPILED_PY = {k: (lvl, re.compile(p)) for k, (lvl, p) in PY_PATTERNS.items()}
ODD = re.compile(ODD_HOSTS)


def fetch(url, data=None, limit=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "patchbar-vet",
                                                          **({"Content-Type": "application/json"} if data else {})})
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read(limit + 1) if limit else r.read()
        if limit and len(body) > limit:
            raise ValueError("too big")
        return body, r.headers


def get_json(url):
    return json.loads(fetch(url)[0])


def hours_since(dt):
    return (datetime.now(timezone.utc) - dt).total_seconds() / 3600


# ---------- code scanning (shared) ----------

def scan_files(files, patterns, ext):
    """files: {path: bytes}. Returns facts about the code: which behaviours appear, odd hosts, obfuscation."""
    facts = {"behaviours": {}, "hosts": {}, "obfuscated": [], "minified": [], "binaries": [], "pth": [], "paths": set(files)}
    for path, raw in files.items():
        if path.endswith((".node", ".so", ".dylib", ".exe", ".dll")) or raw[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"MZ\x90\x00"):
            facts["binaries"].append(path)
            continue
        if path.endswith(".pth"):
            facts["pth"].append(path)
        if not path.endswith(ext) or path.endswith((".map", ".d.ts")):
            continue
        text = raw[:MAX_FILE].decode("utf-8", "replace")
        for name, (_, rx) in patterns.items():
            if name not in facts["behaviours"] and rx.search(text):
                facts["behaviours"][name] = path
        for m in ODD.findall(text):
            facts["hosts"].setdefault(m, path)
        if len(OBFUSCATED.findall(text)) > 30 or (len(text) > 5000 and len(HEX_ESC.findall(text)) * 4 > len(text) * 0.1):
            facts["obfuscated"].append(path)
        elif len(text) > 50000 and text.count("\n") < len(text) / 1000:
            facts["minified"].append(path)
    return facts


def compare_code(old, new, flags):
    if not old or not new:
        return
    for name, path in new["behaviours"].items():
        if name not in old["behaviours"]:
            level = (COMPILED_JS.get(name) or COMPILED_PY.get(name))[0]
            flags.append((level, f"new code {name}: {path}"))
    for host, path in new["hosts"].items():
        if host not in old["hosts"]:
            flags.append((RED, f"new hard-coded host {host}: {path}"))
    for path in new["obfuscated"]:
        if path not in old["paths"] or path not in old["obfuscated"]:
            flags.append((RED, f"obfuscated code: {path}"))
    if new["minified"] and not old["minified"]:
        flags.append((WARN, f"first minified file: {new['minified'][0]}"))
    added_bin = [p for p in new["binaries"] if p not in old["paths"]]
    if added_bin and not old["binaries"]:
        flags.append((WARN, f"first compiled binary: {added_bin[0]}"))
    for path in new["pth"]:
        if path not in old["pth"]:
            flags.append((RED, f"new .pth file (runs on every Python start): {path}"))


def size_jump(old, new, flags, what="unpacked size"):
    if old and new and new > 3 * old and new - old > 1 << 20:
        flags.append((WARN, f"{what} jumped {old / 1e6:.1f} MB → {new / 1e6:.1f} MB"))


# ---------- npm ----------

def npm_files(tarball_url):
    raw, headers = fetch(tarball_url, limit=MAX_DOWNLOAD)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for m in tf:
            if m.isfile():
                path = m.name.split("/", 1)[-1]  # drop the "package/" prefix
                files[path] = tf.extractfile(m).read(MAX_FILE)
    return files, headers


INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def vet_npm(name, installed, target=None):
    flags = []
    base = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    new = get_json(f"{base}/{urllib.parse.quote(target or 'latest')}")
    latest = new["version"]
    try:
        old = get_json(f"{base}/{urllib.parse.quote(installed)}")
    except Exception:
        old = None
        flags.append((WARN, f"couldn't find installed {installed} on the registry to compare"))
    if latest == installed:
        return latest, flags

    if new.get("deprecated"):
        flags.append((WARN, f"deprecated: {str(new['deprecated'])[:120]}"))
    new_scripts = {k: v for k, v in (new.get("scripts") or {}).items() if k in INSTALL_HOOKS}
    if new.get("gypfile") and "install" not in new_scripts:
        new_scripts["install"] = "node-gyp rebuild (binding.gyp)"
    if old is not None:
        old_scripts = {k: v for k, v in (old.get("scripts") or {}).items() if k in INSTALL_HOOKS}
        if old.get("gypfile") and "install" not in old_scripts:
            old_scripts["install"] = "node-gyp rebuild (binding.gyp)"
        for hook, cmd in new_scripts.items():
            if hook not in old_scripts:
                flags.append((RED, f"new {hook} script: {cmd[:120]}"))
            elif old_scripts[hook] != cmd:
                flags.append((RED, f"changed {hook} script: {old_scripts[hook][:60]} → {cmd[:60]}"))

        had_prov = bool(old.get("dist", {}).get("attestations"))
        has_prov = bool(new.get("dist", {}).get("attestations"))
        if had_prov and not has_prov:
            flags.append((RED, "no provenance attestation (the installed version had one)"))

        old_pub = (old.get("_npmUser") or {}).get("name")
        new_pub = (new.get("_npmUser") or {}).get("name")
        old_maint = {m.get("name") for m in old.get("maintainers") or []} | {old_pub}
        if new_pub and new_pub != old_pub:
            trusted = has_prov or (new.get("_npmUser") or {}).get("trustedPublisher")
            if new_pub in old_maint or trusted:
                flags.append(("info", f"published by {new_pub} (was {old_pub})"))
            else:
                flags.append((RED, f"published by {new_pub}, who wasn't a maintainer of {installed}"))
        added = {m.get("name") for m in new.get("maintainers") or []} - old_maint
        if added:
            flags.append((WARN, "new maintainers: " + ", ".join(sorted(filter(None, added)))))
        size_jump(old.get("dist", {}).get("unpackedSize"), new.get("dist", {}).get("unpackedSize"), flags)

    try:
        nf, headers = npm_files(new["dist"]["tarball"])
        if headers.get("Last-Modified"):
            age = hours_since(parsedate_to_datetime(headers["Last-Modified"]))
            if age < FRESH_HOURS:
                flags.append((WARN, f"published {age:.0f}h ago (malicious releases are usually pulled within a day or two)"))
        if old is not None:
            of, _ = npm_files(old["dist"]["tarball"])
            compare_code(scan_files(of, COMPILED_JS, JS_EXT), scan_files(nf, COMPILED_JS, JS_EXT), flags)
    except ValueError:
        flags.append(("info", "package is large; skipped the code diff"))
    return latest, flags


# ---------- PyPI ----------

def pick_wheel(files):
    wheels = [f for f in files if f["filename"].endswith(".whl")]
    order = lambda f: (0 if "none-any" in f["filename"] else 1 if "macosx" in f["filename"] and "arm64" in f["filename"] else 2)
    return sorted(wheels, key=order)[0] if wheels else None


def wheel_files(url):
    raw, _ = fetch(url, limit=MAX_DOWNLOAD)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return {i.filename: z.open(i).read(MAX_FILE) for i in z.infolist() if not i.is_dir()}


def has_provenance(name, version, filename):
    try:
        fetch(f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance")
        return True
    except urllib.error.HTTPError:
        return False


def vet_pypi(name, installed, target=None):
    flags = []
    new = get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/" + (f"{urllib.parse.quote(target)}/json" if target else "json"))
    latest = new["info"]["version"]
    if latest == installed:
        return latest, flags
    try:
        old = get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(installed)}/json")
    except Exception:
        old = None
        flags.append((WARN, f"couldn't find installed {installed} on PyPI to compare"))
    new_files = new.get("urls") or []
    if new_files and all(f.get("yanked") for f in new_files):
        flags.append((WARN, "release is yanked"))
    uploaded = min((f["upload_time_iso_8601"] for f in new_files), default=None)
    if uploaded:
        age = hours_since(datetime.fromisoformat(uploaded.replace("Z", "+00:00")))
        if age < FRESH_HOURS:
            flags.append((WARN, f"published {age:.0f}h ago (malicious releases are usually pulled within a day or two)"))
    new_whl = pick_wheel(new_files)
    if old is not None:
        old_files = old.get("urls") or []
        old_whl = pick_wheel(old_files)
        if old_whl and not new_whl:
            flags.append((RED, "no wheel any more, only source: pip would run the package's setup code"))
        ref_old = old_whl or (old_files[0] if old_files else None)
        ref_new = new_whl or (new_files[0] if new_files else None)
        if ref_old and ref_new and has_provenance(name, installed, ref_old["filename"]) \
                and not has_provenance(name, latest, ref_new["filename"]):
            flags.append((RED, "no provenance attestation (the installed version had one)"))
        size_jump(ref_old and ref_old["size"], ref_new and ref_new["size"], flags, "download size")
        if old_whl and new_whl and new_whl["size"] < MAX_DOWNLOAD and old_whl["size"] < MAX_DOWNLOAD:
            compare_code(scan_files(wheel_files(old_whl["url"]), COMPILED_PY, PY_EXT),
                         scan_files(wheel_files(new_whl["url"]), COMPILED_PY, PY_EXT), flags)
        elif new_whl:
            flags.append(("info", "package is large; skipped the code diff"))
    return latest, flags


# ---------- OSV malicious-package advisories ----------

def osv_malicious(pkgs):
    """pkgs: [(eco, name, version)] -> {index: [MAL ids]}"""
    eco_name = {"npm": "npm", "pypi": "PyPI"}
    body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": eco_name[e]}, "version": v} for e, n, v in pkgs]})
    res = json.loads(fetch("https://api.osv.dev/v1/querybatch", data=body.encode())[0])
    return {i: [v["id"] for v in r.get("vulns") or [] if v["id"].startswith("MAL-")]
            for i, r in enumerate(res.get("results", []))}


# ---------- main ----------

def parse(argv):
    eco, pkgs = None, []
    for tok in argv:
        if tok in ("npm", "pypi"):
            eco = tok
        elif eco:
            name, _, ver = tok.rpartition("@") if tok.rfind("@") > 0 else (tok, "", "?")
            ver, _, target = ver.partition("..")
            pkgs.append((eco, name, ver, target or None))
    return pkgs


def install(eco, specs):
    if not specs:
        return 0
    cmd = ["npm", "install", "-g", *specs] if eco == "npm" else ["python3", "-m", "pip", "install", "-U", *specs]
    print(f"\n{C['b']}Installing:{C['0']} {' '.join(cmd)}\n", flush=True)
    return subprocess.call(cmd)


def main():
    args = sys.argv[1:]
    check_only = "--check-only" in args
    pkgs = parse([a for a in args if a != "--check-only"])
    if not pkgs:
        print(__doc__)
        return 2
    print(f"{C['b']}Checking {len(pkgs)} update(s) for red flags…{C['0']}", flush=True)
    start = time.time()
    pool = ThreadPoolExecutor(max_workers=16)
    futs = [pool.submit(vet_npm if e == "npm" else vet_pypi, n, v, t) for e, n, v, t in pkgs]
    done, _ = wait(futs, timeout=DEADLINE)
    pool.shutdown(wait=False, cancel_futures=True)

    results = []  # (eco, name, installed, latest, flags)
    for (eco, name, installed, target), f in zip(pkgs, futs):
        if f not in done:
            results.append((eco, name, installed, None, [(WARN, "check timed out; not verified")]))
        elif f.exception():
            results.append((eco, name, installed, None, [(WARN, f"couldn't check: {f.exception()}")]))
        else:
            results.append((eco, name, installed, *f.result()))
    try:
        checked = [(i, (r[0], r[1], r[3] or pkgs[i][3])) for i, r in enumerate(results) if r[3] or pkgs[i][3]]
        mal = osv_malicious([p for _, p in checked])
        for k, (i, _) in enumerate(checked):
            for mid in mal.get(k, []):
                results[i][4].append((RED, f"OSV malicious-package advisory {mid}: https://osv.dev/vulnerability/{mid}"))
    except Exception as e:
        print(f"{C['warn']}OSV malware lookup failed ({e}); continuing without it{C['0']}")

    red, unverified = [], []
    for (eco, name, installed, latest, flags), (*_, target) in zip(results, pkgs):
        worst = RED if any(l == RED for l, _ in flags) else WARN if any(l == WARN for l, _ in flags) else "ok"
        mark = {"red": "✗", "warn": "!", "ok": "✓"}[worst]
        print(f"{C[worst]}{mark}{C['0']} {C['b']}{name}{C['0']} {installed} → {latest or target or 'latest'}")
        for level, msg in flags:
            print(f"    {C.get(level, C['dim'])}{msg}{C['0']}")
        if worst == RED:
            red.append(name)
        if not latest:
            unverified.append(name)
    print(f"{C['dim']}Checked in {time.time() - start:.1f}s{C['0']}")

    skip = set()
    if red or unverified:
        if red:
            print(f"\n{C['red']}{C['b']}Red flags on: {', '.join(red)}{C['0']}")
            print("Look at the notes above before installing. Most have an innocent reason, but not all.")
        if unverified:
            print(f"\n{C['warn']}{C['b']}Couldn't check: {', '.join(unverified)}{C['0']}")
        if check_only:
            return 1
        try:
            ans = input("[Enter] install the rest and skip flagged · [a] install all anyway · [n] install nothing: ").strip().lower()
        except EOFError:
            ans = ""
        if ans == "n":
            print("Nothing installed.")
            return 1
        if ans != "a":
            skip = set(red) | set(unverified)
    if check_only:
        return 0

    rc = 0
    for eco in ("npm", "pypi"):
        sep = "@" if eco == "npm" else "=="
        specs = [f"{n}{sep}{latest}" if latest else n for e, n, installed, latest, _ in results
                 if e == eco and n not in skip and latest != installed]
        rc = install(eco, specs) or rc
    if skip:
        print(f"\n{C['warn']}Skipped: {', '.join(sorted(skip))}{C['0']}")
    return rc


if __name__ == "__main__":
    sys.exit(main())

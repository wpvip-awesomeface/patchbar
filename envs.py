"""Patchbar envs: finds every Python and Node install on this Mac and checks each one's global packages.

Each install becomes its own menu section, with update commands pinned to that exact interpreter.
Nothing here installs or removes anything. Runs inside scan.py's background scan (needs Python 3.9+).
"""
import glob
import json
import os
import re
import shlex
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

HOME = Path.home()
BREW_PREFIXES = [p for p in ("/opt/homebrew", "/usr/local") if os.path.isdir(p + "/Cellar")]

# Security support ends (first day it's unsupported). python.org/downloads, nodejs.org/en/about/previous-releases.
PY_EOL = {"3.8": "2024-10-07", "3.9": "2025-10-31", "3.10": "2026-10-31", "3.11": "2027-10-31",
          "3.12": "2028-10-31", "3.13": "2029-10-31", "3.14": "2030-10-31", "3.15": "2031-10-31"}
NODE_EOL = {"16": "2023-09-11", "18": "2025-04-30", "19": "2023-06-01", "20": "2026-04-30", "21": "2024-06-01",
            "22": "2027-04-30", "23": "2025-06-01", "24": "2028-04-30", "25": "2026-06-01", "26": "2029-04-30"}

# Packages whose versions have to move together. "Update everything" leaves these to a "review first" item.
LOCKSTEP = [
    {"torch", "torchvision", "torchaudio", "torchtext", "torchdata"},
    {"tensorflow", "tensorflow-macos", "tensorflow-metal", "tensorflow-io", "keras", "tf-keras"},
    {"jax", "jaxlib", "jax-metal"},
    {"mlx", "mlx-lm", "mlx-metal"},
]
# Never updated through npm on a Homebrew node: brew ships these with node itself.
BREW_NODE_BUNDLED = {"npm", "corepack"}


def run(cmd, timeout=120, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, env=env)
        return p.stdout, p.returncode
    except (OSError, subprocess.TimeoutExpired) as e:
        return "", f"error: {e}"


def canon(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def eol_note(table, series):
    end = table.get(series)
    if not end:
        return ""
    if end <= date.today().isoformat():
        return f"no security fixes since {end[:7]}"
    return ""


def shell_defaults():
    """What a new Terminal window runs for python3 and node (after .zshrc, pyenv/nvm init, etc.)."""
    probe = ('python3 -c "import sys; print(\'PY=\' + sys.executable)" 2>/dev/null; '
             'node -p "\'NODE=\' + process.execPath" 2>/dev/null; true')
    out, _ = run(["/bin/zsh", "-ilc", probe], timeout=30)
    found = dict(line.split("=", 1) for line in out.splitlines() if line.startswith(("PY=", "NODE=")))
    return {k: os.path.realpath(v) for k, v in found.items()}


# ---------- Python ----------

PY_PROBE = ("import sys, os, sysconfig, json, importlib.util as u; print(json.dumps({"
            "'exe': sys.executable, 'version': '%d.%d.%d' % sys.version_info[:3], "
            "'external': os.path.exists(os.path.join(sysconfig.get_path('stdlib'), 'EXTERNALLY-MANAGED')), "
            "'pip': bool(u.find_spec('pip'))}))")


def python_candidates():
    """(source, path) for every Python we know how to find. Duplicates are dropped later by real path."""
    pyenv_root = os.environ.get("PYENV_ROOT") or str(HOME / ".pyenv")
    cands = [("pyenv", p) for p in sorted(glob.glob(f"{pyenv_root}/versions/*/bin/python3"))]
    for prefix in BREW_PREFIXES:
        cands += [("Homebrew", p) for p in sorted(glob.glob(f"{prefix}/opt/python@3.*/bin/python3.*"))
                  if re.search(r"python3\.\d+$", p)]
    cands += [("python.org", p) for p in sorted(glob.glob("/Library/Frameworks/Python.framework/Versions/3.*/bin/python3"))]
    cands += [("uv", p) for p in sorted(glob.glob(str(HOME / ".local/share/uv/python/*/bin/python3")))]
    for base in ("miniconda3", "anaconda3", "miniforge3", "mambaforge", "opt/miniconda3", "opt/anaconda3"):
        root = HOME / base
        cands += [("conda", str(p)) for p in [root / "bin/python3", *sorted(root.glob("envs/*/bin/python3"))] if p.exists()]
    # Apple's Python. Only touch it when Command Line Tools / Xcode is installed, or macOS pops an install dialog.
    dev, _ = run(["/usr/bin/xcode-select", "-p"], timeout=10)
    dev = dev.strip()
    if dev and os.path.exists(f"{dev}/usr/bin/python3"):
        cands.append(("Apple", f"{dev}/usr/bin/python3"))
    return cands


def python_envs(defaults):
    envs, seen = [], set()
    for source, path in python_candidates():
        out, rc = run([path, "-c", PY_PROBE], timeout=20)
        try:
            info = json.loads(out)
        except ValueError:
            continue
        real = os.path.realpath(info["exe"])
        if real in seen:
            continue
        seen.add(real)
        envs.append(dict(info, kind="python", source=source, path=path, real=real))
    # Whatever the shell uses but we didn't find (asdf, mise, a custom build…) still gets checked.
    if defaults.get("PY") and defaults["PY"] not in seen:
        out, _ = run([defaults["PY"], "-c", PY_PROBE], timeout=20)
        try:
            info = json.loads(out)
            envs.append(dict(info, kind="python", source="other", path=info["exe"], real=defaults["PY"]))
        except ValueError:
            pass

    for e in envs:
        e["default"] = e["real"] == defaults.get("PY")
        series = ".".join(e["version"].split(".")[:2])
        e["managed"] = e["external"] or e["source"] in ("Homebrew", "Apple", "conda") or not e["pip"]
        e["label"] = f"Python · {e['source']} {e['version']}" + (" (your default)" if e["default"] else "")
        e["notes"] = []
        if e["source"] == "Homebrew":
            e["notes"].append("Homebrew keeps this up to date; use a venv (or pipx) for packages")
        elif e["source"] == "Apple":
            e["notes"].append("Comes with Apple's Command Line Tools; Apple updates it. Leave it in place")
        elif e["source"] == "conda":
            e["notes"].append("conda manages this; update with conda, not pip")
        elif e["external"]:
            e["notes"].append("Marked externally managed, so pip won't install here")
        eol = eol_note(PY_EOL, series)
        if eol:
            e["notes"].append(f"Python {series}: {eol}")
    _pyenv_suggestions([e for e in envs if e["source"] == "pyenv"])
    _brew_suggestions([e for e in envs if e["source"] == "Homebrew"], "python@{series}")
    return envs


def _pyenv_suggestions(envs):
    if not envs:
        return
    pyenv = next((p for p in [os.environ.get("PYENV_ROOT", str(HOME / ".pyenv")) + "/bin/pyenv",
                              *(f"{b}/bin/pyenv" for b in BREW_PREFIXES)] if os.path.exists(p)), None)
    if not pyenv:
        return
    out, _ = run([pyenv, "install", "--list"], timeout=30)
    available = [v.strip() for v in out.splitlines() if re.fullmatch(r"\s*3\.\d+\.\d+\s*", v)]
    for e in envs:
        series = e["version"].rsplit(".", 1)[0]
        newest = max((v for v in available if v.startswith(series + ".")), key=vtuple, default=None)
        if newest and vtuple(newest) > vtuple(e["version"]):
            e["suggest"] = {
                "text": f"{series}.x security/bug-fix release available: {newest}",
                "cmd": f"pyenv install {newest}",
                "why": f"Installs alongside {e['version']}; switch with `pyenv global {newest}` (or per project) "
                       f"and reinstall packages there. Nothing is removed.",
            }


def _brew_suggestions(envs, formula_fmt):
    """Point out Homebrew runtimes nothing depends on. Old versions are often kept on purpose, so just say so."""
    if len(envs) < 2:
        return
    for e in envs:
        series = e["version"].rsplit(".", 1)[0] if e["kind"] == "python" else e["version"].split(".")[0]
        formula = e.get("formula") or formula_fmt.format(series=series)
        out, rc = run(["brew", "uses", "--installed", formula], timeout=60)
        if rc == 0 and not out.strip() and not e["default"]:
            e["suggest"] = {
                "text": f"No other Homebrew package needs {formula}",
                "cmd": f"brew uninstall {formula}",
                "why": "Only if you don't use it directly (scripts, venvs, IDE). Patchbar never removes it for you.",
            }


def pip_outdated(env):
    exe = env["path"]
    out, _ = run([exe, "-m", "pip", "list", "--outdated", "--format=json", "--disable-pip-version-check"], timeout=240)
    try:
        data = json.loads(out or "[]")
    except ValueError:
        return []
    items = [{"name": p["name"], "current": p["version"], "latest": p["latest_version"],
              "cmd": f"{shlex.quote(exe)} -m pip install -U {p['name']}", "severity": "update",
              "eco": "pypi", "python": exe} for p in data]
    _flag_pip_risks(exe, items)
    return items


# Runs inside the target interpreter: which installed packages would the newest versions break?
CONSTRAINT_PROBE = r"""
import json, re, sys
from importlib.metadata import distributions
try:
    from packaging.requirements import Requirement
except ImportError:
    from pip._vendor.packaging.requirements import Requirement
latest = json.loads(sys.argv[1])
canon = lambda n: re.sub(r"[-_.]+", "-", n).lower()
blocks = {}
for d in distributions():
    for r in d.requires or []:
        try:
            req = Requirement(r)
            if req.marker and not req.marker.evaluate({"extra": ""}):
                continue
        except Exception:
            continue
        n = canon(req.name)
        if n in latest and req.specifier and not req.specifier.contains(latest[n], prereleases=True):
            blocks.setdefault(n, []).append("%s needs %s%s" % (d.metadata["Name"], req.name, req.specifier))
print(json.dumps(blocks))
"""


def _flag_pip_risks(exe, items):
    """Mark updates that shouldn't be bulk -U'd: lockstep groups, pinned by another package, or pip check failures."""
    if not items:
        return
    by = {canon(i["name"]): i for i in items}
    out, _ = run([exe, "-c", CONSTRAINT_PROBE, json.dumps({n: i["latest"] for n, i in by.items()})], timeout=60)
    try:
        for n, why in json.loads(out or "{}").items():
            by[n]["review"] = "Would break: " + "; ".join(sorted(set(why))[:3])
    except (ValueError, KeyError):
        pass
    out, _ = run([exe, "-m", "pip", "check", "--disable-pip-version-check"], timeout=60)
    for line in out.splitlines():  # "a 1.0 has requirement b<2, but you have b 2.1." / "a 1.0 requires b, which is not installed."
        m = re.match(r"(\S+) \S+ (?:has requirement|requires) ([A-Za-z0-9_.\-]+)", line)
        for n in (m.groups() if m else ()):
            if canon(n) in by:
                by[canon(n)].setdefault("review", "pip check already reports a conflict here: " + line.strip()[:90])
    names = set(by)
    for group in LOCKSTEP:
        hit = names & group
        if hit:
            together = sorted(by[n]["name"] for n in hit)
            for n in hit:
                by[n].setdefault("review", "Versions must match: update " + ", ".join(together) + " together")
                by[n]["group"] = together


# ---------- Node ----------

def node_candidates():
    nvm = os.environ.get("NVM_DIR") or str(HOME / ".nvm")
    cands = [("nvm", p) for p in sorted(glob.glob(f"{nvm}/versions/node/*/bin/node"), key=lambda p: vtuple(Path(p).parent.parent.name))]
    for prefix in BREW_PREFIXES:
        cands += [("Homebrew", p) for p in sorted(glob.glob(f"{prefix}/opt/node*/bin/node"))]
    for root in (HOME / ".local/share/fnm", HOME / "Library/Application Support/fnm"):
        cands += [("fnm", str(p)) for p in sorted(root.glob("node-versions/*/installation/bin/node"))]
    cands += [("Volta", str(p)) for p in sorted((HOME / ".volta/tools/image/node").glob("*/bin/node"))]
    cands += [("asdf", str(p)) for p in sorted((HOME / ".asdf/installs/nodejs").glob("*/bin/node"))]
    if os.path.exists("/usr/local/bin/node") and not os.path.realpath("/usr/local/bin/node").startswith("/usr/local/Cellar"):
        cands.append(("nodejs.org", "/usr/local/bin/node"))
    return cands


def node_envs(defaults):
    envs, seen = [], set()
    for source, path in node_candidates():
        real = os.path.realpath(path)
        if real in seen:
            continue
        out, _ = run([path, "-v"], timeout=10)
        if not out.startswith("v"):
            continue
        seen.add(real)
        formula = re.search(r"/opt/(node(?:@\d+)?)/", path)
        envs.append({"kind": "node", "source": source, "path": path, "real": real, "bin": os.path.dirname(path),
                     "version": out.strip().lstrip("v"), "formula": formula and formula[1]})
    if defaults.get("NODE") and defaults["NODE"] not in seen:
        out, _ = run([defaults["NODE"], "-v"], timeout=10)
        if out.startswith("v"):
            envs.append({"kind": "node", "source": "other", "path": defaults["NODE"], "real": defaults["NODE"],
                         "bin": os.path.dirname(defaults["NODE"]), "version": out.strip().lstrip("v")})
    releases = _node_releases() if envs else []
    for e in envs:
        e["default"] = e["real"] == defaults.get("NODE")
        major = e["version"].split(".")[0]
        # Volta keeps globals per tool, not per node, so npm -g doesn't apply.
        e["managed"] = e["source"] == "Volta"
        e["label"] = f"Node · {e['source']} {e['version']}" + (" (your default)" if e["default"] else "")
        e["notes"] = []
        if e["source"] == "Homebrew":
            e["notes"].append("Homebrew updates node itself (and its bundled npm)")
        elif e["source"] == "Volta":
            e["notes"].append("Volta manages global tools: update with `volta install <tool>`")
        eol = eol_note(NODE_EOL, major)
        if eol:
            e["notes"].append(f"Node {major}: {eol}")
        newest = next((r for r in releases if r.split(".")[0] == major), None)
        if newest and vtuple(newest) > vtuple(e["version"]) and e["source"] in ("nvm", "fnm", "asdf"):
            tool = {"nvm": f"nvm install {newest}", "fnm": f"fnm install {newest}",
                    "asdf": f"asdf install nodejs {newest}"}[e["source"]]
            e["suggest"] = {
                "text": f"Node {major}.x update available: {newest}",
                "cmd": tool,
                "why": f"Installs alongside {e['version']}. Move global packages with "
                       f"`nvm install {newest} --reinstall-packages-from={e['version']}` (nvm). Nothing is removed.",
            }
    _brew_suggestions([e for e in envs if e["source"] == "Homebrew"], "node")
    return envs


def _node_releases():
    """Newest version of each Node major, newest first (nodejs.org's public release index)."""
    try:
        req = urllib.request.Request("https://nodejs.org/dist/index.json", headers={"User-Agent": "patchbar"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return [v["version"].lstrip("v") for v in json.load(r)]
    except Exception:
        return []


def npm_path(node_bin):
    """PATH that makes `npm` mean this node's npm, keeping a safe-npm style shim in front if there is one."""
    shims = [str(HOME / ".safe-npm/bin")] if (HOME / ".safe-npm/bin/npm").exists() else []
    return ":".join([*shims, node_bin])


def node_satisfies(version, rng):
    """Does node `version` meet an engines range like "^22.22.2 || >=26.0.0"? Syntax we don't parse counts as yes."""
    v = vtuple(version)
    for alt in rng.split("||"):
        ok = True
        for part in alt.split():
            m = re.fullmatch(r"(\^|~|>=|<=|>|<|=)?v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", part)
            if not m:
                if part in ("*", "x"):
                    continue
                return True
            op = m[1] or "="
            nums = [int(n) if n and n.isdigit() else None for n in m.groups()[1:]]
            lo = tuple(n or 0 for n in nums)
            if op == "^" or (op == "=" and nums[1] is None):
                ok = ok and lo <= v < (lo[0] + 1, 0, 0)
            elif op == "~" or (op == "=" and nums[2] is None):
                ok = ok and lo <= v < (lo[0], lo[1] + 1, 0)
            else:
                ok = ok and {">=": v >= lo, ">": v > lo, "<=": v <= lo, "<": v < lo, "=": v == lo}[op]
        if ok:
            return True
    return False


_PACKUMENTS = {}


def newest_for_node(name, node_version):
    """Newest stable release of an npm package whose engines.node accepts this node, or None if unknown."""
    if name not in _PACKUMENTS:
        try:
            req = urllib.request.Request("https://registry.npmjs.org/" + name.replace("/", "%2F"),
                                         headers={"User-Agent": "patchbar", "Accept": "application/vnd.npm.install-v1+json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                _PACKUMENTS[name] = json.load(r).get("versions", {})
        except Exception:
            _PACKUMENTS[name] = None
    versions = _PACKUMENTS[name]
    if not versions:
        return None
    fits = []
    for v, meta in versions.items():
        engines = meta.get("engines")
        rng = engines.get("node") if isinstance(engines, dict) else None
        if "-" not in v and node_satisfies(node_version, rng or "*"):
            fits.append(v)
    return max(fits, key=vtuple, default=None)


def npm_outdated(env):
    path = npm_path(env["bin"])
    out, _ = run(["npm", "outdated", "-g", "--json"], timeout=180,
                 env=dict(os.environ, PATH=path + ":" + os.environ.get("PATH", "")))
    try:
        data = json.loads(out or "{}")
    except ValueError:
        return []
    prefix = f"PATH={shlex.quote(path)}:$PATH "
    items = []
    for n, v in data.items():
        if v.get("current") == v.get("latest") or not v.get("current"):
            continue
        if env["source"] == "Homebrew" and n in BREW_NODE_BUNDLED:
            continue
        # The latest release may need a newer node than this one (npm 12 won't install on node 18), so aim
        # for the newest release this node can run; skip the package if that's what's already installed.
        # Pin whenever we know the fit: vet.py looks up the registry's "latest" on its own otherwise.
        fit = newest_for_node(n, env["version"])
        if fit and vtuple(fit) <= vtuple(v["current"]):
            continue
        latest, pin = fit or v.get("latest"), bool(fit)
        items.append({"name": n, "current": v["current"], "latest": latest,
                      "cmd": f"{prefix}npm install -g {n}@{latest if pin else 'latest'}", "severity": "update",
                      "eco": "npm", "npm_path": path, "pin": pin})
    return items


# ---------- entry point ----------

def scan(skip=()):
    """Returns (envs, sections): every install found, and {label: [outdated packages]} for the ones pip/npm may touch."""
    defaults = shell_defaults()
    with ThreadPoolExecutor(2) as pool:
        py, node = pool.submit(python_envs, defaults), pool.submit(node_envs, defaults)
        envs = py.result() + node.result()
    # Default first, then newest, so the menu reads in the order people care about.
    envs.sort(key=lambda e: (e["kind"] != "python", not e["default"], e["managed"], tuple(-x for x in vtuple(e["version"]))))
    checkable = [e for e in envs if not e["managed"]]
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(lambda e: pip_outdated(e) if e["kind"] == "python" else npm_outdated(e), checkable))
    sections = {}
    for e, items in zip(checkable, results):
        sections[e["label"]] = [i for i in items if i["name"] not in skip]
    for e in envs:
        e["checked"] = not e["managed"]
    return envs, sections

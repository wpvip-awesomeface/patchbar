#!/bin/zsh
# Patchbar settings helper: "folders" picks code folders to scan, "open" opens the settings file.
CONFIG="$HOME/.config/patchbar/config.json"
mkdir -p "${CONFIG:h}"
[ -f "$CONFIG" ] || echo '{}' > "$CONFIG"

case "$1" in
  folders)
    picked=$(osascript -e 'set fs to choose folder with prompt "Choose the folders where your code lives (hold ⌘ for several):" with multiple selections allowed' \
      -e 'set out to ""' -e 'repeat with f in fs' -e 'set out to out & POSIX path of f & linefeed' -e 'end repeat' -e 'return out' 2>/dev/null) || exit 0
    /usr/bin/python3 - "$CONFIG" "$picked" <<'PY'
import json, sys
path, picked = sys.argv[1], sys.argv[2]
cfg = json.load(open(path))
cfg["project_roots"] = [p.rstrip("/") for p in picked.splitlines() if p.strip()]
json.dump(cfg, open(path, "w"), indent=2)
PY
    osascript -e 'display notification "Saved. The next scan will use these folders." with title "Patchbar"'
    (/usr/bin/python3 "${0:A:h}/scan.py" >/dev/null 2>&1 &)
    ;;
  open)
    open -t "$CONFIG"
    ;;
esac

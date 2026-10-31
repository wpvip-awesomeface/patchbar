#!/bin/zsh
# Patchbar installer: sets up SwiftBar (the menu bar host) and the Patchbar plugin.
# Usage: ./install.sh            full install (adds osv-scanner + mas for more coverage)
#        ./install.sh --minimal  only what's required
set -e
DIR=${0:A:h}
PLUGINS="$HOME/Library/Application Support/SwiftBar/Plugins"
say() { print -P "%F{green}==>%f $1"; }

[[ $(uname) == Darwin ]] || { echo "Patchbar only runs on macOS."; exit 1; }

# Python ships with Apple's Command Line Tools; without them macOS shows an install prompt.
if ! xcode-select -p >/dev/null 2>&1; then
  say "Installing Apple Command Line Tools (a macOS window will open). Re-run this installer when it finishes."
  xcode-select --install || true
  exit 1
fi

if ! command -v brew >/dev/null; then
  [ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
fi
if ! command -v brew >/dev/null; then
  echo "Patchbar needs Homebrew. Install it from https://brew.sh, then re-run this installer."
  exit 1
fi

if [ ! -d /Applications/SwiftBar.app ]; then
  say "Installing SwiftBar"
  brew install --cask swiftbar
fi

if [[ $1 != --minimal ]]; then
  for tool in osv-scanner mas; do
    command -v $tool >/dev/null || { say "Installing $tool"; brew install $tool; }
  done
fi

say "Linking the Patchbar plugin"
mkdir -p "$PLUGINS"
chmod +x "$DIR"/*.sh "$DIR"/*.py
rm -f "$PLUGINS"/patchbar.*.py(N)  # (N): no match on a first install is fine, not a zsh error
ln -sf "$DIR/patchbar.1h.py" "$PLUGINS/patchbar.1h.py"
defaults write com.ameba.SwiftBar PluginDirectory -string "$PLUGINS"

say "Starting the first scan in the background (takes a few minutes)"
(/usr/bin/python3 "$DIR/scan.py" >/dev/null 2>&1 &)

pkill -x SwiftBar 2>/dev/null || true
sleep 1
open -a SwiftBar
say "Done. Look for the shield in your menu bar."

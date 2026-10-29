#!/bin/zsh
# Removes the Patchbar plugin and its cache. Leaves SwiftBar and other Homebrew tools installed.
DIR=${0:A:h}
read -q "?Remove Patchbar? [y/N] " || { echo; exit 0; }
echo
rm -f "$HOME/Library/Application Support/SwiftBar/Plugins"/patchbar.*.py
rm -rf "$HOME/Library/Caches/patchbar"
echo "Patchbar removed from the menu bar."
echo "Settings kept in ~/.config/patchbar (delete it if you like)."
echo "To remove SwiftBar too: brew uninstall --cask swiftbar"
[[ $DIR == $HOME/.patchbar ]] && echo "To delete the code: rm -r ~/.patchbar"

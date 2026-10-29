#!/bin/zsh
# Copies an update command to the clipboard and confirms with a notification.
printf '%s' "$1" | pbcopy
osascript -e 'display notification "Paste it into Terminal." with title "Patchbar: command copied"' >/dev/null 2>&1

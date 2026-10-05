#!/usr/bin/env bash
# Cyclops Safe Copier — per-user install (no sudo needed).
#   bash install.sh             add the command + the app-menu entry
#   bash install.sh --uninstall remove exactly those two things again
# Nothing outside ~/.local/bin and ~/.local/share/applications is touched.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
BIN="$HOME/.local/bin/cyclops-safe-copy"
DESKTOP="$HOME/.local/share/applications/cyclops-safe-copier.desktop"

if [[ "${1:-}" == "--uninstall" ]]; then
  if [[ -L "$BIN" && "$(readlink -f "$BIN")" == "$HERE/bin/cyclops-safe-copy" ]]; then rm -f -- "$BIN"; echo "removed $BIN"; fi
  if [[ -f "$DESKTOP" ]] && grep -q "$HERE/launcher/" "$DESKTOP"; then rm -f -- "$DESKTOP"; echo "removed $DESKTOP"; fi
  exit 0
fi

command -v rsync >/dev/null || { echo "rsync is required: sudo apt install rsync"; exit 1; }
chmod +x "$HERE/bin/cyclops-safe-copy" "$HERE/cyclops_safe_copy.py" "$HERE/launcher/cyclops_safe_copier_gui.py"
mkdir -p "$(dirname "$BIN")" "$(dirname "$DESKTOP")"
if [[ -e "$BIN" && ! -L "$BIN" ]]; then echo "refusing: $BIN exists and is not a symlink"; exit 1; fi
ln -sfn "$HERE/bin/cyclops-safe-copy" "$BIN"
cat > "$DESKTOP" <<DESK
[Desktop Entry]
Type=Application
Version=1.5
Name=Cyclops Safe Copier
GenericName=Verified Copy
Comment=Copy folders to another disk and prove the copy is exact — never deletes
Exec=/usr/bin/env python3 "$HERE/launcher/cyclops_safe_copier_gui.py"
Path=$HERE
Icon=$HERE/launcher/cyclops-safe-copier.svg
Terminal=false
Categories=Utility;Archiving;
Keywords=copy;backup;verify;rsync;checksum;HDD;safe;
StartupNotify=true
StartupWMClass=cyclops-safe-copier
DESK
echo "installed: $BIN"
echo "installed: $DESKTOP  (look for 'Cyclops Safe Copier' in your app menu)"
python3 -c 'import gi; gi.require_version("Gtk","3.0"); from gi.repository import Gtk' 2>/dev/null \
  || echo "note: for the window app install GTK bindings: sudo apt install python3-gi gir1.2-gtk-3.0"

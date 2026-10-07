#!/usr/bin/env bash
# ClipVeil - Linux build (single executable). Run next to clipveil.py:
#   chmod +x build_linux.sh && ./build_linux.sh        (other Python: PYTHON=python3.12 ./build_linux.sh)
set -e
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
[ -f clipveil.py ] || { echo "ERROR: clipveil.py is not in $(pwd)"; exit 1; }

echo "[1/4] Checking system dependencies..."
MISSING=""
$PY -c "import tkinter" 2>/dev/null || MISSING="$MISSING python3-tk"
$PY -m venv --help >/dev/null 2>&1 || MISSING="$MISSING python3-venv"
command -v xclip >/dev/null 2>&1 || command -v xsel >/dev/null 2>&1 || MISSING="$MISSING xclip"
if [ -n "$MISSING" ]; then
  echo "  Missing:$MISSING"
  if command -v apt >/dev/null 2>&1; then
    echo "  Install: sudo apt install -y$MISSING libnotify-bin gir1.2-appindicator3-0.1"
  elif command -v dnf >/dev/null 2>&1; then
    echo "  Install: sudo dnf install -y python3-tkinter xclip libnotify libappindicator-gtk3"
  fi
  exit 1
fi

echo "[2/4] Virtual environment and packages (.venv)..."
# Recent Ubuntu/Debian refuse pip installs into the system Python, so everything goes into .venv.
[ -d .venv ] || $PY -m venv .venv
. .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt pyinstaller

echo "[3/4] Building..."
# Theme files and runtime-loaded backends must be listed explicitly; Xlib powers hotkeys and re-copy detection.
# Excluded: image codecs, fonts and TLS the app never uses (the binary shrinks from ~22 MB to ~14 MB).
EXCLUDES=""
for m in PIL._avif PIL.AvifImagePlugin PIL._webp PIL.WebPImagePlugin PIL._imagingft PIL._imagingcms PIL.ImageCms PIL._imagingmath PIL.ImageMath PIL._imagingmorph PIL.ImageMorph PIL.ImageQt PIL.ImageShow PIL.ImageGrab ssl _ssl _hashlib unittest pydoc doctest lib2to3 distutils setuptools pkg_resources xmlrpc sqlite3 _sqlite3 curses ensurepip venv idlelib turtledemo turtle tkinter.test numpy; do
  EXCLUDES="$EXCLUDES --exclude-module $m"
done
python -m PyInstaller --noconfirm --onefile --strip --name clipveil $EXCLUDES \
  --collect-data customtkinter \
  --hidden-import darkdetect \
  --hidden-import PIL._tkinter_finder \
  --hidden-import pynput.keyboard._xorg \
  --hidden-import pynput.mouse._xorg \
  --hidden-import pystray._xorg \
  --hidden-import pystray._appindicator \
  --hidden-import pystray._gtk \
  --collect-submodules Xlib \
  clipveil.py
python clipveil.py --export-icon dist/clipveil.png >/dev/null

echo "[4/4] Done."
echo "App:   $(pwd)/dist/clipveil"
echo "Icon:  $(pwd)/dist/clipveil.png"
echo "Run:   ./dist/clipveil      (menu entry and autostart: see README)"

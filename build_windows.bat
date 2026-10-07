@echo off
REM ClipVeil - Windows build (single .exe). Put this file next to clipveil.py and double-click it.
REM Python 3.9-3.13 recommended.
setlocal
cd /d "%~dp0"

if not exist "clipveil.py" (
  echo ERROR: clipveil.py is not in this folder: %cd%
  pause
  exit /b 1
)

echo [1/3] Installing packages...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
  echo.
  echo ERROR: package installation failed.
  echo   - Is Python installed? Check with "python --version".
  echo   - A very new Python may not have pystray/Pillow wheels yet; try Python 3.12 or 3.13.
  pause
  exit /b 1
)

echo.
echo [2/3] Building the icon and the EXE...
python clipveil.py --export-icon clipveil.ico || (echo ERROR: icon could not be created & pause & exit /b 1)
REM customtkinter theme files and the runtime-loaded pynput/pystray backends must be included explicitly.
python -m PyInstaller --noconfirm --noconsole --onefile --name ClipVeil ^
  --icon clipveil.ico ^
  --collect-data customtkinter ^
  --hidden-import darkdetect ^
  --hidden-import PIL._tkinter_finder ^
  --hidden-import pynput.keyboard._win32 ^
  --hidden-import pynput.mouse._win32 ^
  --hidden-import pystray._win32 ^
  clipveil.py
if errorlevel 1 (
  echo ERROR: PyInstaller failed.
  pause
  exit /b 1
)

echo.
echo [3/3] Done: "%cd%\dist\ClipVeil.exe"
echo It also runs on Windows machines without Python.
echo If Explorer still shows an old icon, copy the file to another folder (icon cache).
echo To start it with Windows, put a shortcut in  Win+R -^> shell:startup
pause

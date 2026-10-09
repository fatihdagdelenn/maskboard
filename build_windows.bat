@echo off
REM MaskBoard - Windows build (single .exe). Put this file next to maskboard.py and double-click it.
REM Python 3.9-3.13 recommended.
setlocal
cd /d "%~dp0"

if not exist "maskboard.py" (
  echo ERROR: maskboard.py is not in this folder: %cd%
  pause
  exit /b 1
)

REM A running MaskBoard.exe (often hidden in the tray) locks dist\MaskBoard.exe and makes the build fail.
taskkill /IM MaskBoard.exe /F >nul 2>&1

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
python maskboard.py --export-icon maskboard.ico || (echo ERROR: icon could not be created & pause & exit /b 1)
REM customtkinter theme files and the runtime-loaded pynput/pystray backends must be included explicitly.
REM Excluded: image codecs, fonts and TLS the app never uses, which keeps the exe small.
set EXCLUDES=--exclude-module PIL._avif --exclude-module PIL.AvifImagePlugin --exclude-module PIL._webp --exclude-module PIL.WebPImagePlugin --exclude-module PIL._imagingft --exclude-module PIL._imagingcms --exclude-module PIL.ImageCms --exclude-module PIL._imagingmath --exclude-module PIL.ImageMath --exclude-module PIL._imagingmorph --exclude-module PIL.ImageMorph --exclude-module PIL.ImageQt --exclude-module PIL.ImageShow --exclude-module PIL.ImageGrab --exclude-module ssl --exclude-module _ssl --exclude-module _hashlib --exclude-module unittest --exclude-module pydoc --exclude-module doctest --exclude-module lib2to3 --exclude-module distutils --exclude-module setuptools --exclude-module pkg_resources --exclude-module xmlrpc --exclude-module sqlite3 --exclude-module _sqlite3 --exclude-module curses --exclude-module ensurepip --exclude-module venv --exclude-module idlelib --exclude-module turtledemo --exclude-module turtle --exclude-module tkinter.test --exclude-module numpy
python -m PyInstaller --noconfirm --noconsole --onefile --name MaskBoard %EXCLUDES% ^
  --icon maskboard.ico ^
  --collect-data customtkinter ^
  --hidden-import darkdetect ^
  --hidden-import PIL._tkinter_finder ^
  --hidden-import pynput.keyboard._win32 ^
  --hidden-import pynput.mouse._win32 ^
  --hidden-import pystray._win32 ^
  maskboard.py
if errorlevel 1 (
  echo ERROR: PyInstaller failed.
  pause
  exit /b 1
)

echo.
echo [3/3] Done: "%cd%\dist\MaskBoard.exe"
echo It also runs on Windows machines without Python.
echo If Explorer still shows an old icon, copy the file to another folder (icon cache).
echo To start it with Windows, put a shortcut in  Win+R -^> shell:startup
pause

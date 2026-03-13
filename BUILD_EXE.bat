@echo off
title WebSec Scanner v5.0 - Build Tool
color 0B

echo.
echo  =========================================================
echo   WebSec Scanner v5.0 - Enterprise Edition - EXE Builder
echo  =========================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo.
    echo  Install Python 3.8+ from https://python.org
    echo  During install: CHECK "Add Python to PATH"
    echo.
    pause & exit /b 1
)

echo [OK] Python found:
python --version
echo.

echo [1/3] Installing PyInstaller...
pip install pyinstaller --quiet --upgrade
if errorlevel 1 ( echo [ERROR] PyInstaller install failed & pause & exit /b 1 )
echo [OK] PyInstaller ready
echo.

echo [2/3] Compiling WebSecScanner.exe...
echo       (This takes 1-3 minutes - please wait)
echo.

pyinstaller ^
  --onefile ^
  --windowed ^
  --name "WebSecScanner" ^
  --clean ^
  websec_scanner.py

if errorlevel 1 (
    echo.
    echo [ERROR] Compilation failed. See output above.
    pause & exit /b 1
)

echo.
echo [3/3] Cleaning build files...
rmdir /s /q build 2>nul
del /q *.spec   2>nul

echo.
echo  =========================================================
echo   SUCCESS!
echo.
echo   EXE location:  dist\WebSecScanner.exe
echo.
echo   The EXE is fully portable - copy it anywhere!
echo  =========================================================
echo.
pause

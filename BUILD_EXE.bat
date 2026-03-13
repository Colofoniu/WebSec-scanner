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
echo Install Python from https://python.org
echo During install CHECK "Add Python to PATH"
echo.
pause
exit /b 1
)

echo [OK] Python found:
python --version
echo.

echo [1/3] Installing / Updating PyInstaller...
python -m pip install --upgrade pip >nul
python -m pip install pyinstaller --upgrade >nul

if errorlevel 1 (
echo.
echo [ERROR] Failed to install PyInstaller
pause
exit /b 1
)

echo [OK] PyInstaller ready
echo.

echo [2/3] Building WebSecScanner.exe...
echo This may take 1-3 minutes...
echo.

python -m PyInstaller ^
--onefile ^
--windowed ^
--clean ^
--name WebSecScanner ^
WebSec5.py

if errorlevel 1 (
echo.
echo [ERROR] Compilation failed!
pause
exit /b 1
)

echo.
echo [3/3] Cleaning temporary files...
rmdir /s /q build 2>nul
del /q *.spec 2>nul

echo.
echo =========================================================
echo BUILD SUCCESSFUL!
echo.
echo Your EXE is here:
echo dist\WebSecScanner.exe
echo.
echo The EXE is portable and can run on other PCs.
echo =========================================================
echo.

pause

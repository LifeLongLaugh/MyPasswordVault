@echo off
setlocal

REM Move to the folder where this BAT file is located (Root)
cd /d "%~dp0"

REM Run the PowerShell vault script from the src folder
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "src\vault.ps1"

REM Close this launcher window after vault exits
exit /b 0
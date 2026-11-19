@echo off
rem Starts Disk Space Triage as the current (standard) user. Read-only; see README.md.
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0DiskSpaceTriage.ps1" %*
if errorlevel 1 (
  echo.
  echo Disk Space Triage stopped with an error. The message above says why.
  pause
)

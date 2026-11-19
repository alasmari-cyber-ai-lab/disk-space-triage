@echo off
rem Starts Disk Space Triage as the current (standard) user. Read-only; see README.md.
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0DiskSpaceTriage.ps1" %*

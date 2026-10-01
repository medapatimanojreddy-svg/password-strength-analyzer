@echo off
title CipherGuard Live Server
echo Starting CipherGuard Password Strength Analyzer...

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python server.py
    pause
    exit /b
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py server.py
    pause
    exit /b
)

where npx >nul 2>nul
if %ERRORLEVEL% equ 0 (
    call npx live-server --port=8080
    pause
    exit /b
)

where node >nul 2>nul
if %ERRORLEVEL% equ 0 (
    call npx.cmd live-server --port=8080
    pause
    exit /b
)

echo Neither Python nor Node.js/npx was found in PATH.
pause

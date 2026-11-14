@echo off
title IntelliSec - Stopping Servers
color 0C

echo.
echo  Stopping all IntelliSec processes...
echo.

taskkill /FI "WINDOWTITLE eq IntelliSec Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq IntelliSec Frontend*" /F >nul 2>&1

:: Also kill by port in case window titles don't match
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5173 ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

echo  [✓] All IntelliSec servers stopped.
echo.
pause

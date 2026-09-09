@echo off
title IntelliSec Launcher
color 0A
echo.
echo  ==========================================
echo   IntelliSec - Starting Servers
echo  ==========================================
echo.

REM Kill anything on ports 8000 and 5173 first
echo Cleaning up old processes...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":8000 "') do (
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":5173 "') do (
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 2 /nobreak >nul

echo Starting Backend (port 8000)...
start "IntelliSec Backend" cmd /k "cd /d %~dp0backend && .venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo Waiting for backend to start...
timeout /t 5 /nobreak >nul

echo Starting Frontend (port 5173)...
start "IntelliSec Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo  ==========================================
echo   Both servers starting in separate windows
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo  ==========================================
echo.
timeout /t 4 /nobreak >nul

REM Open browser
start "" http://localhost:5173

echo Done! You can close this window.

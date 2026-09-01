@echo off
title IntelliSec - Starting...
echo ========================================
echo   IntelliSec - Starting Both Servers
echo ========================================
echo.
echo Starting Backend (port 8000)...
start "IntelliSec Backend" cmd /k "cd /d C:\Users\aman7\OneDrive\Desktop\intellisec\backend && .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
echo Starting Frontend (port 5173)...
timeout /t 3 /nobreak >nul
start "IntelliSec Frontend" cmd /k "cd /d C:\Users\aman7\OneDrive\Desktop\intellisec\frontend && npm run dev"
echo.
echo Both servers starting...
echo Opening browser in 5 seconds...
timeout /t 5 /nobreak >nul
start http://localhost:5173
echo.
echo Servers are running in separate windows.
echo Close those windows to stop the servers.

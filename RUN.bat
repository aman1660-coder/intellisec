@echo off
title IntelliSec
color 0A

echo.
echo  ==========================================
echo   IntelliSec - Starting All Servers
echo  ==========================================
echo.

echo [1/2] Starting Backend on port 8000...
start "IntelliSec-Backend" /min cmd /k "cd /d C:\Users\aman7\OneDrive\Desktop\intellisec\backend && .venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-exclude strix_runs --reload-exclude .data"

echo [2/2] Starting Frontend on port 5173...
start "IntelliSec-Frontend" /min cmd /k "cd /d C:\Users\aman7\OneDrive\Desktop\intellisec\frontend && npm run dev"

echo.
echo Waiting for servers to start...
timeout /t 8 /nobreak > nul

echo.
echo  ==========================================
echo   READY! Opening browser...
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo  ==========================================
echo.
echo   Keep the 2 minimized CMD windows open!
echo   Close them to stop the servers.
echo.

start http://localhost:5173

pause

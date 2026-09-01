@echo off
title IntelliSec - Backend (port 8000)
cd /d "C:\Users\aman7\OneDrive\Desktop\intellisec\backend"
echo Starting IntelliSec Backend on http://localhost:8000 ...
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause

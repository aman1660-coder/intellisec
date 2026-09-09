module.exports = {
  apps: [
    {
      name: "intellisec-backend",
      script: ".venv/Scripts/python.exe",
      args: "-m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload",
      cwd: "C:/Users/aman7/OneDrive/Desktop/intellisec/backend",
      interpreter: "none",
      autorestart: true,
      watch: false,
      env: {
        PYTHONPATH: "C:/Users/aman7/OneDrive/Desktop/intellisec/backend"
      }
    },
    {
      name: "intellisec-frontend",
      script: "node_modules/.bin/vite.cmd",
      args: "--host 0.0.0.0 --port 5173",
      cwd: "C:/Users/aman7/OneDrive/Desktop/intellisec/frontend",
      interpreter: "none",
      autorestart: true,
      watch: false,
    }
  ]
};

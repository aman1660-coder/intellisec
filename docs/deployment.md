# IntelliSec Deployment

## Backend on Render

1. Create a new Render web service from this repository.
2. Use `backend` as the root directory.
3. Choose Docker as the runtime.
4. Set environment variables from `.env.example`.
5. Set `FRONTEND_URL` and `CORS_ORIGINS` to the deployed Vercel URL.
6. Set `MONGODB_URI` to a MongoDB Atlas connection string for persistent scan history.

The health endpoint is `/api/health`.

## Frontend on Vercel

1. Create a Vercel project using `frontend` as the root directory.
2. Set `VITE_API_URL=https://your-render-service.onrender.com/api`.
3. Deploy. `vercel.json` rewrites client routes to the React entry point.

## MongoDB Atlas

The backend falls back to local JSON storage for local demos. For deployment, configure `MONGODB_URI` so users, scans, findings, reports, compliance mappings, and PQC results persist.


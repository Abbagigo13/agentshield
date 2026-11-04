# Deployment
Backend (Railway): root install, `npm run build`, start `node apps/api/dist/index.js`, set PORT, JWT_SECRET, DATABASE_URL (Railway PostgreSQL + `npx prisma migrate deploy`), SERV_API_KEY, REPPO_API_KEY, CORS_ORIGIN.
Frontend (Vercel or Railway): build `apps/web`, set VITE_API_URL to the API origin (or same-origin proxy).
Verify after deploy: GET /health, register, run the Live Monitoring demo, Integrations → Test connection for both providers.

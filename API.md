# API (v1, Bearer JWT unless noted)
Auth: POST /auth/register, POST /auth/login, GET /auth/me.
Agents: POST/GET /agents, GET /agents/:id (create returns the raw agent key once).
Actions: POST /actions/analyze (idempotencyKey supported), GET /actions, GET /actions/:id, GET /actions/:id/trace.
Evaluations: GET /evaluations, GET /evaluations/:id (polls Reppo while PENDING), POST /evaluations/:id/retry.
Decisions: GET /decisions, POST /decisions/:id/approve, POST /decisions/:id/reject.
Policies: GET/POST /policies, PATCH/DELETE /policies/:id (PATCH creates a PolicyVersion).
Analytics: GET /analytics/overview|threats|improvements. Audit: GET /audit-logs.
Integrations: GET /integrations/status, POST /integrations/test {provider}. Health: GET /health.
Errors: `{error}` with 400/401/404/409/502; success: `{data}`.

- `POST /api/v1/events/ticket` (user auth) -> `{ ticket }` valid 60s; connect with `GET /api/v1/events?token=<ticket>`. Session JWTs are rejected on the stream.

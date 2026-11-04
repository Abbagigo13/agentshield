# Security
- Auth: bcrypt password hashes, JWT (7d), agent keys stored as SHA-256 hashes, shown once.
- Server-only secrets: SERV_API_KEY / REPPO_API_KEY never reach the browser. `.env` is gitignored.
- Reppo privacy: submissions are visible to Reppo's evaluation network. `redact()` drops secret-named fields fail-closed, masks key/token/email/card patterns, and caps payload size. Use synthetic data in demos.
- Enforcement: deterministic rules run before any AI call; AI cannot override critical/hard blocks; pending/missing evaluations never approve.
- Platform: Zod validation, 256kb body limit, rate limiting (300/min), CORS allow-list via CORS_ORIGIN, Prisma ORM (no string SQL) in the Postgres path.
- Detection limits (honest): heuristics catch known injection/secret patterns and policy breaches; they do not guarantee detection of novel obfuscation, semantic manipulation, or multi-step attacks. SERV/Reppo add judgment but can err — hence human REVIEW routing.
- Report issues privately to the maintainers; do not open public issues with live credentials.

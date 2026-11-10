# Security (V2)

## Enforcement invariants (tested)
- BLOCK/HOLD/PENDING_EVALUATION decisions can never be approved via the approval API. Only a PENDING approval on an owner-scoped REVIEW decision can be decided, exactly once; concurrent attempts yield one 200 and one 409. Every human decision is audit-logged.
- A missing, pending, queued, failed, denied, unknown-status, or stale Reppo evaluation can never auto-approve. Only a schema-validated SETTLED verdict with decision=accept, route=auto-ship, confidence high|medium, fresh settledAt, and score >= threshold (default 80) can approve.
- SERV failures are never ignored: servStatus=error|unavailable routes to REVIEW. SERV critical threats and threatDetected disagreements block/review respectively.
- Hard deterministic violations override any AI score.

## Authentication & tenancy
- Users: bcrypt + JWT (7d). JWT_SECRET is required in production (>=32 chars, startup refuses otherwise); development generates an ephemeral per-boot secret. Generate: `openssl rand -hex 32`.
- Agents: API keys (`as_agent_...`) verified by SHA-256 hash comparison (constant-time), with revocation, expiry, ACTIVE-status, and self-only action submission. Rotation revokes all prior keys. Keys are shown once; only hashes persist.
- Every list/detail/analytics/audit query is owner-scoped. Cross-tenant IDs return 404 and empty lists (regression-tested).

## Data protection
- Action payloads and reasoning are redacted BEFORE persistence; traces therefore cannot disclose stored secrets. Reppo submissions additionally pass the same redaction (Reppo evaluations are visible to its network - synthetic data only).
- Destination allow-lists use exact matching (lookalikes rejected). Financial inspection is recursive (nested amounts/destinations). Spending limits are cumulative across an agent's non-blocked actions. Agents with no permissions are denied by default.
- Authorization evidence must be a structured signed-approval reference (`sig:<24+ chars>`). This verifies format only; cryptographic issuer verification is not implemented and is not claimed.

## Hardening notes
- Agent credentials are scoped to their own agent: they cannot list, read, trace or retry other agents' actions, evaluations or decisions (owner users still see everything they own).
- Amount/destination detection is key-name based but normalised (`usd_amount`, `AmountUSD`, `beneficiary`, `recipient_address`, ... and array items). Unparseable amounts (`"1e999"`, `NaN`, free text) in money fields and negative amounts are hard violations; an allow-list with an amount but no recognisable destination is denied. This remains a heuristic: for production, validate payloads against a strict per-action-type schema.
- Cumulative spend uses a rolling `SPEND_WINDOW_HOURS` window and counts only positive amounts of non-blocked actions.
- Reppo allows one PENDING evaluation per account. Queued (HTTP 409) evaluations are resubmitted oldest-first by the 60s worker (or manually via retry); FAILED/DENIED results route to human REVIEW instead of holding forever.
- The live-event stream accepts only a 60-second, single-purpose ticket (`POST /api/v1/events/ticket`), never the session JWT, because the stream URL appears in logs.
- Credit protection: per-IP auth throttling, per-account action rate and daily caps, and an `ALLOW_SIGNUP=false` switch.
- Known remaining items: session JWTs live in `localStorage` (XSS exposure), and the data layer still reads whole tables and filters in memory (fine for a demo; add indexed `where` queries before scaling).

## Honest limits
Heuristic prompt-injection/secret detection catches known patterns only; novel obfuscation and semantic attacks can evade it. SERV/Reppo add judgment but can err - hence human REVIEW routing, freshness checks, and deterministic policy supremacy.

## Configuration
Server-only env: ALLOW_SIGNUP, AUTH_RATE_LIMIT, ACTION_RATE_LIMIT, DAILY_ACTION_CAP, SPEND_WINDOW_HOURS, TRUST_PROXY, JWT_SECRET, SERV_API_KEY, REPPO_API_KEY, DATABASE_URL, SCORE_THRESHOLD, REPPO_MAX_EVAL_AGE_MS, CORS_ORIGIN. Never commit `.env`. Provider keys never reach the browser; the frontend only receives VITE_API_URL.
Report issues privately; never include live credentials in reports.

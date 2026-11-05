# Testing (V2)
Run: `npm test` - 70 tests, all passing at last run. Suites:
- decision.test.ts (16): security-engine basics + decision rules.
- security-regression.test.ts (29): Phase 5 list - BLOCK/HOLD approval bypass, concurrent approvals, cross-tenant access/submission, invalid + revoked + rotated agent keys, agent-key self-only, JWT secret missing/weak (production refuses), nested amount, lookalike destination, malformed authorization evidence, empty permissions, cumulative limits, unknown confidence, route=review, SERV critical/outage/unavailable, stale evaluation, unknown status, QUEUED hold, secret-free traces.
- providers.test.ts (18): HTTP-MOCKED SERV/Reppo adapters (success, 401, 402, 409, 429, timeout, malformed JSON, invalid structured output, pending/settled/rejected, polling errors). Mocks are labelled; they are not live verification.
- lifecycle.test.ts (1): mocked-Reppo submit -> HOLD -> settle -> re-decision + audit events.
- api.test.ts (6): auth, demo block, missing-evaluation-is-not-approval, human approval, idempotency, honest integration status.
Live provider verification still requires real keys via POST /integrations/test. No Playwright suite yet.

# AgentShield

**Trust every action. Verify every decision.**

AgentShield is a security and evaluation infrastructure layer for autonomous AI agents. It intercepts proposed agent actions, enforces deterministic security policies, analyzes them with OpenServ SERV Reasoning, submits sanitized traces to the Reppo Evaluation API, and only then decides: **APPROVE, REVISE, REVIEW, BLOCK, or HOLD**.

Built for the OpenServ SERV Hackathon Edition 02 - Reppo Track.

## Problem and solution

Autonomous agents can move money, call tools, and leak data. Prompt-only guardrails fail silently. AgentShield adds a deterministic enforcement layer that AI verdicts can inform but never override: a critical threat or hard policy violation blocks even with a perfect evaluation score, and a pending or missing evaluation is never treated as approval.

## Architecture

External agents → Gateway (auth + validation) → Security Policy Engine (deterministic) → SERV Reasoning (structured assessment) → Reppo Evaluation (sanitized trace, polled verdict) → Decision Engine → controlled (simulated) execution / human approval → audit trail → dashboard. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Stack

React 19 + Vite + TypeScript + Tailwind + Recharts + TanStack Query (frontend); Node + Express + TypeScript + Zod (API); Prisma + PostgreSQL schema with migrations (file-store fallback for local demo when `DATABASE_URL` is unset); Vitest + Supertest tests.

## Run locally

```bash
cp .env.example .env   # add SERV_API_KEY and REPPO_API_KEY for live integrations
npm install
npm run build
PORT=4000 node apps/api/dist/index.js   # API on :4000
npm run dev -w @agentshield/web         # dashboard on :5173 (proxies /api to :4000)
```

Open http://localhost:5173, sign up, register an agent, then run the demo in Live Monitoring.

Without provider keys the app still runs: SERV/Reppo show `not_configured`, evaluations are not submitted, and affected actions route to REVIEW - never silently approved. Add keys (SERV: console.openserv.ai; Reppo: eval.reppo.xyz → API Key) and use Integrations → Test connection.

## Demo scenario

An autonomous payment agent proposes 500 USDC against a 100 USDC limit with an embedded injection. AgentShield blocks it deterministically, returns feedback, and (with a Reppo key) re-evaluates the revised compliant trace in the Improvement Lab. Scores shown are real settled verdicts only; unsettled ones display as pending.

## Docs

[PRD.md](PRD.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [DATABASE.md](DATABASE.md) · [API.md](API.md) · [SECURITY.md](SECURITY.md) · [TESTING.md](TESTING.md) · [DEPLOYMENT.md](DEPLOYMENT.md) · [HACKATHON.md](HACKATHON.md)

Screenshots/demo links: _placeholder - add after deployment._

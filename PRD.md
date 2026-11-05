# PRD - AgentShield
## Problem
AI agents act autonomously (payments, tools, data). Operators need pre-execution control, independent evaluation, and an audit trail.
## Users
Agent developers and platform/security teams operating autonomous agents.
## Core workflows
Register agent (scoped permissions, spending limit, allow-list) → submit proposed action → deterministic policy check → SERV structured assessment → sanitized Reppo evaluation → decision (APPROVE/REVISE/REVIEW/BLOCK/HOLD) → feedback → revision → re-evaluation → improvement metrics.
## Non-goals (MVP)
Real fund movement or arbitrary command execution (simulated adapter only); automatic model training from feedback (feedback is evidence for agent-side revision, measured not assumed).
## Success metrics
Blocked critical actions = 100% in test scenarios; revision success rate and average improvement tracked from settled Reppo verdicts only.

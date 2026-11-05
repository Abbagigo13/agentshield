# Hackathon - SERV Edition 02, Reppo Track
## Integrations (verified 2026-11-04 against official docs)
- SERV Reasoning: POST https://inference-api.openserv.ai/v1/chat/completions, Bearer key from console.openserv.ai, model gpt-5.4-mini, system prompt required, response_format json_schema for the SecurityAssessment contract. Docs: docs.openserv.ai/serv-reasoning/api/
- Reppo Evaluation API: POST https://eval.reppo.xyz/api/v1/agents/eval-requests/submit {type:"trace", payload, criteria, context, settlementMinutes}, Bearer key from eval.reppo.xyz; poll GET /agents/eval-requests/{evalId} until SETTLED; verdict {score, decision, confidence}, verdicts[], action.route, evidence. One PENDING per account (409). Docs: eval.reppo.xyz/agents.md, docs.reppo.ai/api/eval/evaluations.md
## Status in this environment
No SERV/REPPO keys were available during the build, so live calls are unverified here. The app reports not_configured honestly, never fabricates scores, and routes affected actions to REVIEW. To finish: add keys, run Integrations → Test connection, submit the demo, wait for settlement (≥ settlementMinutes), poll, and record the real verdicts.
## Demo script
Register PayBot (limit 100, destination vendor-payroll) → Live Monitoring → Run attack demo (500 + injection) → BLOCK with findings → submit compliant revision via API with parentActionId → Evaluation Center poll → Improvement Lab compares settled scores → Audit Trail shows every step.

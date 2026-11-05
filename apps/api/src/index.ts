import { app, pollPendingEvaluations } from "./app.js";
import { config, reppoConfigured } from "./config.js";
import { initializeDatabase } from "./repositories.js";

// Probe PostgreSQL once at startup: if DATABASE_URL points at an
// unreachable instance, initializeDatabase logs a warning and the API
// runs on the JSON file store instead of crashing on the first request.
await initializeDatabase();

app.listen(config.port, () => console.log(`AgentShield API listening on :${config.port}`));

// Background evaluation worker: polls PENDING Reppo evaluations and
// re-evaluates their decisions on settlement. Disabled without a Reppo key.
if (reppoConfigured()) {
  setInterval(() => { void pollPendingEvaluations(); }, 60_000).unref();
  console.log("Reppo polling worker enabled (60s interval)");
}

import { app, pollPendingEvaluations } from "./app.js";
import { config, reppoConfigured } from "./config.js";

app.listen(config.port, () => console.log(`AgentShield API listening on :${config.port}`));

// Background evaluation worker: polls PENDING Reppo evaluations and
// re-evaluates their decisions on settlement. Disabled without a Reppo key.
if (reppoConfigured()) {
  setInterval(() => { void pollPendingEvaluations(); }, 60_000).unref();
  console.log("Reppo polling worker enabled (60s interval)");
}

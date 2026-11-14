// Core request handling for the Proof Gatekeeper agent.
// Shared by api/gatekeeper.js (Vercel) and server.mjs (local test server).
// Pure-ish: state (seen proof_tx set + response cache) is passed in so the
// caller owns it. No I/O except proof generation.
import { decide } from "./decide.mjs";
import { buildCircuitInput, generateProof } from "./prove.mjs";
import { verifySignature, signBody } from "./hmac.mjs";

const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";

// Fail-closed: a request is only processed when the HMAC secret is set AND
// the inbound signature verifies. Preflight and task alike.
export async function handleRequest({ rawBody, headers, secret, state }) {
  const unauth = () => ({
    status: 401,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ok: false, error: "unauthorized" }),
  });
  if (!secret) return unauth();
  const sig = headers["x-agent-games-signature"] || headers["X-Agent-Games-Signature"];
  if (!verifySignature(secret, rawBody, sig)) return unauth();

  let env;
  try {
    env = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { status: 400, headers: { "content-type": "application/json" }, body: JSON.stringify({ ok: false, error: "invalid json" }) };
  }

  // Preflight: respond { ok: true, protocolVersion: "v1" }, signed.
  if (env.type === PREFLIGHT_TYPE) {
    const body = JSON.stringify({ ok: true, protocolVersion: "v1" });
    return {
      status: 200,
      headers: { "content-type": "application/json", "x-agent-games-signature": signBody(secret, Buffer.from(body)) },
      body,
    };
  }

  if (env.type !== TASK_TYPE) {
    return { status: 400, headers: { "content-type": "application/json" }, body: JSON.stringify({ ok: false, error: "unknown envelope type" }) };
  }

  // Idempotency: task IDs are idempotency keys — a retry returns the same
  // response without re-deciding or re-proving.
  const taskId = env.task_id;
  if (taskId && state.responses.has(taskId)) {
    const cached = state.responses.get(taskId);
    return { status: 200, headers: { "content-type": "application/json", "x-agent-games-signature": signBody(secret, Buffer.from(cached)) }, body: cached };
  }

  const input = env.input || {};
  const { decision, reason_code } = decide(input, state.seen);

  // Remaining time budget: deadline_at if present, else 55 s from receipt.
  let budgetMs = 45000;
  if (env.deadline_at) {
    const remaining = new Date(env.deadline_at).getTime() - Date.now();
    budgetMs = Math.max(5000, Math.min(45000, remaining - 5000));
  }

  let proof = null;
  let publicSignals = null;
  if (reason_code !== "PROOF_REUSED") {
    // PROOF_REUSED tasks have no proof to submit (circuit has no proof_tx
    // input). Every other task gets a proof if generation fits the budget.
    try {
      const circuitInput = buildCircuitInput(env, decision);
      const res = await generateProof(circuitInput, budgetMs);
      proof = res.proof;
      publicSignals = res.publicSignals;
    } catch (e) {
      // Best-effort: a correct decision WITHOUT a proof still earns +12
      // (minus the -2 proof penalty); timing out would lose the decision too.
      console.error(`[gatekeeper] proof generation failed for ${taskId}:`, String(e).split("\n")[0]);
    }
  }

  if (decision === "APPROVE" && input.proof_tx) {
    state.seen.add(String(input.proof_tx).trim().toLowerCase());
  }

  const response = { decision, reason_code };
  if (proof) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }
  if (input.proof_tx) response.proof_tx = input.proof_tx;

  const body = JSON.stringify(response);
  if (taskId) {
    state.responses.set(taskId, body);
    if (state.responses.size > 200) {
      const first = state.responses.keys().next().value;
      state.responses.delete(first);
    }
  }
  return {
    status: 200,
    headers: { "content-type": "application/json", "x-agent-games-signature": signBody(secret, Buffer.from(body)) },
    body,
  };
}

// Fresh per-process state. LIMITATION: in-memory only — Vercel serverless
// instances don't share it, so a reused proof routed to a different instance
// could be missed. Follow-up: durable store (Vercel KV).
export function createState() {
  return { seen: new Set(), responses: new Map() };
}

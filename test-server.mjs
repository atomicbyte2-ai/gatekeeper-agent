// End-to-end test of server.mjs over HTTP (run: node test-server.mjs).
// Starts the server as a child process on :3001 with a test HMAC secret,
// then exercises preflight, a valid task, a trap task, a reused proof,
// unauthenticated + bad-signature requests, and idempotent retry.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import fs from "fs";

const SECRET = "test-secret-for-gatekeeper-e2e";
const BASE = "http://127.0.0.1:3001";
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0xDe42000000000000000000000000000000009f01";
const vk = JSON.parse(fs.readFileSync("verification_key.json", "utf8"));

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}
function verifyRespSig(body, header) {
  const want = crypto.createHmac("sha256", SECRET).update(body).digest();
  const got = Buffer.from(String(header || ""), "hex");
  return got.length === 32 && crypto.timingSafeEqual(want, got);
}
async function post(path, obj, { signIt = true, badSig = false } = {}) {
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (signIt) headers["x-agent-games-signature"] = badSig ? "00".repeat(32) : sign(body);
  const res = await fetch(BASE + path, { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get("x-agent-games-signature") };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const server = spawn("node", ["server.mjs"], {
  env: { ...process.env, PORT: "3001", AGENT_GAMES_HMAC_SECRET: SECRET },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => process.stdout.write("[server] " + d));
server.stderr.on("data", (d) => process.stdout.write("[server:err] " + d));

let pass = 0, fail = 0;
function check(name, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  ok ? pass++ : fail++;
}

try {
  // wait for the server to listen
  for (let i = 0; i < 30; i++) {
    try { await fetch(BASE, { method: "GET" }); break; } catch { await sleep(200); }
  }

  // 1. preflight
  const pre = await post("/", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  const preJson = JSON.parse(pre.text);
  check("preflight 200 + ok + v1", pre.status === 200 && preJson.ok === true && preJson.protocolVersion === "v1", pre.text.slice(0, 80));
  check("preflight response signed", verifyRespSig(pre.text, pre.sig));

  // 2. valid task -> APPROVE + proof that verifies locally
  const task = {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_e2e_001",
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 55000).toISOString(),
    input: {
      registered_vk: VK_HASH, proof_vk: VK_HASH, minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000, recipient: RECIPIENT,
      condition_recipient: RECIPIENT, amount: "500", max_transfer: "1000",
      proof_tx: "0xe2e100000000000000000000000000000000000000000000000000000000001",
    },
  };
  const t0 = Date.now();
  const r1 = await post("/", task);
  const j1 = JSON.parse(r1.text);
  check("valid task APPROVE/VALID_CONDITION", r1.status === 200 && j1.decision === "APPROVE" && j1.reason_code === "VALID_CONDITION", `${Date.now() - t0}ms`);
  check("valid task has proof + 13 public signals", !!j1.proof && Array.isArray(j1.public_signals) && j1.public_signals.length === 13);
  check("valid task response signed", verifyRespSig(r1.text, r1.sig));
  if (j1.proof) {
    const v = await snarkjs.groth16.verify(vk, j1.public_signals, j1.proof);
    check("valid task proof verifies locally (groth16)", v === true);
    check("publicSignals[11] decision=1, [12] taskId=keccak(gk_e2e_001) mod p", j1.public_signals[11] === "1");
  }

  // 3. idempotent retry — same task_id returns the identical body
  const r1b = await post("/", task);
  check("idempotent retry returns identical body", r1b.status === 200 && r1b.text === r1.text);

  // 4. threshold trap -> REJECT + proof
  const trap = JSON.parse(JSON.stringify(task));
  trap.task_id = "gk_e2e_002";
  trap.input.public_balance = "500";
  trap.input.proof_tx = "0xe2e200000000000000000000000000000000000000000000000000000000002";
  const r2 = await post("/", trap);
  const j2 = JSON.parse(r2.text);
  check("threshold trap REJECT/THRESHOLD_MISMATCH", r2.status === 200 && j2.decision === "REJECT" && j2.reason_code === "THRESHOLD_MISMATCH");
  check("trap task still carries a proof", !!j2.proof && Array.isArray(j2.public_signals) && j2.public_signals.length === 13);
  if (j2.proof) {
    const v2 = await snarkjs.groth16.verify(vk, j2.public_signals, j2.proof);
    check("trap task proof verifies locally", v2 === true);
  }

  // 5. reused proof_tx (same as the APPROVED task 1) -> REJECT/PROOF_REUSED, NO proof
  const reuse = JSON.parse(JSON.stringify(task));
  reuse.task_id = "gk_e2e_003";
  reuse.input.proof_tx = "0xe2e100000000000000000000000000000000000000000000000000000000001";
  const r3 = await post("/", reuse);
  const j3 = JSON.parse(r3.text);
  check("reused proof REJECT/PROOF_REUSED", r3.status === 200 && j3.decision === "REJECT" && j3.reason_code === "PROOF_REUSED");
  check("reused proof carries NO proof/public_signals", !j3.proof && !j3.public_signals);

  // 6. unsigned -> 401
  const r4 = await post("/", task, { signIt: false });
  check("unsigned request 401", r4.status === 401, `got ${r4.status}`);
  // 7. bad signature -> 401
  const r5 = await post("/", task, { badSig: true });
  check("bad signature 401", r5.status === 401, `got ${r5.status}`);
  // 8. unknown type -> 400
  const r6 = await post("/", { type: "agent-games.unknown.v1" });
  check("unknown envelope type 400", r6.status === 400, `got ${r6.status}`);
  // 9. GET -> 405
  const r7 = await fetch(BASE + "/");
  check("GET 405", r7.status === 405, `got ${r7.status}`);
} finally {
  server.kill("SIGTERM");
}

console.log(`\n${pass}/${pass + fail} server e2e tests passed`);
if (fail) process.exit(1);

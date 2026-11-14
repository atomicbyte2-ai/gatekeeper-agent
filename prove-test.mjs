// Proof prototype: build sample task inputs, run snarkjs fullProve, verify, time it.
import * as snarkjs from "snarkjs";
import fs from "fs";

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modP = (x) => ((x % FIELD_P) + FIELD_P) % FIELD_P;

// Published registered vk hash (from /api/circuit-info).
const VK_HASH = 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0n;
const RECIPIENT = 0xDe42000000000000000000000000000000009f01n;

const vk = JSON.parse(fs.readFileSync("verification_key.json", "utf8"));

function validInput(overrides = {}) {
  return {
    minimum: 1000,
    recipient: RECIPIENT.toString(),
    amount: 500,
    publicBalance: 1460,
    expiryBlock: 8430000,
    currentBlock: 8420000,
    conditionRecipient: RECIPIENT.toString(),
    maxTransfer: 1000,
    taskId: 24,
    decision: 1,
    salt: 12345,
    registeredVkHash: modP(VK_HASH).toString(),
    proofVkHash: modP(VK_HASH).toString(),
    ...overrides,
  };
}

async function proveAndVerify(label, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, "gatekeeper.wasm", "gatekeeper_final.zkey");
    const proveMs = Date.now() - t0;
    const t1 = Date.now();
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const verifyMs = Date.now() - t1;
    console.log(`${label}: fullProve ${proveMs}ms, verify ${verifyMs}ms, verify=${ok}`);
    console.log(`  publicSignals (${publicSignals.length}):`, JSON.stringify(publicSignals));
    console.log(`  proof.pi_a[0..1]:`, proof.pi_a.slice(0, 2).map((x) => String(x).slice(0, 24) + "…"));
    return { ok, proveMs, publicSignals };
  } catch (e) {
    console.log(`${label}: PROVE FAILED after ${Date.now() - t0}ms:`, String(e).split("\n").slice(0, 3).join(" | "));
    return { ok: false, error: String(e) };
  }
}

console.log("== 1. VALID task, decision=APPROVE (1) ==");
await proveAndVerify("valid-approve", validInput());

console.log("\n== 2. THRESHOLD trap, decision=REJECT (0) ==");
await proveAndVerify("threshold-reject", validInput({ publicBalance: 500, decision: 0 }));

console.log("\n== 3. WRONG decision: threshold trap but decision=APPROVE (1) — expect failure ==");
await proveAndVerify("threshold-wrong-approve", validInput({ publicBalance: 500, decision: 1 }));

console.log("\n== 4. VK_SUBSTITUTION trap, decision=REJECT (0) ==");
await proveAndVerify("vk-reject", validInput({ proofVkHash: modP(VK_HASH + 1n).toString(), decision: 0 }));

console.log("\n== 5. salt=0 variant of valid task ==");
await proveAndVerify("valid-salt0", validInput({ salt: 0 }));

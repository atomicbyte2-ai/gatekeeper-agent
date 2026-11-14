// Groth16 proof generation for the Proof Gatekeeper circuit (snarkjs).
// Circuit inputs (13, all public) — see NOTES.md §5 for how they were found.
import * as snarkjs from "snarkjs";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";
import { keccak256 } from "./keccak.mjs";

export const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const modP = (x) => ((x % FIELD_P) + FIELD_P) % FIELD_P;

const DIR = path.dirname(fileURLToPath(import.meta.url));
export const WASM_PATH = path.join(DIR, "..", "gatekeeper.wasm");
export const ZKEY_PATH = path.join(DIR, "..", "gatekeeper_final.zkey");
export const VK_PATH = path.join(DIR, "..", "verification_key.json");

// Map a string task_id (e.g. "gk_24_9d1") to a field element.
// ASSUMPTION (unverified): keccak256(task_id) mod p — the most standard
// string->field mapping. The platform's conversion is unknown; if practice
// mode rejects our proofs, this is the first suspect (alternative: the
// numeric suffix of the task_id). See NOTES.md §5.
export function taskIdToField(taskId) {
  return modP(BigInt("0x" + Buffer.from(keccak256(String(taskId))).toString("hex")));
}

// Convert a 0x hex value (address or VK hash) to a field element.
export function hexToField(hex) {
  return modP(BigInt(String(hex).trim()));
}

export function toFieldDecimal(x) {
  // Accepts decimal strings, 0x hex strings, or numbers.
  if (typeof x === "bigint") return modP(x).toString();
  if (typeof x === "number") return modP(BigInt(x)).toString();
  const s = String(x).trim();
  return modP(BigInt(s)).toString();
}

// Build the 13 circuit inputs from a task payload + the decided outcome.
// decision: "APPROVE" (1) or "REJECT" (0). salt: any field element (default random).
// NOTE: for PROOF_REUSED tasks the caller must NOT call this — those tasks
// have no proof to submit (the circuit has no proof_tx input).
export function buildCircuitInput(task, decision, salt) {
  const input = task.input;
  const saltVal =
    salt !== undefined ? salt : BigInt("0x" + [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join(""));
  return {
    minimum: toFieldDecimal(input.minimum),
    recipient: hexToField(input.recipient).toString(),
    amount: toFieldDecimal(input.amount),
    publicBalance: toFieldDecimal(input.public_balance),
    expiryBlock: toFieldDecimal(input.expiry_block),
    currentBlock: toFieldDecimal(input.current_block),
    conditionRecipient: hexToField(input.condition_recipient).toString(),
    maxTransfer: toFieldDecimal(input.max_transfer),
    taskId: taskIdToField(task.task_id).toString(),
    decision: decision === "APPROVE" ? 1 : 0,
    salt: modP(saltVal).toString(),
    registeredVkHash: hexToField(input.registered_vk).toString(),
    proofVkHash: hexToField(input.proof_vk).toString(),
  };
}

// Generate a Groth16 proof. Resolves { proof, publicSignals } or rejects.
// timeoutMs: race a timer against fullProve (the underlying work is NOT
// cancellable — on timeout the proof keeps computing in the background, but
// the caller can already answer without it).
export async function generateProof(circuitInput, timeoutMs = 45000) {
  const work = snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  if (!timeoutMs) return work;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`proof generation timed out after ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    // If we timed out, keep the work from becoming an unhandled rejection.
    work.catch(() => {});
  }
}

export function loadVerificationKey() {
  return JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
}

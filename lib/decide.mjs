// Deterministic Proof Gatekeeper decision logic (pure, dependency-free).
//
// APPROVE only when EVERY check passes; otherwise REJECT with the first
// failing check's reason code. Check order follows the platform's own
// trap-encyclopedia listing on /events/proof-gatekeeper:
//   VK_SUBSTITUTION -> THRESHOLD_MISMATCH -> PROOF_REUSED ->
//   EXPIRED_CONDITION -> RECIPIENT_MISMATCH -> AMOUNT_OVERFLOW
// In practice each task carries a single trap (the published mix sums to
// ~100%), so the order only matters for synthetic multi-trap inputs.
//
// Boundary rules (from the task spec):
//   - public_balance >= minimum  (equal passes)
//   - current_block <= expiry_block  (equal passes, not expired)
//   - amount <= max_transfer  (equal passes)
//   - recipient == condition_recipient (case-insensitive hex)
//   - proof_vk == registered_vk (case-insensitive hex)
//   - proof_tx not in the seen-set (PROOF_REUSED)
//
// `seen` is a Set of proof_tx values already accepted (lowercased).
// The caller owns it; on APPROVE the caller should add proof_tx to it.
// (PROOF_REUSED tasks are rejected, so their proof_tx is NOT added —
// it was already in the set.)

export const REASONS = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  REUSED: "PROOF_REUSED",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
};

function normAddr(a) {
  return String(a ?? "").trim().toLowerCase();
}

function toBig(x) {
  // Accepts decimal strings, 0x hex strings, or numbers.
  if (typeof x === "bigint") return x;
  if (typeof x === "number") return BigInt(x);
  const s = String(x).trim();
  return BigInt(s);
}

export function decide(input, seen = new Set()) {
  const registeredVk = normAddr(input.registered_vk);
  const proofVk = normAddr(input.proof_vk);
  const recipient = normAddr(input.recipient);
  const conditionRecipient = normAddr(input.condition_recipient);
  const proofTx = normAddr(input.proof_tx);

  // 1. VK must match the registered condition key.
  if (registeredVk !== proofVk) {
    return { decision: "REJECT", reason_code: REASONS.VK };
  }
  // 2. Public balance must meet the minimum.
  if (toBig(input.public_balance) < toBig(input.minimum)) {
    return { decision: "REJECT", reason_code: REASONS.THRESHOLD };
  }
  // 3. Proof reference must not have been used before.
  if (proofTx && seen.has(proofTx)) {
    return { decision: "REJECT", reason_code: REASONS.REUSED };
  }
  // 4. Condition must not have expired.
  if (Number(input.current_block) > Number(input.expiry_block)) {
    return { decision: "REJECT", reason_code: REASONS.EXPIRED };
  }
  // 5. Recipient must match the condition.
  if (recipient !== conditionRecipient) {
    return { decision: "REJECT", reason_code: REASONS.RECIPIENT };
  }
  // 6. Amount must not exceed the single-transfer cap.
  if (toBig(input.amount) > toBig(input.max_transfer)) {
    return { decision: "REJECT", reason_code: REASONS.AMOUNT };
  }
  return { decision: "APPROVE", reason_code: REASONS.VALID };
}

// Map a decision to the circuit's decision bit: APPROVE=1, REJECT=0.
export function decisionBit(decision) {
  return decision === "APPROVE" ? 1 : 0;
}

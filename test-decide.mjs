// Tests for lib/decide.mjs — one case per reason code + boundary cases.
import { decide } from "./lib/decide.mjs";

const BASE = {
  registered_vk: "0x7d3a000000000000000000000000000000000000000000000000000000f291",
  proof_vk: "0x7d3a000000000000000000000000000000000000000000000000000000f291",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0xDe42000000000000000000000000000000009f01",
  condition_recipient: "0xDe42000000000000000000000000000000009f01",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xa8aa0000000000000000000000000000000000000000000000000000002c01",
};

const seen = new Set(["0xdead000000000000000000000000000000000000000000000000000000beef01"]);

const cases = [
  ["VALID_CONDITION (approve)", {}, "APPROVE", "VALID_CONDITION"],
  ["VK_SUBSTITUTION", { proof_vk: "0x13aa000000000000000000000000000000000000000000000000000000aa01" }, "REJECT", "VK_SUBSTITUTION"],
  ["THRESHOLD_MISMATCH", { public_balance: "999" }, "REJECT", "THRESHOLD_MISMATCH"],
  ["PROOF_REUSED", { proof_tx: "0xdead000000000000000000000000000000000000000000000000000000beef01" }, "REJECT", "PROOF_REUSED"],
  ["EXPIRED_CONDITION", { current_block: 8430001 }, "REJECT", "EXPIRED_CONDITION"],
  ["RECIPIENT_MISMATCH", { recipient: "0xDe42000000000000000000000000000000009f02" }, "REJECT", "RECIPIENT_MISMATCH"],
  ["AMOUNT_OVERFLOW", { amount: "1001" }, "REJECT", "AMOUNT_OVERFLOW"],
  // boundaries — all must APPROVE
  ["boundary: balance == minimum", { public_balance: "1000" }, "APPROVE", "VALID_CONDITION"],
  ["boundary: current == expiry", { current_block: 8430000 }, "APPROVE", "VALID_CONDITION"],
  ["boundary: amount == max", { amount: "1000" }, "APPROVE", "VALID_CONDITION"],
  ["boundary: amount == 0", { amount: "0" }, "APPROVE", "VALID_CONDITION"],
  // case-insensitive hex
  ["case: VK uppercase", { proof_vk: "0X7D3A000000000000000000000000000000000000000000000000000000F291" }, "APPROVE", "VALID_CONDITION"],
  ["case: recipient uppercase", { recipient: "0XDE42000000000000000000000000000000009F01" }, "APPROVE", "VALID_CONDITION"],
  // priority: VK beats threshold when both fail
  ["priority: VK + threshold -> VK", { proof_vk: "0x13aa000000000000000000000000000000000000000000000000000000aa01", public_balance: "1" }, "REJECT", "VK_SUBSTITUTION"],
  // priority: threshold beats expiry when both fail
  ["priority: threshold + expiry -> threshold", { public_balance: "1", current_block: 9999999 }, "REJECT", "THRESHOLD_MISMATCH"],
  // huge values (BigInt path)
  ["bigint: large balance/amount", { minimum: "1000000000000000000000", public_balance: "1000000000000000000001", amount: "999999999999999999999", max_transfer: "1000000000000000000000" }, "APPROVE", "VALID_CONDITION"],
  // hex-string numbers
  ["hex numbers: 0x balance/amount", { minimum: "0x3e8", public_balance: "0x5b4", amount: "0x1f4", max_transfer: "0x3e8" }, "APPROVE", "VALID_CONDITION"],
];

let pass = 0, fail = 0;
for (const [name, over, wantDec, wantReason] of cases) {
  const got = decide({ ...BASE, ...over }, seen);
  const ok = got.decision === wantDec && got.reason_code === wantReason;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name} -> ${got.decision}/${got.reason_code}${ok ? "" : ` (want ${wantDec}/${wantReason})`}`);
  ok ? pass++ : fail++;
}
console.log(`\n${pass}/${pass + fail} decision tests passed`);
if (fail) process.exit(1);

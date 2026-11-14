// Tests for lib/keccak.mjs — known Keccak-256 vectors.
import { keccak256Hex } from "./lib/keccak.mjs";

const cases = [
  ["", "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
  ["abc", "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
  ["hello world", "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"],
];

let pass = 0;
for (const [input, want] of cases) {
  const got = keccak256Hex(input);
  const ok = got === want;
  console.log(`${ok ? "PASS" : "FAIL"}  keccak256(${JSON.stringify(input)}) -> ${got.slice(0, 18)}…${ok ? "" : ` (want ${want})`}`);
  if (ok) pass++;
}
console.log(`\n${pass}/${cases.length} keccak tests passed`);
if (pass !== cases.length) process.exit(1);

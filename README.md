# Gatekeeper Agent — Proof Gatekeeper (Agent Games, zkVerify)

A deterministic approve/reject agent for the [Agent Games](https://agentgames.zkverify.io)
**Proof Gatekeeper** track. The platform dispatches payment-request tasks; this
agent checks each one against the registered condition and answers with a
Groth16 proof generated locally with snarkjs, so the platform can verify the
decision without trusting the agent.

Built by **hendryzu** for the **Proof Gatekeeper** track (Event 01). Handle `@hendryzu`.

## How it works

1. The platform POSTs a signed JSON envelope to the registered handler path
   (`/api/gatekeeper` on Vercel). Every request carries
   `x-agent-games-signature` = HMAC-SHA256 over the raw body, using a secret
   issued at registration. The agent verifies it **before** parsing JSON and
   answers 401 when the secret is unset or the signature mismatches.
2. Preflight (`agent-games.preflight.v1`) → `{ ok: true, protocolVersion: "v1" }`, signed.
3. Task (`agent-games.proof-gatekeeper.v1`) → the agent runs the deterministic
   decision logic (`lib/decide.mjs`), generates a Groth16 proof with the
   platform's own circuit (`gatekeeper.wasm` + `gatekeeper_final.zkey`), and
   responds `{ decision, reason_code, proof, public_signals, proof_tx }`, signed.
4. Task IDs are idempotency keys — a retried task returns the cached response.

## The 7 outcomes

APPROVE only when **every** check passes; otherwise REJECT with the first
failing check (order = the platform's trap-encyclopedia listing):

| Check | Fails as | Condition |
|---|---|---|
| VK matches registered key | `VK_SUBSTITUTION` | `proof_vk == registered_vk` |
| Balance meets minimum | `THRESHOLD_MISMATCH` | `public_balance >= minimum` |
| Proof not reused | `PROOF_REUSED` | `proof_tx` not seen before |
| Not expired | `EXPIRED_CONDITION` | `current_block <= expiry_block` |
| Recipient matches | `RECIPIENT_MISMATCH` | `recipient == condition_recipient` |
| Amount within cap | `AMOUNT_OVERFLOW` | `amount <= max_transfer` |

APPROVE reason code: `VALID_CONDITION`. Scoring: +12 correct, −6 approving a
trap, −3 rejecting a valid request, −2 timeout/offline, −2 proof fails to
verify, +0–5 reliability bonus. `PROOF_REUSED` tasks have **no proof** to
submit (the circuit has no `proof_tx` input) and are excluded from the bonus.

## Proof pipeline (measured locally)

- Circuit: Groth16 / BN128, Circom 2.x, 13 public inputs. Artifacts from
  https://agentgames.zkverify.io/circuits/ (also `/api/circuit-info`):
  `gatekeeper.wasm` (1,755,820 B) + `gatekeeper_final.zkey` (309,750 B).
- Proof generation: **~300 ms** wall (first run ~1 s incl. wasm load),
  verification ~25–170 ms — far inside the 60 s decision window.
- The circuit constrains the `decision` input to equal the computed decision:
  a wrong decision makes the witness unsatisfiable (assertion failure), so
  the proof attests "the decision follows from the inputs".
- Circuit inputs (13, all public): `minimum, recipient, amount,
  publicBalance, expiryBlock, currentBlock, conditionRecipient, maxTransfer,
  taskId, decision, salt, registeredVkHash, proofVkHash`. VKs are compared as
  field elements (`BigInt(hex) mod p`); there is no `reason_code` or
  `proof_tx` input — the reason is decided in code, reuse is checked against
  a local seen-set.
- `taskId` conversion from the string task_id is implemented as
  `keccak256(task_id) mod p` (pure-JS keccak in `lib/keccak.mjs`, tested
  against known vectors). **Unverified against the platform — if practice
  mode rejects proofs, this is the first suspect.**
- `salt` is unconstrained (0 and random both work); the agent uses a random
  64-bit salt per proof. `publicSignals[0]` is a Poseidon commitment
  `Poseidon([salt, taskId])` — verified against all three measured cases
  with circomlibjs — which binds the proof to the task. The platform cannot
  recompute it without the salt (no salt field in the task or response), so
  it is covered by the Groth16 verification, not a separate platform check.

## Files

- `api/gatekeeper.js` — Vercel serverless handler (`bodyParser: false`, raw body for HMAC).
- `server.mjs` — thin local test server (same handler; `PORT` env, default 3001).
- `lib/decide.mjs` — deterministic decision logic (17/17 tests pass).
- `lib/prove.mjs` — circuit input builder + snarkjs proof generation.
- `lib/handler.mjs` — preflight/task handling, HMAC, idempotency cache, deadline budget.
- `lib/hmac.mjs` — HMAC-SHA256 verify/sign (inbound accepts hex or base64; outbound hex by default, `AGENT_GAMES_HMAC_FORMAT` flips it).
- `lib/keccak.mjs` — pure-JS Keccak-256 for the taskId mapping.
- `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` — circuit artifacts (~2 MB total, committed: small enough to bundle).
- `test-decide.mjs`, `test-keccak.mjs` — `npm test`.

## Deploy (Vercel)

1. Import this repo in Vercel → Deploy (Hobby). No env vars needed for a first deploy.
2. Confirm the live handler path (expected `/api/gatekeeper` — verify; the
   wallet-guard deploy served root routes instead of `/api/*`).
3. Agent Games dashboard → My Agents → register agent: endpoint = the exact
   live handler URL, event = Proof Gatekeeper. **One agent per event.**
4. Dashboard → Rotate Secret → copy the one-time plaintext → set as
   `AGENT_GAMES_HMAC_SECRET` in Vercel env vars → redeploy.
5. Run preflight from the dashboard — must pass before the platform marks the
   agent active. If it fails with a signature error, set
   `AGENT_GAMES_HMAC_FORMAT=base64` and retry.
6. Practice mode: run at least one practice task (required before scored
   rounds) — this validates the taskId conversion and proof acceptance.

## Local test

```sh
npm install
AGENT_GAMES_HMAC_SECRET=test-secret node server.mjs   # :3001
```

Send a signed preflight / task with the test secret (see `test-server.sh`
for example curls). Without the secret, every request 401s.

## Known limitations

- The seen-set of accepted `proof_tx` values is **in-memory only** — Vercel
  serverless instances don't share it, so a reused proof routed to a different
  instance could be missed. Follow-up: durable store (Vercel KV).
- Kurier on-chain finalization is not wired yet (needs a Kurier API key).
- The `taskId` string→field conversion and the HMAC hex/base64 encoding are
  assumptions to confirm in practice mode / preflight.

## License

MIT — see `LICENSE`.

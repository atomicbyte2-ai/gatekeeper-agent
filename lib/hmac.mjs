// HMAC-SHA256 helpers for the Agent Games agent platform.
// Inbound: verify x-agent-games-signature over the RAW request body BEFORE
// parsing JSON. Outbound: sign the raw response body.
// Encoding: the platform docs don't state hex vs base64. Outbound default is
// hex (env AGENT_GAMES_HMAC_FORMAT=hex|base64 flips it). Inbound verification
// accepts hex OR base64 — whichever matches (timing-safe compare).
import crypto from "node:crypto";

function hmacBytes(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest();
}

function safeEqual(a, b) {
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// Verify an inbound signature header. Returns true only on a match.
export function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const digest = hmacBytes(secret, rawBody);
  const h = String(headerValue).trim();
  // hex form
  if (/^[0-9a-fA-F]{64}$/.test(h) && safeEqual(digest, Buffer.from(h, "hex"))) return true;
  // base64 form
  try {
    const b64 = Buffer.from(h, "base64");
    if (b64.length === 32 && safeEqual(digest, b64)) return true;
  } catch { /* not base64 */ }
  return false;
}

// Sign a raw body for an outbound response. Returns the header value.
export function signBody(secret, rawBody) {
  const digest = hmacBytes(secret, rawBody);
  const fmt = (process.env.AGENT_GAMES_HMAC_FORMAT || "hex").toLowerCase();
  return fmt === "base64" ? digest.toString("base64") : digest.toString("hex");
}

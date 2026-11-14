// Thin local test server for the Proof Gatekeeper agent (mirrors the
// wallet-guard pattern). Same handler as the Vercel function.
// Usage:  AGENT_GAMES_HMAC_SECRET=test-secret node server.mjs
//         (PORT env, default 3001 — wallet-guard uses 3000, do NOT touch it)
import http from "node:http";
import { handleRequest, createState } from "./lib/handler.mjs";

const PORT = Number(process.env.PORT || 3001);
const state = createState();

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "method not allowed" }));
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  const result = await handleRequest({ rawBody, headers: req.headers, secret, state });
  res.writeHead(result.status, result.headers);
  res.end(result.body);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[gatekeeper] listening on :${PORT} (HMAC secret ${process.env.AGENT_GAMES_HMAC_SECRET ? "set" : "UNSET — all requests will 401"})`);
});

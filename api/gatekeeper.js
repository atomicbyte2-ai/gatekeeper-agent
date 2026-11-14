// Vercel serverless handler for the Proof Gatekeeper agent.
// Live path (after deploy): /api/gatekeeper  — VERIFY the actual live path
// after the first deploy and register THAT exact URL (wallet-guard's deploy
// served root routes instead of /api/* — do not assume).
import { handleRequest, createState } from "../lib/handler.mjs";

const state = createState();

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "method not allowed" });
    return;
  }
  // Read the RAW body (Vercel does not parse it for us when we disable the
  // body parser — see the `api.bodyParser: false` export below). The HMAC
  // must be computed over these exact bytes.
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);

  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  const result = await handleRequest({
    rawBody,
    headers: req.headers,
    secret,
    state,
  });
  res.status(result.status);
  for (const [k, v] of Object.entries(result.headers)) res.setHeader(k, v);
  res.send(result.body);
}

export const config = {
  api: { bodyParser: false },
};

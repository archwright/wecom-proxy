import Fastify from "fastify";
import fetch from "node-fetch";
import { getWecomAccessToken, wecomSendText } from "./wecom.js";

const app = Fastify({
  logger: true,
  bodyLimit: 5 * 1024 * 1024
});

// Register raw body parsing for XML
app.addContentTypeParser("text/xml", { parseAs: "string" }, (req, body, done) => {
  done(null, body);
});
app.addContentTypeParser("application/xml", { parseAs: "string" }, (req, body, done) => {
  done(null, body);
});

const {
  PROXY_SHARED_SECRET,
  SUPABASE_INBOUND_FORWARD_URL,
  WECOM_CORP_ID,
  WECOM_SECRET,
  WECOM_AGENT_ID
} = process.env;

function requireAuth(req) {
  const auth = req.headers["authorization"] || "";
  const expected = `Bearer ${PROXY_SHARED_SECRET}`;
  if (!PROXY_SHARED_SECRET || auth !== expected) {
    const err = new Error("Unauthorized");
    err.statusCode = 401;
    throw err;
  }
}

app.get("/health", async () => ({ ok: true }));

// Supabase -> Proxy -> WeCom (outbound messages)
app.post("/wecom/send", async (req, reply) => {
  requireAuth(req);
  const { toUser, content } = req.body || {};
  if (!toUser || !content) {
    return reply.code(400).send({ error: "Missing toUser or content" });
  }
  const token = await getWecomAccessToken({
    corpId: WECOM_CORP_ID,
    corpSecret: WECOM_SECRET
  });
  const result = await wecomSendText({
    accessToken: token,
    agentId: WECOM_AGENT_ID,
    toUser,
    content
  });
  return { ok: true, result };
});

// WeCom -> Proxy -> Supabase (URL VERIFICATION - GET)
app.get("/wecom/callback", async (req, reply) => {
  const qs = req.url.includes("?") ? req.url.split("?")[1] : "";
  const url = qs
    ? `${SUPABASE_INBOUND_FORWARD_URL}?${qs}`
    : SUPABASE_INBOUND_FORWARD_URL;

  console.log(`[GET] Forwarding verification to: ${url}`);

  const res = await fetch(url, { method: "GET" });
  const text = await res.text();

  console.log(`[GET] Supabase response: ${res.status} - ${text}`);

  // Return plain text for WeCom verification
  reply
    .code(res.status)
    .header("content-type", "text/plain")
    .send(text);
});

// WeCom -> Proxy -> Supabase (INBOUND MESSAGES - POST)
app.post("/wecom/callback", async (req, reply) => {
  const qs = req.url.includes("?") ? req.url.split("?")[1] : "";
  const url = qs
    ? `${SUPABASE_INBOUND_FORWARD_URL}?${qs}`
    : SUPABASE_INBOUND_FORWARD_URL;

  const body = typeof req.body === "string" ? req.body : "";

  console.log(`[POST] Forwarding message to: ${url}`);
  console.log(`[POST] Body length: ${body.length}`);

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": req.headers["content-type"] || "text/xml" },
    body
  });

  const text = await res.text();
  console.log(`[POST] Supabase response: ${res.status} - ${text}`);

  reply.code(res.status).send(text);
});

const port = process.env.PORT ? Number(process.env.PORT) : 8080;
try {
  await app.listen({ port, host: "0.0.0.0" });
  console.log(`Server running on port ${port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

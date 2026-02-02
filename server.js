import Fastify from "fastify";
import rawBody from "@fastify/raw-body";
import fetch from "node-fetch";
import { getWecomAccessToken, wecomSendText } from "./wecom.js";

const app = Fastify({ logger: true });

await app.register(rawBody, {
  field: "rawBody",
  global: false,
  encoding: "utf8",
  runFirst: true
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

// Supabase -> Proxy -> WeCom
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

// WeCom -> Proxy -> Supabase
app.post(
  "/wecom/callback",
  { config: { rawBody: true } },
  async (req, reply) => {
    const qs = req.url.includes("?") ? req.url.split("?")[1] : "";
    const url = qs
      ? `${SUPABASE_INBOUND_FORWARD_URL}?${qs}`
      : SUPABASE_INBOUND_FORWARD_URL;

    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": req.headers["content-type"] || "text/xml" },
      body: req.rawBody || ""
    });

    const text = await res.text();
    reply.code(res.status).send(text);
  }
);

const port = process.env.PORT ? Number(process.env.PORT) : 8080;
app.listen({ port, host: "0.0.0.0" });

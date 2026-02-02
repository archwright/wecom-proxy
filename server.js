// server.js

import Fastify from "fastify";
import fetch from "node-fetch";
import crypto from "crypto";
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
  WECOM_AGENT_ID,
  WECOM_KF_SECRET,
  SUPABASE_FUNCTIONS_URL,

  // Used ONLY for WeCom KF URL verification (GET /wecom/kf-callback)
  WECOM_KF_TOKEN,
  WECOM_KF_ENCODING_AES_KEY
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

// Health endpoint for Fly health checks
app.get("/health", async () => ({ ok: true }));

// =============================
// WeCom crypto helpers (KF GET verification)
// =============================
function sha1Hex(str) {
  return crypto.createHash("sha1").update(str).digest("hex");
}

function verifyWecomSignature({ token, timestamp, nonce, signature, data }) {
  const arr = [token, timestamp, nonce, data].sort();
  const computed = sha1Hex(arr.join(""));
  return computed === signature;
}

function decryptWecomEchoStr({ encodingAESKey, corpId, echostrB64 }) {
  const keyStr = (encodingAESKey || "").trim();
  if (keyStr.length !== 43) {
    throw new Error(`EncodingAESKey length ${keyStr.length} != 43`);
  }

  // WeCom uses 43-char base64 without '=' padding
  const aesKey = Buffer.from(keyStr + "=", "base64"); // 32 bytes
  if (aesKey.length !== 32) {
    throw new Error(`AES key length ${aesKey.length} != 32`);
  }

  // IV is first 16 bytes of key
  const iv = aesKey.subarray(0, 16);

  // Base64 decode echostr
  const cipherBuf = Buffer.from(echostrB64, "base64");

  // AES-256-CBC decrypt (PKCS7 padding handled by Node)
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
  const plain = Buffer.concat([decipher.update(cipherBuf), decipher.final()]);

  // Plain structure: random(16) + msg_len(4) + msg + corpId
  const msgLen = plain.readUInt32BE(16);
  const msgStart = 20;
  const msgEnd = msgStart + msgLen;

  if (msgEnd > plain.length) {
    throw new Error(`Bad msgLen ${msgLen} exceeds buffer ${plain.length}`);
  }

  const msg = plain.subarray(msgStart, msgEnd).toString("utf8");
  const corpFromMsg = plain.subarray(msgEnd).toString("utf8");

  if (corpId && corpFromMsg && corpFromMsg !== corpId) {
    throw new Error(`CorpID mismatch got=${corpFromMsg} expected=${corpId}`);
  }

  return msg;
}

// ============================================
// Supabase -> Proxy -> WeCom (outbound messages)
// ============================================
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

// ============================================
// WeCom -> Proxy -> Supabase (Enterprise callback)
// ============================================

// URL VERIFICATION - GET
app.get("/wecom/callback", async (req, reply) => {
  const qs = req.url.includes("?") ? req.url.split("?")[1] : "";
  const url = qs ? `${SUPABASE_INBOUND_FORWARD_URL}?${qs}` : SUPABASE_INBOUND_FORWARD_URL;

  app.log.info(`[GET] Forwarding verification to: ${url}`);

  const res = await fetch(url, { method: "GET" });
  const text = await res.text();

  app.log.info(`[GET] Supabase response: ${res.status} - ${text}`);

  reply.code(res.status).header("content-type", "text/plain").send(text);
});

// INBOUND MESSAGES - POST
app.post("/wecom/callback", async (req, reply) => {
  const qs = req.url.includes("?") ? req.url.split("?")[1] : "";
  const url = qs ? `${SUPABASE_INBOUND_FORWARD_URL}?${qs}` : SUPABASE_INBOUND_FORWARD_URL;

  const body = typeof req.body === "string" ? req.body : "";

  app.log.info(`[POST] Forwarding message to: ${url}`);
  app.log.info(`[POST] Body length: ${body.length}`);

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": req.headers["content-type"] || "text/xml" },
    body
  });

  const text = await res.text();
  app.log.info(`[POST] Supabase response: ${res.status} - ${text}`);

  reply.code(res.status).send(text);
});

// ============================================
// WeCom Customer Service (KF) Routes
// ============================================

// Get KF access token (cached in-memory)
let kfAccessToken = null;
let kfTokenExpiry = 0;

async function getKFAccessToken() {
  if (kfAccessToken && Date.now() < kfTokenExpiry) {
    return kfAccessToken;
  }

  if (!WECOM_CORP_ID || !WECOM_KF_SECRET) {
    throw new Error("Missing WECOM_CORP_ID or WECOM_KF_SECRET");
  }

  const response = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${WECOM_CORP_ID}&corpsecret=${WECOM_KF_SECRET}`
  );
  const data = await response.json();

  if (data.access_token) {
    kfAccessToken = data.access_token;
    kfTokenExpiry = Date.now() + (data.expires_in - 300) * 1000;
    return kfAccessToken;
  }

  throw new Error(`KF token error: ${data.errmsg || JSON.stringify(data)}`);
}

// GET /wecom/kf-token - Return KF access token (protected)
app.get("/wecom/kf-token", async (req) => {
  requireAuth(req);
  const token = await getKFAccessToken();
  return { access_token: token };
});

// WeCom KF -> Proxy (URL VERIFICATION - GET) - handled in Fly (NOT Supabase)
app.get("/wecom/kf-callback", async (req, reply) => {
  try {
    const { msg_signature, timestamp, nonce, echostr } = req.query || {};

    if (!msg_signature || !timestamp || !nonce || !echostr) {
      reply.code(400).type("text/plain").send("missing params");
      return;
    }

    if (!WECOM_KF_TOKEN || !WECOM_KF_ENCODING_AES_KEY || !WECOM_CORP_ID) {
      app.log.error("[KF] Missing Fly env vars for verification", {
        token: !!WECOM_KF_TOKEN,
        encodingAESKeyLen: (WECOM_KF_ENCODING_AES_KEY || "").length,
        corpId: !!WECOM_CORP_ID
      });
      reply.code(500).type("text/plain").send("server misconfigured");
      return;
    }

    // Verify signature: SHA1(sort(token,timestamp,nonce,echostr))
    const ok = verifyWecomSignature({
      token: WECOM_KF_TOKEN,
      timestamp: String(timestamp),
      nonce: String(nonce),
      signature: String(msg_signature),
      data: String(echostr)
    });

    if (!ok) {
      app.log.warn("[KF] Signature verification failed (GET)");
      reply.code(403).type("text/plain").send("Verification failed");
      return;
    }

    // Decrypt echostr and return plaintext
    const plaintext = decryptWecomEchoStr({
      encodingAESKey: WECOM_KF_ENCODING_AES_KEY,
      corpId: WECOM_CORP_ID,
      echostrB64: String(echostr)
    });

    app.log.info("[KF] Verification OK (GET)");
    reply.code(200).type("text/plain").send(plaintext);
  } catch (err) {
    app.log.error({ err }, "[KF] Verification error (GET)");
    reply.code(500).type("text/plain").send("Verification failed");
  }
});

// WeCom KF -> Proxy -> Supabase (INBOUND EVENTS - POST) - keep forwarding
app.post("/wecom/kf-callback", async (req, reply) => {
  const { msg_signature, timestamp, nonce } = req.query || {};

  if (!SUPABASE_FUNCTIONS_URL) {
    throw new Error("Missing SUPABASE_FUNCTIONS_URL");
  }

  const params = new URLSearchParams({
    msg_signature,
    timestamp,
    nonce
  });

  const url = `${SUPABASE_FUNCTIONS_URL}/inbound-wecom-kf?${params}`;

  const body = typeof req.body === "string" ? req.body : "";
  app.log.info(`[POST] KF event forward -> ${url}`);
  app.log.info(`[POST] KF body length: ${body.length}`);

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": req.headers["content-type"] || "text/xml" },
    body
  });

  const text = await res.text();
  app.log.info(`[POST] KF Supabase response: ${res.status} - ${text}`);

  // Always respond success to WeCom to avoid retries
  reply.code(200).header("content-type", "text/plain").send("success");
});

// Proxy -> WeCom KF API: sync messages (protected)
app.post("/wecom/kf-sync", async (req) => {
  requireAuth(req);
  const token = await getKFAccessToken();

  const { cursor, token: syncToken, open_kfid, limit } = req.body || {};

  const res = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token=${token}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        cursor,
        token: syncToken,
        open_kfid,
        limit: limit || 100
      })
    }
  );

  return res.json();
});

// Proxy -> WeCom KF API: send message (protected)
app.post("/wecom/kf-send", async (req) => {
  requireAuth(req);
  const token = await getKFAccessToken();

  const { touser, open_kfid, msgtype, text } = req.body || {};

  const res = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token=${token}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ touser, open_kfid, msgtype, text })
    }
  );

  return res.json();
});

const port = process.env.PORT ? Number(process.env.PORT) : 8080;
try {
  await app.listen({ port, host: "0.0.0.0" });
  console.log(`Server running on port ${port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

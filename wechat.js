// wechat.js — WeChat Service Account integration module
// Covers: URL verification, XML parsing, token management, custom send, template send

import fetch from "node-fetch";
import { XMLParser } from "fast-xml-parser";

// ============================================================
// Config — read from env at module load time
// ============================================================
export const WECHAT_CONFIG = {
  appId:          process.env.WECHAT_APP_ID          || null,
  appSecret:      process.env.WECHAT_APP_SECRET       || null,
  token:          process.env.WECHAT_TOKEN            || null,
  encodingAESKey: process.env.WECHAT_ENCODING_AES_KEY || null,
};

const WECHAT_API = "https://api.weixin.qq.com";

// ============================================================
// XML Parser
// ============================================================
const xmlParser = new XMLParser({ ignoreAttributes: false, parseTagValue: true });

/**
 * Parse a WeChat XML body string into a plain object.
 * Returns { ok: true, data } or { ok: false, error }.
 */
export function parseWeChatXml(rawXml) {
  if (!rawXml || !rawXml.trim()) {
    return { ok: false, error: "empty body" };
  }
  try {
    const parsed = xmlParser.parse(rawXml);
    const msg = parsed?.xml || parsed;
    return { ok: true, data: msg };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Extract a normalised log-safe summary from a parsed WeChat message object.
 */
export function summariseMessage(parsed, rawXmlLength) {
  return {
    ToUserName:   parsed?.ToUserName   ?? null,
    FromUserName: parsed?.FromUserName ?? null,
    MsgType:      parsed?.MsgType      ?? null,
    Event:        parsed?.Event        ?? null,
    CreateTime:   parsed?.CreateTime   ?? null,
    MsgId:        parsed?.MsgId        ?? null,
    EventKey:     parsed?.EventKey     ?? null,
    rawXmlLength: rawXmlLength ?? 0,
  };
}

// ============================================================
// Access Token — in-memory cache with auto-refresh
// ============================================================
let _tokenCache = { token: null, expiresAt: 0 };
const TOKEN_BUFFER_SECS = 300; // refresh 5 min before expiry

async function fetchFreshToken() {
  const { appId, appSecret } = WECHAT_CONFIG;
  if (!appId || !appSecret) {
    throw new Error("WECHAT_APP_ID and WECHAT_APP_SECRET are required");
  }
  const url = `${WECHAT_API}/cgi-bin/token?grant_type=client_credential&appid=${appId}&secret=${appSecret}`;
  const res = await fetch(url);
  const data = await res.json();
  if (data.errcode) {
    throw new Error(`WeChat token error ${data.errcode}: ${data.errmsg}`);
  }
  return { token: data.access_token, expiresIn: data.expires_in };
}

/**
 * Returns a valid WeChat access token, fetching/refreshing as needed.
 * Never throws — returns null on failure so callers can degrade gracefully.
 */
export async function getWeChatAccessToken(log) {
  const now = Date.now() / 1000;
  if (_tokenCache.token && _tokenCache.expiresAt > now) {
    return _tokenCache.token;
  }
  try {
    const { token, expiresIn } = await fetchFreshToken();
    _tokenCache = { token, expiresAt: now + expiresIn - TOKEN_BUFFER_SECS };
    log?.info("[WeChat] Access token refreshed successfully");
    return token;
  } catch (err) {
    log?.error({ err }, "[WeChat] Failed to fetch access token");
    return null;
  }
}

// ============================================================
// Outbound: Custom (customer service) text message
// ============================================================

/**
 * Send a text custom message to a WeChat user.
 * @param {object} opts
 * @param {string} opts.openid    - WeChat user openid
 * @param {string} opts.content   - Text content to send
 * @param {object} opts.log       - Fastify logger (or console)
 */
export async function sendWeChatCustomText({ openid, content, log }) {
  if (!openid?.trim()) throw new Error("sendWeChatCustomText: openid is required");
  if (!content?.trim()) throw new Error("sendWeChatCustomText: content is required");

  const token = await getWeChatAccessToken(log);
  if (!token) throw new Error("sendWeChatCustomText: could not obtain access token");

  const payload = {
    touser:  openid,
    msgtype: "text",
    text:    { content },
  };

  const res = await fetch(
    `${WECHAT_API}/cgi-bin/message/custom/send?access_token=${encodeURIComponent(token)}`,
    {
      method:  "POST",
      headers: { "content-type": "application/json" },
      body:    JSON.stringify(payload),
    }
  );
  const data = await res.json();
  log?.info({ data }, "[WeChat] custom text send response");

  if (data.errcode !== 0) {
    // Retry once on token-expired error
    if (data.errcode === 40001 || data.errcode === 42001) {
      log?.warn("[WeChat] Token expired mid-flight, invalidating cache and retrying");
      _tokenCache = { token: null, expiresAt: 0 };
      return sendWeChatCustomText({ openid, content, log });
    }
    throw new Error(`WeChat custom send error ${data.errcode}: ${data.errmsg}`);
  }
  return data;
}

// ============================================================
// Outbound: Template message
// ============================================================

/**
 * Send a WeChat template message.
 * @param {object} opts
 * @param {string}  opts.openid      - WeChat user openid
 * @param {string}  opts.templateId  - WeChat template ID
 * @param {string}  [opts.url]       - Optional click-through URL
 * @param {object}  [opts.miniprogram] - Optional miniprogram config { appid, pagepath }
 * @param {object}  opts.data        - Template data fields, e.g. { keyword1: { value: '...' } }
 * @param {object}  opts.log
 */
export async function sendWeChatTemplateMessage({ openid, templateId, url, miniprogram, data, log }) {
  if (!openid?.trim())     throw new Error("sendWeChatTemplateMessage: openid is required");
  if (!templateId?.trim()) throw new Error("sendWeChatTemplateMessage: templateId is required");
  if (!data || typeof data !== "object") throw new Error("sendWeChatTemplateMessage: data object is required");

  const token = await getWeChatAccessToken(log);
  if (!token) throw new Error("sendWeChatTemplateMessage: could not obtain access token");

  const payload = {
    touser:      openid,
    template_id: templateId,
    data,
    ...(url        ? { url }        : {}),
    ...(miniprogram ? { miniprogram } : {}),
  };

  const res = await fetch(
    `${WECHAT_API}/cgi-bin/message/template/send?access_token=${encodeURIComponent(token)}`,
    {
      method:  "POST",
      headers: { "content-type": "application/json" },
      body:    JSON.stringify(payload),
    }
  );
  const result = await res.json();
  log?.info({ result }, "[WeChat] template message send response");

  if (result.errcode !== 0) {
    if (result.errcode === 40001 || result.errcode === 42001) {
      log?.warn("[WeChat] Token expired mid-flight, retrying template send");
      _tokenCache = { token: null, expiresAt: 0 };
      return sendWeChatTemplateMessage({ openid, templateId, url, miniprogram, data, log });
    }
    throw new Error(`WeChat template send error ${result.errcode}: ${result.errmsg}`);
  }
  return result;
}

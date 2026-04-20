import fetch from "node-fetch";

// Keyed by `${corpId}:${corpSecret}` to prevent KF and enterprise tokens colliding
const tokenCache = new Map();

/**
 * Generic WeCom access token fetcher with per-secret caching.
 * Used for BOTH enterprise + KF tokens (different secrets = different cache entries).
 */
export async function getWecomAccessToken({ corpId, corpSecret }) {
  const cacheKey = `${corpId}:${corpSecret}`;
  const now = Date.now();
  const cached = tokenCache.get(cacheKey);
  if (cached && now < cached.expiryMs) return cached.token;

  const url = `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(
    corpId
  )}&corpsecret=${encodeURIComponent(corpSecret)}`;

  const res = await fetch(url);
  const raw = await res.text();

  if (!raw || !raw.trim()) {
    throw new Error(`gettoken: empty response from WeCom (HTTP ${res.status})`);
  }

  let data;
  try { data = JSON.parse(raw); }
  catch (e) {
    throw new Error(`gettoken: unparseable response: ${raw.slice(0, 200)}`);
  }

  if (!res.ok || data.errcode !== 0) {
    throw new Error(`gettoken failed: ${JSON.stringify(data)}`);
  }

  tokenCache.set(cacheKey, {
    token: data.access_token,
    expiryMs: now + (data.expires_in - 60) * 1000 // 60s buffer
  });

  return data.access_token;
}

/**
 * KF-specific access token helper
 * Uses WECOM_KF_SECRET (NOT enterprise secret)
 */
export async function getKfAccessToken() {
  const corpId = process.env.WECOM_CORP_ID;
  const kfSecret = process.env.WECOM_KF_SECRET;

  if (!corpId || !kfSecret) {
    throw new Error("Missing WECOM_CORP_ID or WECOM_KF_SECRET");
  }

  return getWecomAccessToken({
    corpId,
    corpSecret: kfSecret
  });
}

/**
 * Send enterprise text message
 */
export async function wecomSendText({ accessToken, agentId, toUser, content }) {
  const url = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(
    accessToken
  )}`;

  const payload = {
    touser: toUser,
    msgtype: "text",
    agentid: Number(agentId),
    text: { content },
    safe: 0
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });

  const raw = await res.text();
  if (!raw || !raw.trim()) throw new Error(`message/send: empty response (HTTP ${res.status})`);
  let data;
  try { data = JSON.parse(raw); } catch (e) { throw new Error(`message/send: unparseable: ${raw.slice(0, 200)}`); }

  if (!res.ok || data.errcode !== 0) {
    throw new Error(`message/send failed: ${JSON.stringify(data)}`);
  }

  return data;
}

/**
 * Fetch KF customer profile info (nickname, avatar, etc.)
 */
export async function kfCustomerBatchGet({ external_userid_list }) {
  if (!Array.isArray(external_userid_list) || external_userid_list.length === 0) {
    throw new Error("external_userid_list must be a non-empty array");
  }

  const accessToken = await getKfAccessToken();

  const res = await fetch(
    `https://qyapi.weixin.qq.com/cgi-bin/kf/customer/batchget?access_token=${encodeURIComponent(
      accessToken
    )}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ external_userid_list })
    }
  );

  const raw = await res.text();
  if (!raw || !raw.trim()) throw new Error(`kf/customer/batchget: empty response (HTTP ${res.status})`);
  let data;
  try { data = JSON.parse(raw); } catch (e) { throw new Error(`kf/customer/batchget: unparseable: ${raw.slice(0, 200)}`); }

  if (!res.ok || data.errcode !== 0) {
    throw new Error(`kf/customer/batchget failed: ${JSON.stringify(data)}`);
  }

  return data;
}

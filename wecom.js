import fetch from "node-fetch";

let cachedToken = null;
let tokenExpiryMs = 0;

/**
 * Generic WeCom access token fetcher
 * Used for BOTH enterprise + KF tokens (different secrets)
 */
export async function getWecomAccessToken({ corpId, corpSecret }) {
  const now = Date.now();
  if (cachedToken && now < tokenExpiryMs) return cachedToken;

  const url = `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(
    corpId
  )}&corpsecret=${encodeURIComponent(corpSecret)}`;

  const res = await fetch(url);
  const data = await res.json();

  if (!res.ok || data.errcode !== 0) {
    throw new Error(`gettoken failed: ${JSON.stringify(data)}`);
  }

  cachedToken = data.access_token;
  tokenExpiryMs = now + (data.expires_in - 60) * 1000; // 60s buffer

  return cachedToken;
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

  const data = await res.json();
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

  const data = await res.json();

  if (!res.ok || data.errcode !== 0) {
    throw new Error(`kf/customer/batchget failed: ${JSON.stringify(data)}`);
  }

  return data;
}

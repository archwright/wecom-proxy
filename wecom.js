import fetch from "node-fetch";

let cachedToken = null;
let tokenExpiryMs = 0;

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
  tokenExpiryMs = now + (data.expires_in - 60) * 1000;
  return cachedToken;
}

export async function wecomSendText({ accessToken, agentId, toUser, content }) {
  const url = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;

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

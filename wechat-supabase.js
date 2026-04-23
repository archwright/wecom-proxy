// wechat-supabase.js — fire-and-forget persistence for inbound WeChat events

import { createClient } from "@supabase/supabase-js";

let _client = null;

function getClient() {
  if (_client) return _client;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  _client = createClient(url, key);
  return _client;
}

/**
 * Persist an inbound WeChat event to wechat_inbound_events.
 * Never throws — logs error and continues so WeChat gets its 200.
 *
 * @param {object} opts
 * @param {string} opts.fromUserName
 * @param {string} opts.toUserName
 * @param {string} opts.msgType
 * @param {string} [opts.eventType]
 * @param {string} opts.rawXml
 * @param {object} opts.parsedPayload
 * @param {object} opts.log  — fastify logger
 */
export async function persistWeChatEvent({ fromUserName, toUserName, msgType, eventType, rawXml, parsedPayload, log }) {
  const supabase = getClient();
  if (!supabase) {
    log?.warn("[WeChat] SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY not set — skipping persistence");
    return;
  }

  const { error } = await supabase.from("wechat_inbound_events").insert({
    source:              "wechat_service_account",
    from_user_name:      fromUserName  ?? null,
    to_user_name:        toUserName    ?? null,
    msg_type:            msgType       ?? null,
    event_type:          eventType     ?? null,
    raw_xml:             rawXml        ?? null,
    parsed_payload_json: parsedPayload ?? null,
    received_at:         new Date().toISOString(),
  });

  if (error) {
    log?.error({ error }, "[WeChat] Supabase insert failed — event not persisted");
  } else {
    log?.info("[WeChat] Event persisted to wechat_inbound_events");
  }
}

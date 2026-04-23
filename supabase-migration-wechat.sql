-- Run this in Supabase SQL editor to create the WeChat inbound events table.
-- Required before Fly app can persist WeChat webhook events.

create table if not exists wechat_inbound_events (
  id                  bigserial primary key,
  source              text        not null default 'wechat_service_account',
  from_user_name      text,
  to_user_name        text,
  msg_type            text,
  event_type          text,
  raw_xml             text,
  parsed_payload_json jsonb,
  received_at         timestamptz not null default now()
);

-- Optional: index for querying by sender
create index if not exists idx_wechat_inbound_from_user
  on wechat_inbound_events (from_user_name, received_at desc);

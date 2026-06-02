// ip-whitelist.js
// IP allowlist enforcement for wecom-proxy-blueedu
//
// Set ALLOWED_IPS env var to a comma-separated list of IPs or IPv4 CIDR blocks.
// Example: ALLOWED_IPS="1.2.3.4,10.0.0.0/8,203.0.113.5"
//
// If ALLOWED_IPS is not set (or empty) the whitelist is DISABLED and all IPs pass.
// Webhook callback paths from Tencent are always exempt regardless.

// Parse the ALLOWED_IPS env var into an array.
// Returns null if whitelisting is disabled.
export function parseAllowedIPs(raw) {
  if (!raw || !raw.trim()) return null; // disabled
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function ipToInt(ip) {
  return ip.split('.').map(Number).reduce((acc, octet) => ((acc << 8) | octet) >>> 0, 0);
}

function isIPv4InCIDR(ip, cidr) {
  const [network, bits] = cidr.split('/');
  const mask = bits !== undefined ? (~0 << (32 - +bits)) >>> 0 : 0xFFFFFFFF;
  return (ipToInt(ip) & mask) === (ipToInt(network) & mask);
}

// Check whether a client IP is in the allowlist.
// Returns true if whitelisting is disabled (allowedList === null).
export function isAllowed(clientIP, allowedList) {
  if (allowedList === null) return true; // whitelist disabled
  if (!clientIP) return false;

  for (const entry of allowedList) {
    if (entry.includes('/')) {
      try {
        if (isIPv4InCIDR(clientIP, entry)) return true;
      } catch {
        // malformed CIDR — skip
      }
    } else if (clientIP === entry) {
      return true;
    }
  }
  return false;
}

// Paths that are always exempt from IP checking.
// These receive callbacks from external services (Tencent WeChat/WeCom servers)
// whose IPs we don't control and shouldn't lock out.
const EXEMPT_PATHS = new Set([
  '/health',
  '/7028d453-f412-4b4f-8bfd-e29dfe0a8033.txt', // WeChat domain verification
  '/wecom/callback',
  '/wechat/callback',
  '/wecom/kf-callback',
]);

export function isExemptPath(rawPath) {
  const path = rawPath.split('?')[0]; // strip query string
  return EXEMPT_PATHS.has(path);
}

// Extract the real client IP from a Fastify request.
// Fly.io sets Fly-Client-IP which reflects the actual remote address
// and cannot be spoofed by the client via X-Forwarded-For.
export function getClientIP(req) {
  const flyIP = req.headers['fly-client-ip'];
  if (flyIP && flyIP.trim()) return flyIP.trim();

  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = xff.split(',')[0].trim();
    if (first) return first;
  }

  return req.socket?.remoteAddress ?? null;
}

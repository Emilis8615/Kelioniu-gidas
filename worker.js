// Prieigos kodų serveris (Cloudflare Worker). Kodai saugomi KV saugykloje "CODES".
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });

function newCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const chars = [...bytes].map(b => ALPHABET[b % ALPHABET.length]);
  return [chars.slice(0, 4), chars.slice(4, 8), chars.slice(8, 12)].map(g => g.join("")).join("-");
}
const norm = c => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const pretty = n => n.match(/.{1,4}/g).join("-");
const key = n => "code:" + n;

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(String(a))), crypto.subtle.digest("SHA-256", enc.encode(String(b)))]);
  const A = new Uint8Array(x), B = new Uint8Array(y);
  let d = 0; for (let i = 0; i < A.length; i++) d |= A[i] ^ B[i];
  return d === 0;
}

async function isAdmin(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const h = request.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  return t ? safeEqual(t, env.ADMIN_PASSWORD) : false;
}

async function body(request) { try { return await request.json(); } catch (e) { return {}; } }

async function redeem(request, env, bind) {
  const { code, device } = await body(request);
  const n = norm(code), dev = String(device || "").slice(0, 100);
  if (n.length !== 12 || !dev) return json({ ok: false, error: "invalid" }, 400);
  const raw = await env.CODES.get(key(n));
  if (!raw) return json({ ok: false, error: "invalid" }, 404);
  const rec = JSON.parse(raw);
  if (rec.revoked) return json({ ok: false, error: "revoked" }, 403);
  if (!rec.device) {
    if (!bind) return json({ ok: false, error: "invalid" }, 403);
    rec.device = dev; rec.activated = new Date().toISOString(); rec.lastSeen = rec.activated;
    await env.CODES.put(key(n), JSON.stringify(rec));
    return json({ ok: true });
  }
  if (rec.device !== dev) return json({ ok: false, error: "other_device" }, 403);
  rec.lastSeen = new Date().toISOString();
  await env.CODES.put(key(n), JSON.stringify(rec));
  return json({ ok: true });
}

async function admin(request, env, path) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  if (path === "/api/admin/list" && request.method === "GET") {
    const out = []; let cursor;
    do {
      const page = await env.CODES.list({ prefix: "code:", cursor });
      for (const k of page.keys) {
        const raw = await env.CODES.get(k.name);
        if (raw) out.push({ code: pretty(k.name.slice(5)), ...JSON.parse(raw) });
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    out.sort((a, b) => String(b.created).localeCompare(String(a.created)));
    return json({ codes: out });
  }
  if (request.method !== "POST") return json({ error: "method" }, 405);
  const b = await body(request);
  if (path === "/api/admin/create") {
    const note = String(b.note || "").slice(0, 200);
    let n; do { n = norm(newCode()); } while (await env.CODES.get(key(n)));
    const rec = { created: new Date().toISOString(), note, device: null, activated: null, lastSeen: null, revoked: false };
    await env.CODES.put(key(n), JSON.stringify(rec));
    return json({ code: pretty(n), ...rec });
  }
  const n = norm(b.code), raw = n && await env.CODES.get(key(n));
  if (!raw) return json({ error: "not_found" }, 404);
  const rec = JSON.parse(raw);
  if (path === "/api/admin/reset") { rec.device = null; rec.activated = null; rec.lastSeen = null; }
  else if (path === "/api/admin/revoke") { rec.revoked = true; }
  else if (path === "/api/admin/restore") { rec.revoked = false; }
  else if (path === "/api/admin/delete") { await env.CODES.delete(key(n)); return json({ ok: true }); }
  else return json({ error: "not_found" }, 404);
  await env.CODES.put(key(n), JSON.stringify(rec));
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url), path = url.pathname;
    if (path === "/api/redeem" && request.method === "POST") return redeem(request, env, true);
    if (path === "/api/check" && request.method === "POST") return redeem(request, env, false);
    if (path.startsWith("/api/admin/")) return admin(request, env, path);
    if (path.startsWith("/api/")) return json({ error: "not_found" }, 404);
    return env.ASSETS.fetch(request);
  }
};

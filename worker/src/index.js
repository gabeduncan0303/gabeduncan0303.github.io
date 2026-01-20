const json = (obj, init = {}) => new Response(JSON.stringify(obj), {
  ...init,
  headers: {
    "content-type": "application/json; charset=utf-8",
    ...(init.headers || {})
  }
});

const corsHeaders = (origin) => ({
  "access-control-allow-origin": origin,
  "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
  "access-control-allow-headers": "authorization,content-type",
  "access-control-max-age": "86400",
  "vary": "Origin"
});

function nowISO() { return new Date().toISOString(); }

function isValidUsername(u) {
  return typeof u === "string" && /^[A-Za-z0-9_\-.]{3,32}$/.test(u);
}

function isValidPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 72;
}

function base64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function pbkdf2(password, saltBytes, iterations = 210000) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const dk = await pbkdf2(password, salt);
  return {
    salt: base64u(salt),
    hash: base64u(dk)
  };
}

async function verifyPassword(password, saltB64u, hashB64u) {
  const salt = Uint8Array.from(atob(saltB64u.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const dk = await pbkdf2(password, salt);
  const got = base64u(dk);
  return timingSafeEqual(got, hashB64u);
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let out = 0;
  for (let i = 0; i < aa.length; i++) out |= aa[i] ^ bb[i];
  return out === 0;
}

function getOrigin(req, env) {
  const o = req.headers.get("Origin");
  const allowed = env.FRONTEND_ORIGIN;
  if (!allowed) return o || "*";
  return (o && o === allowed) ? o : allowed;
}

function bearerToken(req) {
  const h = req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

async function authUser(req, env) {
  const token = bearerToken(req);
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT s.token as token, s.expires_at as expires_at, u.id as user_id, u.username as username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?"
  ).bind(token).first();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }
  return { token, userId: row.user_id, username: row.username };
}

function randomToken() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return base64u(b);
}

function mediaId() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return base64u(b);
}

function extFromMime(mime) {
  const map = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/avif": "avif",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov"
  };
  return map[mime] || "";
}

function classifyType(mime) {
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/")) return "video";
  return null;
}

async function readMultipartFile(req) {
  const ct = req.headers.get("content-type") || "";
  if (!ct.includes("multipart/form-data")) return null;
  const form = await req.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return null;
  return file;
}

function badRequest(msg) { return json({ error: msg }, { status: 400 }); }
function unauthorized() { return json({ error: "Unauthorized" }, { status: 401 }); }
function forbidden() { return json({ error: "Forbidden" }, { status: 403 }); }

export default {
  async fetch(req, env) {
    const origin = getOrigin(req, env);
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const url = new URL(req.url);
    const path = url.pathname;

    const withCors = (res) => {
      const h = new Headers(res.headers);
      for (const [k, v] of Object.entries(corsHeaders(origin))) h.set(k, v);
      return new Response(res.body, { status: res.status, headers: h });
    };

    try {
      if (path === "/api/register" && req.method === "POST") {
        const body = await req.json().catch(() => null);
        const username = body && String(body.username || "").trim();
        const password = body && String(body.password || "");
        if (!isValidUsername(username)) return withCors(badRequest("Invalid username (3-32 chars: letters, numbers, _ - .)"));
        if (!isValidPassword(password)) return withCors(badRequest("Invalid password (min 8 chars)"));

        const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
        if (existing) return withCors(json({ error: "Username already taken" }, { status: 409 }));

        const { salt, hash } = await hashPassword(password);
        await env.DB.prepare(
          "INSERT INTO users (username, pass_salt, pass_hash, created_at) VALUES (?, ?, ?, ?)"
        ).bind(username, salt, hash, nowISO()).run();

        return withCors(json({ ok: true }));
      }

      if (path === "/api/login" && req.method === "POST") {
        const body = await req.json().catch(() => null);
        const username = body && String(body.username || "").trim();
        const password = body && String(body.password || "");
        if (!isValidUsername(username) || !isValidPassword(password)) return withCors(unauthorized());

        const user = await env.DB.prepare(
          "SELECT id, username, pass_salt, pass_hash FROM users WHERE username = ?"
        ).bind(username).first();

        if (!user) return withCors(unauthorized());
        const ok = await verifyPassword(password, user.pass_salt, user.pass_hash);
        if (!ok) return withCors(unauthorized());

        const token = randomToken();
        const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        await env.DB.prepare(
          "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
        ).bind(token, user.id, expires, nowISO()).run();

        return withCors(json({ token, username: user.username, expiresAt: expires }));
      }

      if (path === "/api/logout" && req.method === "POST") {
        const token = bearerToken(req);
        if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
        return withCors(json({ ok: true }));
      }

      if (path === "/api/media" && req.method === "GET") {
        const au = await authUser(req, env);
        if (!au) return withCors(unauthorized());

        const rs = await env.DB.prepare(
          "SELECT id, type, mime_type as mimeType, original_name as originalName, size_bytes as sizeBytes, created_at as createdAt FROM media WHERE owner_id = ? ORDER BY created_at DESC"
        ).bind(au.userId).all();

        return withCors(json({ items: rs.results || [] }));
      }

      if (path === "/api/media" && req.method === "POST") {
        const au = await authUser(req, env);
        if (!au) return withCors(unauthorized());

        const file = await readMultipartFile(req);
        if (!file) return withCors(badRequest("Missing file"));

        const mime = file.type || "application/octet-stream";
        const t = classifyType(mime);
        if (!t) return withCors(badRequest("Only images/videos allowed"));

        const size = file.size || 0;
        const max = t === "video" ? 250 * 1024 * 1024 : 25 * 1024 * 1024;
        if (size > max) return withCors(badRequest("File too large"));

        const id = mediaId();
        const ext = extFromMime(mime);
        const safeName = (file.name || "upload").replace(/[^A-Za-z0-9_.\-]/g, "_").slice(0, 120);
        const key = `${au.userId}/${id}${ext ? "." + ext : ""}`;

        await env.BUCKET.put(key, file.stream(), {
          httpMetadata: { contentType: mime },
          customMetadata: { originalName: safeName }
        });

        await env.DB.prepare(
          "INSERT INTO media (id, owner_id, storage_key, type, mime_type, original_name, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(id, au.userId, key, t, mime, safeName, size, nowISO()).run();

        return withCors(json({ ok: true, id }));
      }

      const mFile = path.match(/^\/api\/media\/([^/]+)\/file$/);
      if (mFile && req.method === "GET") {
        const au = await authUser(req, env);
        if (!au) return withCors(unauthorized());
        const id = decodeURIComponent(mFile[1]);

        const row = await env.DB.prepare(
          "SELECT storage_key as storageKey, owner_id as ownerId, mime_type as mimeType, original_name as originalName FROM media WHERE id = ?"
        ).bind(id).first();

        if (!row) return withCors(json({ error: "Not found" }, { status: 404 }));
        if (row.ownerId !== au.userId) return withCors(forbidden());

        const obj = await env.BUCKET.get(row.storageKey);
        if (!obj) return withCors(json({ error: "Not found" }, { status: 404 }));

        const headers = new Headers();
        headers.set("content-type", row.mimeType || "application/octet-stream");
        headers.set("cache-control", "private, no-store");
        headers.set("content-disposition", `inline; filename="${row.originalName || "file"}"`);

        return withCors(new Response(obj.body, { status: 200, headers }));
      }

      const mDel = path.match(/^\/api\/media\/([^/]+)$/);
      if (mDel && req.method === "DELETE") {
        const au = await authUser(req, env);
        if (!au) return withCors(unauthorized());
        const id = decodeURIComponent(mDel[1]);

        const row = await env.DB.prepare(
          "SELECT storage_key as storageKey, owner_id as ownerId FROM media WHERE id = ?"
        ).bind(id).first();

        if (!row) return withCors(json({ error: "Not found" }, { status: 404 }));
        if (row.ownerId !== au.userId) return withCors(forbidden());

        await env.BUCKET.delete(row.storageKey);
        await env.DB.prepare("DELETE FROM media WHERE id = ?").bind(id).run();

        return withCors(json({ ok: true }));
      }

      return withCors(json({ error: "Not found" }, { status: 404 }));
    } catch (e) {
      return withCors(json({ error: "Server error" }, { status: 500 }));
    }
  }
};

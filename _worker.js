/**
 * Cloudflare Pages Worker (advanced mode) — رفع صور آمن.
 *
 * المتغيرات السرية (Pages ⟶ Settings ⟶ Variables and Secrets):
 *   FIREBASE_PROJECT_ID    مثال: lam7cars
 *   SUPABASE_URL           مثال: https://xxxx.supabase.co
 *   SUPABASE_SERVICE_KEY   مفتاح service_role (Secret — لا يوضع في أي ملف)
 *   SUPABASE_BUCKET        مثال: media   (اختياري، الافتراضي media)
 *
 * الفكرة: المتصفح يرسل توكن Firebase → نتحقق من توقيعه → نتأكد إن صاحبه
 * موجود في admins/{uid} (بنفس توكنه، فتطبّق قواعد Firestore) → ثم نرفع.
 */
const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const MAX_BYTES = 2 * 1024 * 1024;
const TYPES = { "image/webp": "webp", "image/jpeg": "jpg", "image/png": "png" };
const FOLDERS = ["cars", "settings"];

let jwksCache = { keys: null, exp: 0 };

const b64uToBytes = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

async function getKeys() {
  if (jwksCache.keys && Date.now() < jwksCache.exp) return jwksCache.keys;
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error("jwks");
  jwksCache = { keys: (await res.json()).keys, exp: Date.now() + 60 * 60 * 1000 };
  return jwksCache.keys;
}

async function verifyFirebaseToken(token, projectId) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const dec = new TextDecoder();
  const header = JSON.parse(dec.decode(b64uToBytes(parts[0])));
  const payload = JSON.parse(dec.decode(b64uToBytes(parts[1])));
  if (header.alg !== "RS256" || !header.kid) return null;
  const jwk = (await getKeys()).find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uToBytes(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  if (!ok) return null;
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId || payload.iss !== "https://securetoken.google.com/" + projectId) return null;
  if (!payload.sub || payload.exp <= now || payload.iat > now + 60) return null;
  return payload;
}

async function isAdmin(uid, token, projectId) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/admins/${encodeURIComponent(uid)}`;
  const res = await fetch(url, { headers: { Authorization: "Bearer " + token } });
  return res.status === 200;
}

async function handleUpload(request, env) {
  if (request.method !== "POST") return json({ error: "method" }, 405);
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId || !env.SUPABASE_URL || !env.SUPABASE_SERVICE_KEY) return json({ error: "server not configured" }, 500);

  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  let user = null;
  try { user = token ? await verifyFirebaseToken(token, projectId) : null; } catch (e) { user = null; }
  if (!user) return json({ error: "unauthorized" }, 401);
  if (!(await isAdmin(user.sub, token, projectId))) return json({ error: "forbidden" }, 403);

  const type = (request.headers.get("Content-Type") || "").split(";")[0].trim();
  if (!TYPES[type]) return json({ error: "type" }, 415);
  const declared = Number(request.headers.get("Content-Length") || 0);
  if (declared > MAX_BYTES) return json({ error: "too large" }, 413);
  const body = await request.arrayBuffer();
  if (body.byteLength === 0 || body.byteLength > MAX_BYTES) return json({ error: "size" }, 413);

  // اسم الملف: نفس المجلد + اسم عشوائي بامتداد مطابق للنوع (نتجاهل اسم العميل)
  const dir = (new URL(request.url).searchParams.get("path") || "").split("/")[0];
  if (!FOLDERS.includes(dir)) return json({ error: "path" }, 400);
  const name = `${dir}/${Date.now()}_${crypto.randomUUID()}.${TYPES[type]}`;

  const bucket = env.SUPABASE_BUCKET || "media";
  const base = env.SUPABASE_URL.replace(/\/$/, "");
  const up = await fetch(`${base}/storage/v1/object/${bucket}/${name}`, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + env.SUPABASE_SERVICE_KEY,
      apikey: env.SUPABASE_SERVICE_KEY,
      "Content-Type": type,
      "Cache-Control": "max-age=31536000",
      "x-upsert": "false",
    },
    body,
  });
  if (!up.ok) return json({ error: "storage" }, 502);
  return json({ url: `${base}/storage/v1/object/public/${bucket}/${name}` });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/upload") return handleUpload(request, env);
    return env.ASSETS.fetch(request);
  },
};

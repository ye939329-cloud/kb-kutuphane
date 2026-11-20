const PASSWORD_ITERATIONS = 100000;
const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_COOLDOWN_MS = 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizePhone(value) {
  const phone = String(value || "").replace(/[\s()-]/g, "");
  return /^0\d{10}$/.test(phone) ? `+90${phone.slice(1)}` : phone;
}

function normalizeName(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function validEmail(value) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

function validPhone(value) {
  return /^\+?\d{10,15}$/.test(value);
}

function validPassword(value) {
  return typeof value === "string" &&
    value.length >= 8 &&
    value.length <= 256 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid encoding");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function requireSecret(env) {
  if (typeof env.TOKEN_SECRET !== "string" || encoder.encode(env.TOKEN_SECRET).length < 32) {
    throw new Error("TOKEN_SECRET must contain at least 32 bytes");
  }
  return env.TOKEN_SECRET;
}

async function hmac(env, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(requireSecret(env)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

async function passwordHash(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const result = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PASSWORD_ITERATIONS },
    key,
    256,
  );
  return `pbkdf2-sha256$${PASSWORD_ITERATIONS}$${bytesToBase64Url(salt)}$${bytesToBase64Url(new Uint8Array(result))}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false;
  try {
    const salt = base64UrlToBytes(parts[2]);
    const expected = base64UrlToBytes(parts[3]);
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const actual = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      key,
      256,
    ));
    return constantTimeEqual(actual, expected);
  } catch {
    return false;
  }
}

function randomCode() {
  const limit = Math.floor(0x100000000 / 900000) * 900000;
  const value = new Uint32Array(1);
  do {
    crypto.getRandomValues(value);
  } while (value[0] >= limit);
  return String(100000 + (value[0] % 900000));
}

async function createToken(env, user) {
  const payload = bytesToBase64Url(encoder.encode(JSON.stringify({
    id: user.id,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
    ver: user.token_version,
  })));
  const signature = bytesToBase64Url(await hmac(env, `token:${payload}`));
  return `${payload}.${signature}`;
}

async function authenticate(request, env, requiredRole) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.replace(/^Bearer\s+/i, "");
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra) return null;

  try {
    const expected = await hmac(env, `token:${payload}`);
    if (!constantTimeEqual(expected, base64UrlToBytes(signature))) return null;
    const claims = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload)));
    if (!Number.isInteger(claims.id) || !Number.isFinite(claims.exp) || claims.exp <= Date.now()) return null;
    const user = await env.DB.prepare(
      "SELECT id, role, token_version FROM users WHERE id = ?",
    ).bind(claims.id).first();
    if (!user || user.token_version !== claims.ver || (requiredRole && user.role !== requiredRole)) return null;
    return user;
  } catch {
    return null;
  }
}

function deliveryConfigured(env, type) {
  return type === "email"
    ? Boolean(env.RESEND_API_KEY && env.EMAIL_FROM)
    : Boolean(env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_FROM);
}

function allowedOrigins(env) {
  return String(env.APP_ORIGIN || "").split(",").map((value) => value.trim()).filter(Boolean).map((value) => {
    if (value === "*") return value;
    try {
      return new URL(value).origin;
    } catch {
      return value.replace(/\/+$/, "");
    }
  });
}

function logFailure(label, error) {
  const message = String(error && error.message || "");
  let kind = error && error.name || "Error";
  if (message.includes("D1_BINDING_MISSING")) kind = "D1_BINDING_MISSING";
  else if (message.includes("D1_INSERT_DID_NOT_RETURN_ROW_ID")) kind = "D1_INSERT_RESULT_INVALID";
  else if (/no such table|no such column|no such database/i.test(message)) kind = "D1_SCHEMA_MISSING";
  else if (/D1|database|SQLITE/i.test(message)) kind = "D1_QUERY_FAILED";
  console.error(label, kind);
}

async function health(env) {
  if (!env.DB || typeof env.DB.prepare !== "function") {
    return json({ ok: false, database: "binding-missing" }, 503);
  }
  try {
    await env.DB.prepare("SELECT id FROM users LIMIT 0").all();
    await env.DB.prepare("SELECT user_id FROM verification_codes LIMIT 0").all();
    return json({ ok: true, database: "ready" });
  } catch (error) {
    logFailure("Health check failed", error);
    return json({ ok: false, database: "unavailable-or-schema-missing" }, 503);
  }
}

async function deliverCode(env, recipient, type, code, purpose) {
  const subject = purpose === "reset" ? "Parola sıfırlama kodun" : "Ders Çalışma doğrulama kodun";
  const text = `${subject}: ${code}. Kod 10 dakika geçerlidir.`;
  if (type === "email") {
    if (!deliveryConfigured(env, type)) throw new Error("Email delivery is not configured");
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [recipient], subject, text }),
    });
    if (!response.ok) throw new Error("Email provider rejected the request");
    return;
  }

  if (!deliveryConfigured(env, type)) throw new Error("SMS delivery is not configured");
  const account = env.TWILIO_ACCOUNT_SID;
  const credentials = btoa(`${account}:${env.TWILIO_AUTH_TOKEN}`);
  const body = new URLSearchParams({ To: recipient, From: env.TWILIO_FROM, Body: text });
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(account)}/Messages.json`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!response.ok) throw new Error("SMS provider rejected the request");
}

async function createChallenge(env, user, type, purpose) {
  const now = Date.now();
  const previous = await env.DB.prepare(
    "SELECT created_at FROM verification_codes WHERE user_id = ? AND type = ? AND purpose = ?",
  ).bind(user.id, type, purpose).first();
  if (previous && now - previous.created_at < CODE_COOLDOWN_MS) {
    const error = new Error("Kod için kısa süre önce istek yapıldı.");
    error.status = 429;
    throw error;
  }

  const code = randomCode();
  const codeHash = bytesToBase64Url(await hmac(env, `code:${purpose}:${type}:${user.id}:${code}`));
  await env.DB.prepare(
    `INSERT INTO verification_codes (user_id, type, purpose, code_hash, expires_at, attempts, created_at)
     VALUES (?, ?, ?, ?, ?, 0, ?)
     ON CONFLICT(user_id, type, purpose) DO UPDATE SET
       code_hash = excluded.code_hash,
       expires_at = excluded.expires_at,
       attempts = 0,
       created_at = excluded.created_at`,
  ).bind(user.id, type, purpose, codeHash, now + CODE_TTL_MS, now).run();
  await deliverCode(env, type === "email" ? user.email : user.phone, type, code, purpose);
}

async function readJson(request) {
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    const error = new Error("İstek gövdesi çok büyük.");
    error.status = 413;
    throw error;
  }
  const text = await request.text();
  if (encoder.encode(text).length > MAX_BODY_BYTES) {
    const error = new Error("İstek gövdesi çok büyük.");
    error.status = 413;
    throw error;
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    const error = new Error("Geçersiz JSON.");
    error.status = 400;
    throw error;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    const error = new Error("Geçersiz istek.");
    error.status = 400;
    throw error;
  }
  return body;
}

function contactFrom(body) {
  const email = normalizeEmail(body.email) || null;
  const phone = normalizePhone(body.phone) || null;
  if ((email && !validEmail(email)) || (phone && !validPhone(phone))) return null;
  return { email, phone };
}

async function findUser(env, contact) {
  if (contact.email) {
    return env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(contact.email).first();
  }
  if (contact.phone) {
    return env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(contact.phone).first();
  }
  return null;
}

async function findUsersByName(env, name) {
  const result = await env.DB.prepare(
    "SELECT * FROM users WHERE name = ? ORDER BY id DESC",
  ).bind(normalizeName(name)).all();
  return result.results || [];
}

async function findInsertedUser(env, contact, name, createdAt) {
  if (contact.email || contact.phone) return findUser(env, contact);
  return env.DB.prepare(
    "SELECT * FROM users WHERE name = ? AND created_at = ? ORDER BY id DESC LIMIT 1",
  ).bind(name, createdAt).first();
}

async function register(request, env) {
  const body = await readJson(request);
  const name = normalizeName(body.name);
  const contact = contactFrom(body);
  if (!name || name.length > 120 || !contact || !validPassword(body.password)) {
    return json({ error: "Geçerli ad ve güçlü parola gerekli. E-posta/telefon isteğe bağlıdır." }, 400);
  }

  const password = await passwordHash(body.password);
  const createdAt = Date.now();
  let insertedId;
  try {
    await env.DB.prepare(
      `INSERT INTO users (name, email, phone, password_hash, role, created_at)
       VALUES (?, ?, ?, ?, 'student', ?)`,
    ).bind(name, contact.email, contact.phone, password, createdAt).run();
    const insertedUser = await findInsertedUser(env, contact, name, createdAt);
    insertedId = Number(insertedUser && insertedUser.id);
    if (!Number.isSafeInteger(insertedId) || insertedId < 1) {
      const error = new Error("D1_INSERTED_USER_NOT_FOUND");
      error.name = "D1InsertError";
      throw error;
    }
  } catch (error) {
    if (String(error && error.message).includes("UNIQUE constraint failed")) {
      return json({ error: "Bu e-posta veya telefon zaten kayıtlı." }, 409);
    }
    logFailure("Register insert failed", error);
    throw error;
  }

  return json({ id: insertedId, verificationRequired: false }, 201);
}

async function login(request, env) {
  const body = await readJson(request);
  const contact = contactFrom(body);
  const name = normalizeName(body.name);
  if (((!contact || (!contact.email && !contact.phone)) && !name) || typeof body.password !== "string") {
    return json({ error: "Giriş bilgileri hatalı." }, 401);
  }
  const candidates = contact && (contact.email || contact.phone)
    ? [await findUser(env, contact)]
    : await findUsersByName(env, name);
  let user = null;
  for (const candidate of candidates) {
    if (candidate && await verifyPassword(body.password, candidate.password_hash)) {
      user = candidate;
      break;
    }
  }
  if (!user) {
    return json({ error: "Giriş bilgileri hatalı." }, 401);
  }
  return json({
    token: await createToken(env, user),
    user: { id: user.id, name: user.name, role: user.role, email: user.email, phone: user.phone },
  });
}

async function verifyCode(request, env) {
  const body = await readJson(request);
  const contact = contactFrom(body);
  const type = body.type === "email" || body.type === "phone" ? body.type : null;
  if (!contact || !type || (type === "email" && !contact.email) || (type === "phone" && !contact.phone) ||
      !/^\d{6}$/.test(String(body.code || ""))) {
    return json({ error: "Doğrulama bilgileri geçersiz." }, 400);
  }
  const user = await findUser(env, contact);
  if (!user) return json({ error: "Kod geçersiz veya süresi dolmuş." }, 400);

  const codeHash = bytesToBase64Url(await hmac(env, `code:verify:${type}:${user.id}:${body.code}`));
  const now = Date.now();
  const challenge = await env.DB.prepare(
    `SELECT code_hash FROM verification_codes
     WHERE user_id = ? AND type = ? AND purpose = 'verify' AND expires_at > ? AND attempts < 5`,
  ).bind(user.id, type, now).first();
  if (!challenge || !constantTimeEqual(encoder.encode(challenge.code_hash), encoder.encode(codeHash))) {
    if (challenge) {
      await env.DB.prepare(
        `UPDATE verification_codes SET attempts = attempts + 1
         WHERE user_id = ? AND type = ? AND purpose = 'verify' AND attempts < 5`,
      ).bind(user.id, type).run();
    }
    return json({ error: "Kod geçersiz veya süresi dolmuş." }, 400);
  }

  const consumed = await env.DB.prepare(
    `DELETE FROM verification_codes
     WHERE user_id = ? AND type = ? AND purpose = 'verify' AND code_hash = ? AND expires_at > ? AND attempts < 5`,
  ).bind(user.id, type, codeHash, now).run();
  if (!consumed.meta || consumed.meta.changes !== 1) {
    return json({ error: "Kod geçersiz veya süresi dolmuş." }, 400);
  }
  const column = type === "email" ? "email_verified" : "phone_verified";
  await env.DB.prepare(`UPDATE users SET ${column} = 1 WHERE id = ?`).bind(user.id).run();
  return json({ verified: true });
}

async function resendCode(request, env) {
  const body = await readJson(request);
  const contact = contactFrom(body);
  const type = body.type === "email" || body.type === "phone" ? body.type : null;
  if (!contact || !type || (type === "email" && !contact.email) || (type === "phone" && !contact.phone)) {
    return json({ error: "Doğrulama türü geçersiz." }, 400);
  }
  if (!deliveryConfigured(env, type)) return json({ error: "Doğrulama gönderimi henüz yapılandırılmadı." }, 503);
  const user = await findUser(env, contact);
  if (!user) return json({ sent: true });
  const verified = type === "email" ? user.email_verified : user.phone_verified;
  if (verified) return json({ sent: true });
  try {
    await createChallenge(env, user, type, "verify");
  } catch (error) {
    console.error("Verification delivery failed");
    return json({ error: error.status ? error.message : "Kod gönderilemedi." }, error.status || 503);
  }
  return json({ sent: true });
}

async function forgotPassword(request, env) {
  const body = await readJson(request);
  const contact = contactFrom(body);
  if (!contact || (!contact.email && !contact.phone)) {
    return json({ error: "Geçerli e-posta veya telefon gerekli." }, 400);
  }
  const user = await findUser(env, contact);
  if (user) {
    const type = contact.email ? "email" : "phone";
    if (deliveryConfigured(env, type)) {
      try {
        await createChallenge(env, user, type, "reset");
      } catch {
        console.error("Password reset delivery failed");
      }
    }
  }
  return json({ sent: true });
}

async function resetPassword(request, env) {
  const body = await readJson(request);
  const contact = contactFrom(body);
  if (!contact || (!contact.email && !contact.phone) || !/^\d{6}$/.test(String(body.code || "")) ||
      !validPassword(body.password)) {
    return json({ error: "Kod veya yeni parola geçersiz." }, 400);
  }
  const user = await findUser(env, contact);
  if (!user) return json({ error: "Kod veya yeni parola geçersiz." }, 400);
  const type = contact.email ? "email" : "phone";
  const codeHash = bytesToBase64Url(await hmac(env, `code:reset:${type}:${user.id}:${body.code}`));
  const now = Date.now();
  const challenge = await env.DB.prepare(
    `SELECT code_hash FROM verification_codes
     WHERE user_id = ? AND type = ? AND purpose = 'reset' AND expires_at > ? AND attempts < 5`,
  ).bind(user.id, type, now).first();
  if (!challenge || !constantTimeEqual(encoder.encode(challenge.code_hash), encoder.encode(codeHash))) {
    if (challenge) {
      await env.DB.prepare(
        `UPDATE verification_codes SET attempts = attempts + 1
         WHERE user_id = ? AND type = ? AND purpose = 'reset' AND attempts < 5`,
      ).bind(user.id, type).run();
    }
    return json({ error: "Kod veya yeni parola geçersiz." }, 400);
  }

  const newPasswordHash = await passwordHash(body.password);
  const consumed = await env.DB.prepare(
    `DELETE FROM verification_codes
     WHERE user_id = ? AND type = ? AND purpose = 'reset' AND code_hash = ? AND expires_at > ? AND attempts < 5`,
  ).bind(user.id, type, codeHash, now).run();
  if (!consumed.meta || consumed.meta.changes !== 1) {
    return json({ error: "Kod veya yeni parola geçersiz." }, 400);
  }
  await env.DB.prepare(
    "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
  ).bind(newPasswordHash, user.id).run();
  return json({ reset: true });
}

async function adminUsers(request, env) {
  const user = await authenticate(request, env);
  if (!user) return json({ error: "Giriş gerekli." }, 401);
  if (user.role !== "admin") return json({ error: "Yönetici yetkisi gerekli." }, 403);
  const result = await env.DB.prepare(
    `SELECT id, name, email, phone, role, email_verified, phone_verified, created_at
     FROM users ORDER BY id DESC`,
  ).all();
  return json({ users: result.results || [] });
}

function addCors(response, request, env) {
  const requestOrigin = request.headers.get("Origin");
  const allowed = allowedOrigins(env);
  const headers = new Headers(response.headers);
  headers.set("Vary", "Origin");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Max-Age", "86400");
  if (requestOrigin && (allowed.includes("*") || allowed.includes(requestOrigin))) {
    headers.set("Access-Control-Allow-Origin", allowed.includes("*") ? "*" : requestOrigin);
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allowed = allowedOrigins(env);
    if (origin && (!allowed.length || (!allowed.includes("*") && !allowed.includes(origin)))) {
      console.error("CORS rejected request", allowed.length ? "ORIGIN_NOT_ALLOWED" : "APP_ORIGIN_MISSING");
      return addCors(json({ error: "Origin izinli değil." }, 403), request, env);
    }
    if (request.method === "OPTIONS") {
      return addCors(new Response(null, { status: 204 }), request, env);
    }

    try {
      const url = new URL(request.url);
      let response;
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
        response = await health(env);
      } else if (!env.DB || typeof env.DB.prepare !== "function") {
        response = json({ error: "D1 veritabanı bağlaması eksik." }, 503);
      } else if (request.method === "POST" && url.pathname === "/api/auth/register") response = await register(request, env);
      else if (request.method === "POST" && url.pathname === "/api/auth/login") response = await login(request, env);
      else if (request.method === "POST" && url.pathname === "/api/auth/verify") response = await verifyCode(request, env);
      else if (request.method === "POST" && url.pathname === "/api/auth/resend") response = await resendCode(request, env);
      else if (request.method === "POST" && url.pathname === "/api/auth/forgot") response = await forgotPassword(request, env);
      else if (request.method === "POST" && url.pathname === "/api/auth/reset") response = await resetPassword(request, env);
      else if (request.method === "GET" && url.pathname === "/api/admin/users") response = await adminUsers(request, env);
      else response = json({ error: "Bulunamadı." }, 404);
      return addCors(response, request, env);
    } catch (error) {
      if (error.status) return addCors(json({ error: error.message }, error.status), request, env);
      if (String(error && error.message).includes("UNIQUE constraint failed")) {
        return addCors(json({ error: "Bu e-posta veya telefon zaten kayıtlı." }, 409), request, env);
      }
      logFailure("Worker request failed", error);
      if (/no such table|no such column|no such database/i.test(String(error && error.message || ""))) {
        return addCors(json({ error: "D1 şeması eksik; schema.sql dosyasını bu veritabanına uygulayın." }, 503), request, env);
      }
      return addCors(json({ error: "İstek tamamlanamadı." }, 500), request, env);
    }
  },
};

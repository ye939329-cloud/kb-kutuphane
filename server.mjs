import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";
import express from "express";
import helmet from "helmet";
import nodemailer from "nodemailer";

const root = path.dirname(fileURLToPath(import.meta.url));
const env = process.env;
const port = Number(env.PORT || 8787);
const origin = env.APP_ORIGIN || `http://localhost:${port}`;
if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters.");

const dataDir = path.join(root, "data");
fs.mkdirSync(dataDir, { recursive: true });
const storeFile = path.join(dataDir, "store.json");
let store = fs.existsSync(storeFile) ? JSON.parse(fs.readFileSync(storeFile, "utf8")) : { nextId: 1, users: [], codes: [] };
function persist() { fs.writeFileSync(storeFile, JSON.stringify(store, null, 2), "utf8"); }
function findUser(email, phone) { return store.users.find((u) => (email && u.email === email) || (phone && u.phone === phone)); }
function findUserById(id) { return store.users.find((u) => u.id === Number(id)); }
if (env.ADMIN_EMAIL && env.ADMIN_PASSWORD && validContact(normalizeEmail(env.ADMIN_EMAIL), normalizePhone(env.ADMIN_PHONE))) {
  const adminEmail = normalizeEmail(env.ADMIN_EMAIL);
  if (!findUser(adminEmail, null)) {
    if (!validPassword(env.ADMIN_PASSWORD)) throw new Error("ADMIN_PASSWORD does not meet the password policy.");
    const adminHash = await hashPassword(env.ADMIN_PASSWORD);
    store.users.push({ id: store.nextId++, name: "Yönetici", email: adminEmail, phone: normalizePhone(env.ADMIN_PHONE) || null, password_hash: adminHash, role: "admin", email_verified: 1, phone_verified: 1, created_at: new Date().toISOString() });
    persist();
  }
}

const app = express();
// The app is a single HTML file with an inline script; keep Helmet's other
// protections while disabling only the incompatible default CSP policy.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}
function normalizePhone(value) {
  const phone = String(value || "").replace(/[\s()-]/g, "");
  return /^0\d{10}$/.test(phone) ? `+90${phone.slice(1)}` : phone;
}
function validContact(email, phone) {
  return (email && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) || (phone && /^\+?\d{10,15}$/.test(phone));
}
function validPassword(value) {
  return typeof value === "string" && value.length >= 8 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(`${salt}:${key.toString("hex")}`)));
}
async function checkPassword(password, stored) {
  const [salt, expected] = String(stored).split(":");
  if (!salt || !expected) return false;
  const actual = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(actual.split(":")[1], "hex"), Buffer.from(expected, "hex"));
}
function hashCode(code) {
  return crypto.createHash("sha256").update(`${code}:${env.SESSION_SECRET}`).digest("hex");
}
function randomCode() {
  return String(crypto.randomInt(100000, 1000000));
}
function tokenFor(user) {
  const payload = Buffer.from(JSON.stringify({ id: user.id, role: user.role, exp: Date.now() + 7 * 86400000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", env.SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function auth(req, requiredRole) {
  const value = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const [payload, signature] = value.split(".");
  if (!payload || !signature) throw new Error("unauthorized");
  const expected = crypto.createHmac("sha256", env.SESSION_SECRET).update(payload).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) throw new Error("unauthorized");
  const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  if (parsed.exp < Date.now() || (requiredRole && parsed.role !== requiredRole)) throw new Error("forbidden");
  return parsed;
}
function sendEmail(to, code) {
  if (!env.SMTP_HOST) {
    console.warn(`Email provider is not configured; verification code for ${to}: ${code}`);
    return Promise.resolve();
  }
  const transporter = nodemailer.createTransport({ host: env.SMTP_HOST, port: Number(env.SMTP_PORT || 587), secure: Number(env.SMTP_PORT) === 465, auth: { user: env.SMTP_USER, pass: env.SMTP_PASSWORD } });
  return transporter.sendMail({ from: env.SMTP_FROM || env.SMTP_USER, to, subject: "Ders Çalışma doğrulama kodun", text: `Doğrulama kodun: ${code}. Kod 10 dakika geçerlidir.` });
}
async function sendSms(to, code) {
  if (!env.TWILIO_ACCOUNT_SID) {
    console.warn(`SMS provider is not configured; verification code for ${to}: ${code}`);
    return;
  }
  const body = new URLSearchParams({ To: to, From: env.TWILIO_FROM, Body: `Ders Çalışma doğrulama kodun: ${code}` });
  const credentials = Buffer.from(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`).toString("base64");
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`, { method: "POST", headers: { Authorization: `Basic ${credentials}`, "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!response.ok) throw new Error("SMS provider failed");
}
function issueCode(user, type) {
  const code = randomCode();
  store.codes = store.codes.filter((item) => !(item.user_id === user.id && item.type === type));
  store.codes.push({ user_id: user.id, type, code_hash: hashCode(code), expires_at: Date.now() + 10 * 60 * 1000, attempts: 0 });
  persist();
  return code;
}
async function deliverCode(user, type) {
  const code = issueCode(user, type);
  if (type === "email") await sendEmail(user.email, code);
  else await sendSms(user.phone, code);
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    const normalizedEmail = normalizeEmail(email) || null, normalizedPhone = normalizePhone(phone) || null;
    if (!name || !validContact(normalizedEmail, normalizedPhone) || !validPassword(password)) return res.status(400).json({ error: "Geçerli ad, e-posta/telefon ve güçlü parola gerekli." });
    if (findUser(normalizedEmail, normalizedPhone)) return res.status(409).json({ error: "Bu e-posta veya telefon zaten kayıtlı." });
    const user = { id: store.nextId++, name: name.trim(), email: normalizedEmail, phone: normalizedPhone, password_hash: await hashPassword(password), role: "student", email_verified: 0, phone_verified: 0, created_at: new Date().toISOString() };
    store.users.push(user); persist();
    if (user.email) await deliverCode(user, "email");
    if (user.phone) await deliverCode(user, "phone");
    res.status(201).json({ id: user.id, verificationRequired: true });
  } catch (error) {
    console.error(error); res.status(500).json({ error: "Kayıt oluşturulamadı." });
  }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, phone, password } = req.body || {};
    const user = findUser(normalizeEmail(email), normalizePhone(phone));
    if (!user || !(await checkPassword(password, user.password_hash))) return res.status(401).json({ error: "Giriş bilgileri hatalı." });
    if (user.role !== "admin" && !user.email_verified && !user.phone_verified) return res.status(403).json({ error: "Önce e-posta veya telefon doğrulamasını tamamla." });
    res.json({ token: tokenFor(user), user: { id: user.id, name: user.name, role: user.role, email: user.email, phone: user.phone } });
  } catch (error) { console.error(error); res.status(500).json({ error: "Giriş yapılamadı." }); }
});
app.post("/api/auth/verify", async (req, res) => {
  try {
    const { email, phone, type, code } = req.body || {};
    if (!["email", "phone"].includes(type) || !/^\d{6}$/.test(String(code || ""))) return res.status(400).json({ error: "Doğrulama bilgileri geçersiz." });
    const user = findUser(normalizeEmail(email), normalizePhone(phone));
    const stored = user && store.codes.find((item) => item.user_id === user.id && item.type === type);
    if (!user || !stored || stored.expires_at < Date.now() || stored.attempts >= 5 || stored.code_hash !== hashCode(code)) {
      if (stored) { stored.attempts += 1; persist(); }
      return res.status(400).json({ error: "Kod geçersiz veya süresi dolmuş." });
    }
    user[`${type}_verified`] = 1; store.codes = store.codes.filter((item) => !(item.user_id === user.id && item.type === type)); persist();
    res.json({ verified: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Doğrulama başarısız." }); }
});
app.post("/api/auth/resend", async (req, res) => {
  try {
    const { email, phone, type } = req.body || {};
    if (!["email", "phone"].includes(type)) return res.status(400).json({ error: "Doğrulama türü geçersiz." });
    const user = findUser(normalizeEmail(email), normalizePhone(phone));
    if (!user || (type === "email" && !user.email) || (type === "phone" && !user.phone)) return res.status(404).json({ error: "Hesap bulunamadı." });
    await deliverCode(user, type);
    res.json({ sent: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Kod gönderilemedi." }); }
});
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email, phone } = req.body || {};
    const user = findUser(normalizeEmail(email), normalizePhone(phone));
    if (user) await deliverCode(user, user.email ? "email" : "phone");
    res.json({ sent: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Parola sıfırlama kodu gönderilemedi." }); }
});
app.post("/api/auth/reset", async (req, res) => {
  try {
    const { email, phone, code, password } = req.body || {};
    const user = findUser(normalizeEmail(email), normalizePhone(phone));
    const stored = user && store.codes.find((item) => item.user_id === user.id && item.type === (user.email ? "email" : "phone"));
    if (!user || !stored || stored.expires_at < Date.now() || stored.attempts >= 5 || stored.code_hash !== hashCode(code) || !validPassword(password)) return res.status(400).json({ error: "Kod veya yeni parola geçersiz." });
    user.password_hash = await hashPassword(password); store.codes = store.codes.filter((item) => item !== stored); persist();
    res.json({ reset: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Parola sıfırlanamadı." }); }
});
app.get("/api/admin/users", (req, res) => {
  try {
    auth(req, "admin");
    const users = store.users.slice().sort((a, b) => b.id - a.id).map(({ id, name, email, phone, role, email_verified, phone_verified, created_at }) => ({ id, name, email, phone, role, email_verified, phone_verified, created_at }));
    res.json({ users });
  } catch (error) { res.status(error.message === "unauthorized" ? 401 : 403).json({ error: "Yönetici yetkisi gerekli." }); }
});

const staticCandidates = [path.join(root, "ders-calisma-uygulamasi.html"), path.join(root, "..", "ders-calisma-uygulamasi.html")];
const staticFile = staticCandidates.find((file) => fs.existsSync(file)) || staticCandidates[0];
app.get("/", (req, res) => res.sendFile(staticFile));
app.listen(port, () => console.log(`Ders Çalışma backend: ${origin}`));

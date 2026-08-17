// Backend de Educación Financiera
//
// Qué hace:
//  1. Cuentas de usuario con contraseña cifrada — guardadas en Supabase
//     (Postgres), NO en un archivo local — porque el plan gratis de Render
//     borra los archivos locales cada vez que el servidor se reinicia
//     (y se reinicia solo tras 15 minutos sin uso). Con Supabase, tus
//     cuentas y tus datos son permanentes de verdad.
//  2. Recuperar/cambiar contraseña, eliminar cuenta.
//  3. Sesión recordada (un token que el navegador guarda, para no pedir
//     usuario/contraseña cada vez).
//  4. Guarda los datos financieros de cada usuario (gastos, deudas, metas,
//     recordatorios, progreso de cursos) — también en Supabase.
//  5. Notificaciones push reales y códigos de verificación por correo/SMS
//     (igual que antes).

const express = require("express");
const webpush = require("web-push");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------
// Conexión a Supabase (Postgres) — permanente, a diferencia del
// sistema de archivos del propio servidor.
// ---------------------------------------------------------------
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("Falta la variable de entorno DATABASE_URL (la cadena de conexión de Supabase).");
  process.exit(1);
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      country TEXT NOT NULL,
      method TEXT NOT NULL,
      contact TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL DEFAULT '',
      salt TEXT NOT NULL DEFAULT '',
      push_subscription JSONB,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// ---------------------------------------------------------------
// Contraseñas — igual que en la versión de escritorio: PBKDF2-HMAC-SHA256
// con 200,000 iteraciones y una sal aleatoria por cuenta. Nunca en texto plano.
// ---------------------------------------------------------------
const PBKDF2_ITERATIONS = 200000;

function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256").toString("hex");
  return { hash, salt: salt.toString("hex") };
}

function verifyPassword(password, storedHash, saltHex) {
  if (!storedHash || !saltHex) return false;
  const { hash } = hashPassword(password, saltHex);
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(storedHash, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function toPublicUser(row) {
  return { id: row.id, name: row.name, country: row.country, method: row.method, contact: row.contact };
}

// ---------------------------------------------------------------
// Verificación por correo/SMS real (igual que antes)
// ---------------------------------------------------------------
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_CONTACT_EMAIL = process.env.VAPID_CONTACT_EMAIL || "mailto:contacto@example.com";
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error("Faltan VAPID_PUBLIC_KEY y VAPID_PRIVATE_KEY.");
  process.exit(1);
}
webpush.setVapidDetails(VAPID_CONTACT_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL;
const TEXTBELT_KEY = process.env.TEXTBELT_KEY || "textbelt";
const VONAGE_API_KEY = process.env.VONAGE_API_KEY;
const VONAGE_API_SECRET = process.env.VONAGE_API_SECRET;
const VONAGE_FROM = process.env.VONAGE_FROM || "EducFin";

const pendingCodes = new Map(); // contact -> { code, expiresAt }
const CODE_TTL_MS = 10 * 60 * 1000;

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendEmailCode(toEmail, code) {
  if (!RESEND_API_KEY || !RESEND_FROM_EMAIL) {
    throw new Error("RESEND_API_KEY o RESEND_FROM_EMAIL no configurados en el servidor.");
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: RESEND_FROM_EMAIL,
      to: toEmail,
      subject: `Tu código de verificación: ${code}`,
      html: `<p>Tu código de verificación para Educación Financiera es:</p><h2>${code}</h2><p>Vence en 10 minutos.</p>`,
    }),
  });
  if (!res.ok) throw new Error(`Resend respondió ${res.status}: ${await res.text()}`);
}

async function sendViaTextbelt(toPhone, code) {
  const res = await fetch("https://textbelt.com/text", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      phone: toPhone,
      message: `Tu código de verificación de Educación Financiera es: ${code}`,
      key: TEXTBELT_KEY,
    }),
  });
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "Textbelt no pudo enviar el SMS.");
}

async function sendViaVonage(toPhone, code) {
  if (!VONAGE_API_KEY || !VONAGE_API_SECRET) {
    throw new Error("Vonage no está configurado en el servidor.");
  }
  const body = new URLSearchParams({
    api_key: VONAGE_API_KEY,
    api_secret: VONAGE_API_SECRET,
    from: VONAGE_FROM,
    to: toPhone.replace(/[^\d]/g, ""),
    text: `Tu código de verificación de Educación Financiera es: ${code}`,
  });
  const res = await fetch("https://rest.nexmo.com/sms/json", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const data = await res.json();
  const message = data.messages && data.messages[0];
  if (!message || message.status !== "0") {
    throw new Error((message && message["error-text"]) || "Vonage no pudo enviar el SMS.");
  }
}

async function sendSmsCode(toPhone, code) {
  try {
    await sendViaTextbelt(toPhone, code);
    return;
  } catch (textbeltErr) {
    console.error("Textbelt falló, probando con el respaldo:", textbeltErr.message);
  }
  await sendViaVonage(toPhone, code);
}

// ---------------------------------------------------------------
// Servidor
// ---------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => res.json({ ok: true }));

// ----- Código de verificación (crear cuenta / recuperar contraseña) -----
app.post("/api/send-code", async (req, res) => {
  const { contact, method } = req.body;
  if (!contact || !method) return res.status(400).json({ error: "Falta contact o method" });

  const code = generateCode();
  pendingCodes.set(contact, { code, expiresAt: Date.now() + CODE_TTL_MS });

  try {
    if (method === "email") await sendEmailCode(contact, code);
    else if (method === "phone") await sendSmsCode(contact, code);
    else return res.status(400).json({ error: "method debe ser 'email' o 'phone'" });
    res.json({ ok: true });
  } catch (err) {
    pendingCodes.delete(contact);
    console.error("Error enviando código:", err.message);
    res.status(502).json({ error: err.message });
  }
});

app.post("/api/verify-code", (req, res) => {
  const { contact, code } = req.body;
  if (!contact || !code) return res.status(400).json({ error: "Falta contact o code" });

  const entry = pendingCodes.get(contact);
  if (!entry) return res.json({ ok: false, reason: "no_pending" });
  if (Date.now() > entry.expiresAt) {
    pendingCodes.delete(contact);
    return res.json({ ok: false, reason: "expired" });
  }
  if (entry.code !== code) return res.json({ ok: false, reason: "mismatch" });

  pendingCodes.delete(contact);
  res.json({ ok: true });
});

// ----- Cuentas -----

app.get("/api/account-exists", async (req, res) => {
  const { contact } = req.query;
  if (!contact) return res.status(400).json({ error: "Falta contact" });
  const result = await pool.query("SELECT id, method FROM users WHERE contact = $1", [contact]);
  const row = result.rows[0];
  res.json({ exists: !!row, method: row ? row.method : null });
});

// ---------------------------------------------------------------
// Iniciar sesión con Google / Facebook — ambos son gratis (a diferencia
// de "Iniciar sesión con Apple", que exige una cuenta de desarrollador de
// pago, por eso no está incluido).
//
// Cómo funciona: el navegador va a Google/Facebook, la persona inicia
// sesión ahí (su contraseña nunca pasa por nuestro servidor), y el
// proveedor regresa aquí con un código. Lo cambiamos por su correo y
// nombre, y si ya existe una cuenta con ese correo, entra directo; si es
// nueva, mandamos al navegador de vuelta a la app pidiendo su país para
// terminar de crear la cuenta.
// ---------------------------------------------------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FACEBOOK_CLIENT_ID = process.env.FACEBOOK_CLIENT_ID;
const FACEBOOK_CLIENT_SECRET = process.env.FACEBOOK_CLIENT_SECRET;
const BACKEND_URL = process.env.BACKEND_URL || "https://mi-backend-finanzas.onrender.com";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://educacion-financiera-hn.netlify.app";

async function findOrCreateSessionForOAuth(res, email, name, provider) {
  const existing = await pool.query("SELECT id FROM users WHERE contact = $1", [email]);
  if (existing.rows.length > 0) {
    const userId = existing.rows[0].id;
    const token = crypto.randomBytes(32).toString("hex");
    await pool.query("INSERT INTO sessions (token, user_id) VALUES ($1, $2)", [token, userId]);
    res.redirect(`${FRONTEND_URL}/?session_token=${token}`);
  } else {
    // Cuenta nueva: todavía no tenemos su país, así que no la creamos
    // aquí — mandamos a la app a pedirlo, y ahí se termina de crear.
    const params = new URLSearchParams({
      oauth_new: "1", oauth_provider: provider, oauth_email: email, oauth_name: name || email.split("@")[0],
    });
    res.redirect(`${FRONTEND_URL}/?${params}`);
  }
}

app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(500).send("Iniciar sesión con Google no está configurado en el servidor.");
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${BACKEND_URL}/auth/google/callback`,
    response_type: "code",
    scope: "openid email profile",
    access_type: "online",
    prompt: "select_account",
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get("/auth/google/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}/?oauth_error=${encodeURIComponent(error || "sin_codigo")}`);
  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        redirect_uri: `${BACKEND_URL}/auth/google/callback`,
        grant_type: "authorization_code",
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("No se pudo obtener el token de acceso de Google.");

    const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();
    if (!profile.email) throw new Error("Google no compartió tu correo.");

    await findOrCreateSessionForOAuth(res, profile.email, profile.name, "google");
  } catch (err) {
    console.error("Error en Google OAuth:", err.message);
    res.redirect(`${FRONTEND_URL}/?oauth_error=${encodeURIComponent(err.message)}`);
  }
});

app.get("/auth/facebook", (req, res) => {
  if (!FACEBOOK_CLIENT_ID) return res.status(500).send("Iniciar sesión con Facebook no está configurado en el servidor.");
  const params = new URLSearchParams({
    client_id: FACEBOOK_CLIENT_ID,
    redirect_uri: `${BACKEND_URL}/auth/facebook/callback`,
    response_type: "code",
    scope: "email public_profile",
  });
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?${params}`);
});

app.get("/auth/facebook/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect(`${FRONTEND_URL}/?oauth_error=${encodeURIComponent(error || "sin_codigo")}`);
  try {
    const params = new URLSearchParams({
      client_id: FACEBOOK_CLIENT_ID,
      client_secret: FACEBOOK_CLIENT_SECRET,
      code,
      redirect_uri: `${BACKEND_URL}/auth/facebook/callback`,
    });
    const tokenRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?${params}`);
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("No se pudo obtener el token de acceso de Facebook.");

    const profileRes = await fetch(
      `https://graph.facebook.com/me?fields=email,name&access_token=${tokenData.access_token}`
    );
    const profile = await profileRes.json();
    if (!profile.email) throw new Error("Facebook no compartió tu correo.");

    await findOrCreateSessionForOAuth(res, profile.email, profile.name, "facebook");
  } catch (err) {
    console.error("Error en Facebook OAuth:", err.message);
    res.redirect(`${FRONTEND_URL}/?oauth_error=${encodeURIComponent(err.message)}`);
  }
});

// Termina de crear la cuenta de alguien que inició sesión con Google/Facebook
// por primera vez (una vez que ya nos dio su país).
app.post("/api/oauth-signup", async (req, res) => {
  const { name, email, country, provider } = req.body;
  if (!name || !email || !country || !provider) return res.status(400).json({ error: "Faltan datos" });

  const existing = await pool.query("SELECT id FROM users WHERE contact = $1", [email]);
  if (existing.rows.length > 0) return res.status(409).json({ error: "Ya existe una cuenta con ese correo." });

  const result = await pool.query(
    `INSERT INTO users (name, country, method, contact, password_hash, salt)
     VALUES ($1, $2, $3, $4, '', '') RETURNING id, name, country, method, contact`,
    [name, country, `oauth_${provider}`, email]
  );
  const userRow = result.rows[0];
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO sessions (token, user_id) VALUES ($1, $2)", [token, userRow.id]);
  res.json({ ok: true, token, user: toPublicUser(userRow) });
});

app.post("/api/signup", async (req, res) => {
  const { name, country, method, contact, password } = req.body;
  if (!name || !country || !method || !contact || !password) {
    return res.status(400).json({ error: "Faltan datos" });
  }
  if (password.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

  const existing = await pool.query("SELECT id FROM users WHERE contact = $1", [contact]);
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Ya existe una cuenta con ese correo/teléfono" });
  }

  const { hash, salt } = hashPassword(password);
  const result = await pool.query(
    `INSERT INTO users (name, country, method, contact, password_hash, salt)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, country, method, contact`,
    [name, country, method, contact, hash, salt]
  );
  res.json({ ok: true, user: toPublicUser(result.rows[0]) });
});

app.post("/api/login", async (req, res) => {
  const { contact, password } = req.body;
  if (!contact || !password) return res.status(400).json({ error: "Faltan datos" });

  const result = await pool.query("SELECT * FROM users WHERE contact = $1", [contact]);
  const row = result.rows[0];
  if (!row || !verifyPassword(password, row.password_hash, row.salt)) {
    return res.status(401).json({ error: "Correo/teléfono o contraseña incorrectos" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO sessions (token, user_id) VALUES ($1, $2)", [token, row.id]);
  res.json({ ok: true, token, user: toPublicUser(row) });
});

app.post("/api/change-password", async (req, res) => {
  const { userId, currentPassword, newPassword } = req.body;
  if (!userId || !currentPassword || !newPassword) return res.status(400).json({ error: "Faltan datos" });
  if (newPassword.length < 6) return res.status(400).json({ error: "La contraseña nueva debe tener al menos 6 caracteres" });

  const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
  const row = result.rows[0];
  if (!row || !verifyPassword(currentPassword, row.password_hash, row.salt)) {
    return res.status(401).json({ error: "Contraseña actual incorrecta" });
  }
  const { hash, salt } = hashPassword(newPassword);
  await pool.query("UPDATE users SET password_hash = $1, salt = $2 WHERE id = $3", [hash, salt, userId]);
  res.json({ ok: true });
});

app.post("/api/reset-password", async (req, res) => {
  const { contact, newPassword } = req.body;
  if (!contact || !newPassword) return res.status(400).json({ error: "Faltan datos" });
  if (newPassword.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

  const result = await pool.query("SELECT id FROM users WHERE contact = $1", [contact]);
  if (result.rows.length === 0) return res.status(404).json({ error: "No existe una cuenta con ese contacto" });

  const { hash, salt } = hashPassword(newPassword);
  await pool.query("UPDATE users SET password_hash = $1, salt = $2 WHERE contact = $3", [hash, salt, contact]);
  res.json({ ok: true });
});

app.post("/api/delete-account", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ error: "Faltan datos" });

  const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
  const row = result.rows[0];
  if (!row || !verifyPassword(password, row.password_hash, row.salt)) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }
  await pool.query("DELETE FROM users WHERE id = $1", [userId]);
  res.json({ ok: true });
});

// ----- Sesión recordada -----
app.get("/api/session", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: "Falta token" });
  const result = await pool.query(
    `SELECT u.id, u.name, u.country, u.method, u.contact
     FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1`,
    [token]
  );
  if (result.rows.length === 0) return res.status(401).json({ error: "Sesión inválida" });
  res.json({ ok: true, user: toPublicUser(result.rows[0]) });
});

app.post("/api/session/clear", async (req, res) => {
  const { token } = req.body;
  if (token) await pool.query("DELETE FROM sessions WHERE token = $1", [token]);
  res.json({ ok: true });
});

// ----- Datos financieros del usuario -----
app.get("/api/user-data", async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: "Falta userId" });
  const result = await pool.query("SELECT data FROM users WHERE id = $1", [userId]);
  if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });
  res.json({ ok: true, data: result.rows[0].data || {} });
});

app.post("/api/user-data", async (req, res) => {
  const { userId, data } = req.body;
  if (!userId || !data) return res.status(400).json({ error: "Faltan datos" });
  await pool.query("UPDATE users SET data = $1 WHERE id = $2", [JSON.stringify(data), userId]);
  res.json({ ok: true });
});

// ----- Notificaciones push -----
app.post("/api/subscribe", async (req, res) => {
  const { userId, subscription } = req.body;
  if (!userId || !subscription) return res.status(400).json({ error: "Falta userId o subscription" });
  await pool.query("UPDATE users SET push_subscription = $1 WHERE id = $2", [JSON.stringify(subscription), userId]);
  res.json({ ok: true });
});

app.listen(PORT, async () => {
  await initDB();
  console.log(`Servidor escuchando en el puerto ${PORT}, conectado a Supabase.`);
});

// ---------------------------------------------------------------
// Revisor de recordatorios: corre cada minuto.
// ---------------------------------------------------------------
function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

async function checkReminders() {
  const result = await pool.query(
    "SELECT id, data, push_subscription FROM users WHERE push_subscription IS NOT NULL"
  );
  for (const row of result.rows) {
    const data = row.data || {};
    const reminders = data.reminders || [];
    let changed = false;

    for (const reminder of reminders) {
      if (reminder.notified) continue;
      if (reminder.dueDate > todayISO()) continue;

      const payload = JSON.stringify({
        title: "Recordatorio de pago",
        body: `${reminder.name} — vence hoy`,
        tag: "recordatorio-" + reminder.id,
      });

      try {
        await webpush.sendNotification(row.push_subscription, payload);
        reminder.notified = true;
        changed = true;
        console.log(`Push enviado a usuario ${row.id}: ${reminder.name}`);
      } catch (err) {
        console.error(`Error enviando push a ${row.id}:`, err.statusCode || err.message);
        if (err.statusCode === 410 || err.statusCode === 404) {
          await pool.query("UPDATE users SET push_subscription = NULL WHERE id = $1", [row.id]);
        }
      }
    }

    if (changed) {
      await pool.query("UPDATE users SET data = $1 WHERE id = $2", [JSON.stringify(data), row.id]);
    }
  }
}

setInterval(() => { checkReminders().catch((e) => console.error("checkReminders falló:", e.message)); }, 60 * 1000);

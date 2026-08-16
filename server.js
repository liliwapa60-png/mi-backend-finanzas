// Backend de notificaciones para Educación Financiera
//
// Qué hace:
//  1. Guarda la "suscripción push" que el navegador genera para cada usuario.
//  2. Guarda los recordatorios de pago de cada usuario (sincronizados desde la app).
//  3. Cada minuto, revisa si algún recordatorio venció y aún no se avisó,
//     y le envía una notificación push real a través del navegador —
//     incluso si el usuario tiene la app cerrada.
//
// Guarda todo en un archivo JSON local (db.json). Para un uso real con muchos
// usuarios convendría una base de datos de verdad, pero para este prototipo
// alcanza y evita depender de un servicio externo.

const express = require("express");
const webpush = require("web-push");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, "db.json");

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_CONTACT_EMAIL = process.env.VAPID_CONTACT_EMAIL || "mailto:contacto@example.com";

if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error(
    "Faltan las variables de entorno VAPID_PUBLIC_KEY y VAPID_PRIVATE_KEY.\n" +
    "Genéralas con generate-vapid-keys.js y configúralas en tu hosting."
  );
  process.exit(1);
}

webpush.setVapidDetails(VAPID_CONTACT_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// Envío real de código de verificación: correo vía Resend, SMS vía Twilio.
// Si no configuras estas variables, /api/send-code responde con un error claro
// y la app (del lado del cliente) cae de vuelta al modo de demostración.
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL; // ej: "Educación Financiera <codigo@tudominio.com>"
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_FROM_NUMBER = process.env.TWILIO_FROM_NUMBER; // ej: "+15017122661"

// Códigos de verificación pendientes, en memoria (se pierden si el servidor
// se reinicia, lo cual está bien: solo viven unos minutos de todas formas).
const pendingCodes = new Map(); // contact -> { code, expiresAt }
const CODE_TTL_MS = 10 * 60 * 1000; // 10 minutos

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

async function sendSmsCode(toPhone, code) {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FROM_NUMBER) {
    throw new Error("Variables de Twilio no configuradas en el servidor.");
  }
  const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString("base64");
  const body = new URLSearchParams({
    To: toPhone,
    From: TWILIO_FROM_NUMBER,
    Body: `Tu código de verificación de Educación Financiera es: ${code}`,
  });
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`Twilio respondió ${res.status}: ${await res.text()}`);
}

// ---------------------------------------------------------------
// "Base de datos" simple en un archivo JSON
// ---------------------------------------------------------------
function loadDB() {
  if (!fs.existsSync(DB_PATH)) return { users: {} };
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch (e) {
    console.error("db.json corrupto, empezando de cero:", e.message);
    return { users: {} };
  }
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ---------------------------------------------------------------
// Servidor
// ---------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json());

// El navegador manda aquí su suscripción push (una sola vez, o cuando cambie).
app.post("/api/subscribe", (req, res) => {
  const { userId, subscription } = req.body;
  if (!userId || !subscription) return res.status(400).json({ error: "Falta userId o subscription" });

  const db = loadDB();
  if (!db.users[userId]) db.users[userId] = { subscription: null, reminders: [] };
  db.users[userId].subscription = subscription;
  saveDB(db);

  res.json({ ok: true });
});

// La app sincroniza aquí la lista completa de recordatorios de un usuario,
// cada vez que el usuario agrega, edita o borra uno.
app.post("/api/reminders", (req, res) => {
  const { userId, reminders } = req.body;
  if (!userId || !Array.isArray(reminders)) return res.status(400).json({ error: "Falta userId o reminders" });

  const db = loadDB();
  if (!db.users[userId]) db.users[userId] = { subscription: null, reminders: [] };

  // Conserva el estado "notified" de los recordatorios que ya existían,
  // para no volver a notificar uno que ya se avisó.
  const prev = db.users[userId].reminders || [];
  db.users[userId].reminders = reminders.map((r) => {
    const existing = prev.find((p) => p.id === r.id);
    return { ...r, notified: existing ? existing.notified : false };
  });
  saveDB(db);

  res.json({ ok: true });
});

app.get("/health", (req, res) => res.json({ ok: true }));

// Genera un código, lo guarda 10 minutos, y lo envía por correo o SMS de verdad.
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

// Verifica el código que el usuario escribió contra el que se envió.
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

app.listen(PORT, () => console.log(`Servidor de notificaciones escuchando en el puerto ${PORT}`));

// ---------------------------------------------------------------
// Revisor de recordatorios: corre cada minuto, envía el push cuando toca.
// ---------------------------------------------------------------
function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

async function checkReminders() {
  const db = loadDB();
  let changed = false;

  for (const userId of Object.keys(db.users)) {
    const user = db.users[userId];
    if (!user.subscription) continue;

    for (const reminder of user.reminders) {
      if (reminder.notified) continue;
      if (reminder.dueDate > todayISO()) continue; // todavía no vence

      const payload = JSON.stringify({
        title: "Recordatorio de pago",
        body: `${reminder.name} — vence hoy`,
        tag: "recordatorio-" + reminder.id,
      });

      try {
        await webpush.sendNotification(user.subscription, payload);
        reminder.notified = true;
        changed = true;
        console.log(`Push enviado a ${userId}: ${reminder.name}`);
      } catch (err) {
        console.error(`Error enviando push a ${userId}:`, err.statusCode || err.message);
        // Si la suscripción ya no es válida (410/404), la borramos para no seguir intentando.
        if (err.statusCode === 410 || err.statusCode === 404) {
          user.subscription = null;
          changed = true;
        }
      }
    }
  }

  if (changed) saveDB(db);
}

setInterval(checkReminders, 60 * 1000);
checkReminders();

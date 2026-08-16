// Genera un nuevo par de llaves VAPID (públicas/privadas) para el backend
// de notificaciones push. Solo hace falta correrlo si quieres generar tus
// propias llaves en vez de usar las que ya vienen listas en README.md.
//
// Uso:  node generate-vapid-keys.js

const crypto = require("crypto");

function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});

const publicJwk = publicKey.export({ format: "jwk" });
const x = Buffer.from(publicJwk.x, "base64");
const y = Buffer.from(publicJwk.y, "base64");
const publicRaw = Buffer.concat([Buffer.from([0x04]), x, y]);

const privateJwk = privateKey.export({ format: "jwk" });
const privateRaw = Buffer.from(privateJwk.d, "base64");

console.log("Copia estas dos variables a tu hosting (ej. Render → Environment):\n");
console.log("VAPID_PUBLIC_KEY=" + base64url(publicRaw));
console.log("VAPID_PRIVATE_KEY=" + base64url(privateRaw));
console.log(
  "\nLa VAPID_PUBLIC_KEY también hay que pegarla en el archivo del frontend (index.html), " +
  "en la constante VAPID_PUBLIC_KEY."
);

// Шифрует дашборд в страницу входа.
// Использование: KBR_LOGIN=... KBR_PASSWORD=... node tools/encrypt.mjs dashboard.html index.html
// Логин и пароль в репозиторий не попадают: они берутся только из переменных окружения.
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [src, out] = process.argv.slice(2);
const { KBR_LOGIN: login, KBR_PASSWORD: password } = process.env;
if (!src || !out || !login || !password) {
  console.error("Нужны аргументы <dashboard.html> <index.html> и переменные KBR_LOGIN, KBR_PASSWORD");
  process.exit(1);
}
const ITERATIONS = 600000;
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(login + "\n" + password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const data = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, readFileSync(src)));
const b64 = (u) => Buffer.from(u).toString("base64");
const payload = JSON.stringify({ v: 1, iterations: ITERATIONS, salt: b64(salt), iv: b64(iv), data: b64(data) });
const tpl = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "login-template.html"), "utf8");
writeFileSync(out, tpl.replace("/*__PAYLOAD__*/", payload));
console.log(`OK: ${out} (${(data.length / 1024).toFixed(0)} КБ шифротекста)`);

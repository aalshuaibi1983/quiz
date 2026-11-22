// يبني ملف بنك الأسئلة المشفّر bank.js من ملف أسئلة JSON ورموز دخول.
// الاستخدام:  node tools/quiz-build.mjs questions.json CODE1 [CODE2 ...]
// كل رمز يفتح البنك نفسه؛ لإلغاء رمز أعد البناء بدونه.
import fs from 'node:fs';
import zlib from 'node:zlib';
import { webcrypto as crypto } from 'node:crypto';

const [, , src, ...codes] = process.argv;
if (!src || !codes.length) {
  console.error('usage: node tools/quiz-build.mjs questions.json CODE1 [CODE2 ...]');
  process.exit(1);
}
const ITER = 210000;
const norm = (c) => c.normalize('NFKC').toUpperCase().replace(/[\s\-_]/g, '');
const b64 = (u8) => Buffer.from(u8).toString('base64');
const enc = new TextEncoder();

const questions = JSON.parse(fs.readFileSync(src, 'utf8'));
const payload = zlib.gzipSync(Buffer.from(JSON.stringify({ v: 1, built: new Date().toISOString(), questions })), { level: 9 });

const dataKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', dataKey));
const iv = crypto.getRandomValues(new Uint8Array(12));
const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dataKey, payload));

const keys = [];
for (const code of codes) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const base = await crypto.subtle.importKey('raw', enc.encode(norm(code)), 'PBKDF2', false, ['deriveKey']);
  const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const kiv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: kiv }, kek, rawKey));
  keys.push({ s: b64(salt), i: b64(kiv), k: b64(wrapped) });
}

const out = `/* بنك أسئلة مشفّر — جميع الحقوق محفوظة. لا يُفتح إلا برمز دخول من المالك. */\nwindow.QUIZ_BANK=${JSON.stringify({ v: 1, it: ITER, keys, iv: b64(iv), d: b64(data) })};\n`;
fs.writeFileSync('bank.js', out);
console.log(`bank.js: ${questions.length} questions, ${codes.length} code(s), ${out.length} bytes`);

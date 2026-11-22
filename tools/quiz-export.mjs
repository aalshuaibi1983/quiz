// يفك تشفير bank.js برمز دخول صحيح ويحفظ الأسئلة في ملف JSON للتعديل.
// الاستخدام:  node tools/quiz-export.mjs CODE questions.json
import fs from 'node:fs';
import zlib from 'node:zlib';
import { webcrypto as crypto } from 'node:crypto';

const [, , code, dest = 'questions.json'] = process.argv;
if (!code) { console.error('usage: node tools/quiz-export.mjs CODE [questions.json]'); process.exit(1); }
const txt = fs.readFileSync('bank.js', 'utf8');
const bank = JSON.parse(txt.slice(txt.indexOf('{', txt.indexOf('QUIZ_BANK')), txt.lastIndexOf('}') + 1));
const norm = (c) => c.normalize('NFKC').toUpperCase().replace(/[\s\-_]/g, '');
const u8 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm(code)), 'PBKDF2', false, ['deriveKey']);
for (const k of bank.keys) {
  try {
    const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: u8(k.s), iterations: bank.it, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8(k.i) }, kek, u8(k.k));
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const gz = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8(bank.iv) }, key, u8(bank.d));
    const { questions } = JSON.parse(zlib.gunzipSync(Buffer.from(gz)).toString('utf8'));
    fs.writeFileSync(dest, JSON.stringify(questions, null, 1));
    console.log(`${questions.length} questions -> ${dest}`);
    process.exit(0);
  } catch { /* try next key */ }
}
console.error('wrong code'); process.exit(2);

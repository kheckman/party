// Encrypts the invitation into a single index.html, or decrypts a published one.
//   PARTY_CODE=... node build.mjs build <srcDir> <out.html> [formUrl]
//   PARTY_CODE=... node build.mjs open  <index.html> <outDir>
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { webcrypto as c } from 'node:crypto';
import { join } from 'node:path';

const ITER = 600000;
const norm = s => s.toLowerCase().replace(/[^a-z0-9]/g, '');
const code = process.env.PARTY_CODE;
if (!code) { console.error('Set PARTY_CODE'); process.exit(1); }

async function key(salt, iter) {
  const base = await c.subtle.importKey('raw', new TextEncoder().encode(norm(code)), 'PBKDF2', false, ['deriveKey']);
  return c.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const RE = /\/\*VAULT\*\/[\s\S]*?\/\*END\*\//;
const [mode, a, b, formUrl] = process.argv.slice(2);

if (mode === 'build') {
  const read = f => readFileSync(join(a, f), 'utf8');
  const img = f => 'data:image/jpeg;base64,' + readFileSync(join(a, f)).toString('base64');
  const alt = read('alt.txt').trim();
  const bg = existsSync(join(a, 'hero-wide.jpg'))
    ? `<div class="bg"><img class="wide" src="${img('hero-wide.jpg')}" alt="${alt}"><img class="tall" src="${img('hero.jpg')}" alt="${alt}"></div>`
    : `<div class="bg fb"><img class="blur" src="${img('hero.jpg')}" alt=""><img class="tall" src="${img('hero.jpg')}" alt="${alt}"></div>`;
  const rsvp = formUrl
    ? `<a class="btn big" href="${formUrl}" target="_blank" rel="noopener">RSVP now</a><p class="rsvp-note">Opens a short form in a new tab.</p>`
    : `<span class="btn big off" aria-disabled="true">RSVP opens soon</span>`;
  const payload = { title: read('title.txt').trim(), css: read('content.css'), html: read('content.html').replace('{{BG}}', () => bg).replace('{{RSVP}}', () => rsvp) };
  const salt = c.getRandomValues(new Uint8Array(16)), iv = c.getRandomValues(new Uint8Array(12));
  const data = await c.subtle.encrypt({ name: 'AES-GCM', iv }, await key(salt, ITER), new TextEncoder().encode(JSON.stringify(payload)));
  const B = u => Buffer.from(u).toString('base64');
  const vault = { iter: ITER, salt: B(salt), iv: B(iv), data: B(new Uint8Array(data)) };
  writeFileSync(b, read('shell.html').replace(RE, () => '/*VAULT*/' + JSON.stringify(vault) + '/*END*/'));
  console.log('built', b);
} else if (mode === 'open') {
  const v = JSON.parse(readFileSync(a, 'utf8').match(RE)[0].replace('/*VAULT*/', '').replace('/*END*/', ''));
  const D = s => Buffer.from(s, 'base64');
  const plain = await c.subtle.decrypt({ name: 'AES-GCM', iv: D(v.iv) }, await key(D(v.salt), v.iter), D(v.data));
  const p = JSON.parse(new TextDecoder().decode(plain));
  mkdirSync(b, { recursive: true });
  writeFileSync(join(b, 'content.css'), p.css); writeFileSync(join(b, 'content.html'), p.html);
  console.log('opened:', p.title, '| html', p.html.length, 'chars');
} else { console.error('mode must be build or open'); process.exit(1); }

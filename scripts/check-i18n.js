'use strict';
// Verifies that de/en have the same keys and that every data-t key in index.html exists.
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');

global.window = {};
require(path.join(root, 'i18n.js'));
const I = global.window.I18N;

let fail = 0;
const de = Object.keys(I.de).sort();
const en = Object.keys(I.en).sort();
const onlyDe = de.filter(k => !en.includes(k));
const onlyEn = en.filter(k => !de.includes(k));
if (onlyDe.length) { console.error('keys only in de:', onlyDe.join(', ')); fail++; }
if (onlyEn.length) { console.error('keys only in en:', onlyEn.join(', ')); fail++; }

const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const used = new Set();
for (const m of html.matchAll(/data-t(?:-ph)?="([^"]+)"/g)) used.add(m[1]);
const missing = [...used].filter(k => !(k in I.de) || !(k in I.en));
if (missing.length) { console.error('data-t keys missing in i18n:', missing.join(', ')); fail++; }

const empty = [...de, ...en].filter(k => {
  const v = (de.includes(k) ? I.de[k] : '') , w = (en.includes(k) ? I.en[k] : '');
  return v === '' || w === '';
});
if (empty.length) { console.error('empty strings:', [...new Set(empty)].join(', ')); fail++; }

if (fail) { console.error('i18n check FAILED'); process.exit(1); }
console.log('i18n check OK:', de.length, 'keys, both languages, all', used.size, 'data-t keys present');

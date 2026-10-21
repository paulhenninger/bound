#!/usr/bin/env node
// Rotate the issuer's signing key (SPEC §4):  npm run rotate-key
//
// The new key signs from the next start. Old keys stay published until every
// token they signed has expired and its renewal window has closed, then the
// issuer drops them on startup. Run this while the issuer is stopped: a running
// issuer keeps its state in memory and would overwrite the file.

import net from 'node:net';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cfg from '../config.js';
import { loadStore, saver, rotateKey } from './store.js';

const dataFile = process.env.BOUND_ISSUER_DATA ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'data', 'issuer.json');

const running = await new Promise((resolve) => {
  const s = net.connect(cfg.port(cfg.ISSUER), '127.0.0.1', () => { s.destroy(); resolve(true); });
  s.on('error', () => resolve(false));
});
if (running) {
  console.error(`The issuer is running at ${cfg.ISSUER}. Stop it first, then rotate.`);
  process.exit(1);
}

const { db, fresh } = await loadStore(dataFile);
if (fresh) { console.error(`No issuer data at ${dataFile}; start the issuer once first.`); process.exit(1); }
const keepFor = cfg.ACCESS_TTL + cfg.RENEW_WINDOW + 120;
const k = await rotateKey(db, { keepFor });
await saver(dataFile, db)();
console.log(`New signing key ${k.kid}. Previous keys stay published for ${Math.round(keepFor / 3600)} h, then are removed.`);

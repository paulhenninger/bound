// The issuer's persistent state: signing keys, pairwise secret, accounts and
// grants, kept in one JSON file.
//
//   { keys: [{ kid, key (private JWK), created, retireAt? }], pairwiseSecret, users, grants }
//
// The newest key signs. Older keys stay published (so tokens they signed still
// verify, and stay renewable) until their retireAt, then are dropped.

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomId, now } from '../lib/encoding.js';
import { generateKeyPair, exportPrivateJwk } from '../lib/keys.js';

async function newKey() {
  const kp = await generateKeyPair({ extractable: true });
  return { kid: randomId(8), key: await exportPrivateJwk(kp.privateKey), created: now() };
}

/**
 * Load the store. A missing file means a fresh issuer. A file that exists but
 * can't be read is an error: silently replacing it would discard the signing
 * key, every account and every grant.
 * Returns { db, fresh, migrated }.
 */
export async function loadStore(dataFile) {
  let raw = null;
  try { raw = await readFile(dataFile, 'utf8'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (raw === null) {
    return { db: { keys: [await newKey()], pairwiseSecret: randomId(32), users: {}, grants: {} }, fresh: true, migrated: false };
  }
  let db;
  try { db = JSON.parse(raw); } catch { db = null; }
  // Files written before key rotation existed have a single { kid, key }.
  let migrated = false;
  if (db && !db.keys && db.key && db.kid) {
    migrated = true;
    db.keys = [{ kid: db.kid, key: db.key, created: now() }];
    delete db.key; delete db.kid;
  }
  const keysOk = Array.isArray(db?.keys) && db.keys.length > 0 && db.keys.every((k) => typeof k?.kid === 'string' && k.key?.d);
  if (!keysOk || !db.pairwiseSecret || !db.users || !db.grants) {
    throw new Error(`${dataFile} is unreadable or incomplete. Refusing to start rather than replace it. ` +
      'Restore it from a backup, or delete it to start a fresh issuer (all accounts and grants will be lost).');
  }
  return { db, fresh: false, migrated };
}

/**
 * Atomic, serialized saves: write a temp file, then rename it over the old one,
 * so a crash mid-write can't leave a truncated file behind.
 */
export function saver(dataFile, db) {
  let saving = Promise.resolve();
  return () => {
    saving = saving.catch(() => {}).then(async () => {
      await mkdir(dirname(dataFile), { recursive: true });
      const tmp = `${dataFile}.${randomId(6)}.tmp`;
      await writeFile(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
      await rename(tmp, dataFile);
    });
    return saving;
  };
}

/** Drop keys past their retirement. The newest key is never retired. */
export function pruneKeys(db, t = now()) {
  const before = db.keys.length;
  db.keys = db.keys.filter((k, i) => i === db.keys.length - 1 || !(k.retireAt <= t));
  return db.keys.length !== before;
}

/**
 * Start signing with a new key. Existing keys stay published for `keepFor`
 * seconds: long enough for every token they signed to expire *and* for its
 * renewal window to close (renewal accepts expired tokens, so it still needs
 * the old key to check them).
 */
export async function rotateKey(db, { keepFor }) {
  const t = now();
  for (const k of db.keys) k.retireAt = Math.min(k.retireAt ?? Infinity, t + keepFor);
  const k = await newKey();
  db.keys.push(k);
  return k;
}

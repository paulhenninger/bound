#!/usr/bin/env node
// A command-line Bound client (Flow B: back-channel authorization).
//
//   node src/cli/notes.js            list notes
//   node src/cli/notes.js "a note"   add a note, then list
//   node src/cli/notes.js --forget   give the access back and delete the saved key
//
// The CLI has its own key. The issuer binds everything to that key, so the user
// code shown here is useless to anyone who sees it. The key and the latest
// access token are kept in ~/.bound/notes-cli.json (readable only by you) so
// later runs renew instead of asking for approval again. A real client would
// keep the key in the OS key store (Keychain, TPM, Secret Service) instead.

import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import * as cfg from '../config.js';
import { makeHolder, generateKeyPair, exportPrivateJwk, importKeyPairJwk } from '../lib/keys.js';
import { boundFetch } from '../lib/client.js';
import { IssuerDirectory } from '../lib/verifier.js';

const STATE = process.env.BOUND_CLI_STATE ?? join(homedir(), '.bound', 'notes-cli.json');
const args = process.argv.slice(2);
const md = await new IssuerDirectory(cfg.ISSUER).metadata();

const load = async () => { try { return JSON.parse(await readFile(STATE, 'utf8')); } catch { return null; } };
const save = async (s) => { await mkdir(join(STATE, '..'), { recursive: true }); await writeFile(STATE, JSON.stringify(s), { mode: 0o600 }); };

let state = await load();
const key = state?.issuer === cfg.ISSUER ? await makeHolder(await importKeyPairJwk(state.key)) : null;

if (args[0] === '--forget') {
  if (key && state.access) await boundFetch(key, md.revoke_endpoint, { method: 'POST', token: state.access }).catch(() => {});
  await rm(STATE, { force: true });
  console.log('  Access revoked and saved key deleted.');
  process.exit(0);
}

const text = args.join(' ').trim();
const actions = text ? ['read', 'write'] : ['read'];
let access = null;
let holder = key;

// Try the saved access first: renewal needs only the key, no user interaction.
if (holder && state.access && actions.every((a) => state.actions.includes(a))) {
  const r = await boundFetch(holder, md.renew_endpoint, { method: 'POST', token: state.access });
  if (r.ok) { access = r.data.access; console.log('\n  Renewed saved access (no approval needed).'); }
  else console.log(`\n  Saved access is no longer valid (${r.data?.error}); asking for approval again.`);
}

if (!access) {
  // We're about to replace the saved key, so give its grant back first rather
  // than leave it renewable with a key nobody will hold.
  if (holder && state.access) await boundFetch(holder, md.revoke_endpoint, { method: 'POST', token: state.access }).catch(() => {});
  const kp = await generateKeyPair({ extractable: true });
  holder = await makeHolder(kp);
  state = { issuer: cfg.ISSUER, key: await exportPrivateJwk(kp.privateKey), actions };
  const req = await boundFetch(holder, md.request_endpoint, {
    method: 'POST',
    json: { client_name: 'Notes CLI', aud: [cfg.RS], grants: [{ res: `${cfg.RS}/notes/`, act: actions }] },
  });
  if (!req.ok) { console.error('request failed:', req.data); process.exit(1); }

  console.log(`\n  To approve, open ${req.data.interact}\n  and enter the code:  ${req.data.user_code}\n`);

  const deadline = Date.now() + req.data.expires_in * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, req.data.interval * 1000));
    const t = await boundFetch(holder, md.token_endpoint, { method: 'POST', json: { request_id: req.data.request_id } });
    if (t.status === 428) { process.stdout.write('.'); continue; }
    if (!t.ok) { console.error('\nauthorization failed:', t.data?.error); process.exit(1); }
    access = t.data.access;
    break;
  }
  if (!access) { console.error('\ntimed out'); process.exit(1); }
  console.log('\n  Approved.');
}
state.access = access;
await save(state);

const notesUrl = `${cfg.RS}/notes/`;
if (text) {
  const r = await boundFetch(holder, notesUrl, { method: 'POST', token: access, json: { text } });
  console.log(r.ok ? `\n  Added: ${r.data.text}` : `\n  Add failed: ${r.data?.error}`);
}

const list = await boundFetch(holder, notesUrl, { token: access });
if (!list.ok) { console.error('  list failed:', list.data?.error); process.exit(1); }
console.log(`\n  Your notes (${list.data.notes.length}):`);
for (const n of list.data.notes) console.log(`   - ${n.text}`);
console.log();

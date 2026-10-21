// Browser-only files (pages' scripts) never run under the other tests, so check
// them here: every source file parses, every page's import graph resolves to a
// file the servers actually serve, and browser files use no Node-only APIs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const walk = (d) => readdirSync(join(ROOT, d), { withFileTypes: true })
  .flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : e.name.endsWith('.js') ? [join(d, e.name)] : []));

test('every source file parses', () => {
  for (const f of walk('src')) {
    assert.doesNotThrow(() => execFileSync(process.execPath, ['--check', join(ROOT, f)], { stdio: 'pipe' }), f);
  }
});

// What each server serves, by URL prefix (see staticDirs in the servers).
const SITES = {
  issuer: { mounts: { '/lib/': 'src/lib', '/': 'src/issuer/public' }, entries: ['/account.js', '/device.js', '/bound/mediator.js'] },
  rp: { mounts: { '/lib/': 'src/lib', '/': 'src/rp/public' }, entries: ['/app.js'] },
};

function servedFile(site, url) {
  for (const [prefix, dir] of Object.entries(SITES[site].mounts)) {
    if (url.startsWith(prefix)) return join(ROOT, dir, url.slice(prefix.length));
  }
  return null;
}

for (const site of Object.keys(SITES)) {
  test(`${site} pages: imports resolve, and use browser APIs only`, () => {
    const seen = new Set();
    const queue = [...SITES[site].entries];
    while (queue.length) {
      const url = queue.pop();
      if (seen.has(url)) continue;
      seen.add(url);
      const file = servedFile(site, url);
      assert.ok(file && existsSync(file), `${site}: ${url} is not served`);
      const src = readFileSync(file, 'utf8');
      assert.doesNotMatch(src, /from ['"]node:|\bBuffer\.|\bprocess\.|\brequire\(/, `${url} uses a Node-only API`);
      for (const m of src.matchAll(/^\s*(?:import|export)\b[^'"]*?from\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gm)) {
        queue.push(new URL(m[1] ?? m[2], `http://x${url}`).pathname);
      }
    }
    assert.ok(seen.size > SITES[site].entries.length, 'followed some imports');
  });
}

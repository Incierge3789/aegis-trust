#!/usr/bin/env node
// version-parity.mjs
// -----------------------------------------------------------------------------
// ONE-COMMAND version parity gate for aegis-trust. Cross-checks the version
// across ALL of:
//   - local  node/package.json   (npm SDK)
//   - local  node/VERSION
//   - local  node/src/index.ts   (export const VERSION)
//   - local  python/pyproject.toml [project].version  (PyPI SDK)
//   - git    latest tag
//   - LIVE   npm registry   (is this version actually published?)
//   - LIVE   PyPI registry  (is this version actually published?)
//
// Why: existing CI checks only compare LOCAL files to each other. They never hit
// the live registries or the tag, so "the repo says 0.9.1 but PyPI still serves
// 0.8.1" drifts silently until a human notices. This closes that gap.
//
// npm uses the hyphen pre-release form (0.9.0-rc8); PyPI uses the PEP 440
// canonical form (0.9.0rc8). Everything is normalized to a canonical key before
// comparison, so the two spellings are treated as equal.
//
// Usage:
//   node scripts/version-parity.mjs            full check (local + tag + registries)
//   node scripts/version-parity.mjs --offline  local + tag only (no network)
//   node scripts/version-parity.mjs --json     machine-readable output
//
// Exit codes:  0 = full parity   1 = drift   2 = local sources incoherent
// No third-party dependencies.
// -----------------------------------------------------------------------------

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const OFFLINE = args.has('--offline');
const JSON_OUT = args.has('--json');
const PACKAGE = 'aegis-trust';

// PEP 440-ish canonical key so npm (0.9.0-rc8) and PyPI (0.9.0rc8) compare equal.
function canonical(v) {
  if (v == null) return null;
  let s = String(v).trim().replace(/^v/, '').toLowerCase();
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(s);
  if (!m) return s;
  const rel = m[1];
  let rest = m[2];
  if (!rest) return rel;
  let pre = rest.replace(/[-_.]+/g, '');
  pre = pre.replace(/^alpha/, 'a').replace(/^beta/, 'b').replace(/^(preview|pre)/, 'rc').replace(/^c(?=\d)/, 'rc');
  if (/^(a|b|rc|dev)$/.test(pre)) pre += '0';
  return /^dev/.test(pre) ? `${rel}.${pre}` : `${rel}${pre}`;
}

function readLocal(rel, extract) {
  const abs = join(ROOT, rel);
  if (!existsSync(abs)) return { raw: null, note: 'missing' };
  try {
    return { raw: extract(readFileSync(abs, 'utf8')), note: '' };
  } catch (e) {
    return { raw: null, note: `parse error: ${e.message}` };
  }
}

function git(arglist) {
  try { return execFileSync('git', arglist, { cwd: ROOT, encoding: 'utf8' }).trim(); }
  catch { return null; }
}

async function fetchJson(url) {
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) return { err: `HTTP ${res.status}` };
    return { json: await res.json() };
  } catch (e) {
    return { err: e.message };
  }
}

// ---- gather sources --------------------------------------------------------
const sources = [];
const add = (label, raw, note = '') => sources.push({ label, raw, canon: raw == null ? null : canonical(raw), note });

add('local node/package.json', readLocal('node/package.json', (t) => JSON.parse(t).version).raw);
add('local node/VERSION', readLocal('node/VERSION', (t) => t.trim()).raw);
add('local node/src/index.ts', readLocal('node/src/index.ts', (t) => {
  const m = /^export const VERSION = "([^"]+)"/m.exec(t);
  if (!m) throw new Error("no 'export const VERSION'");
  return m[1];
}).raw);
add('local python/pyproject.toml', readLocal('python/pyproject.toml', (t) => {
  const m = /\[project\][\s\S]*?\bversion\s*=\s*"([^"]+)"/.exec(t);
  if (!m) throw new Error('no [project].version');
  return m[1];
}).raw);

// latest tag by version (avoid `git tag` subcommand spelling for tooling hooks)
const latestTag = git(['for-each-ref', '--sort=-version:refname', '--format=%(refname:short)', 'refs/tags']);
add('git latest tag', latestTag ? latestTag.split('\n')[0] : null);

// The "intended" version = the local npm package.json (source of truth for the build).
const intended = sources[0].canon;

// ---- live registries -------------------------------------------------------
let npmInfo = { rawLatest: null, rawRc: null, present: null, note: 'skipped (offline)' };
let pypiInfo = { rawStable: null, present: null, note: 'skipped (offline)' };
if (!OFFLINE) {
  const npm = await fetchJson(`https://registry.npmjs.org/${PACKAGE}`);
  if (npm.json) {
    const tags = npm.json['dist-tags'] || {};
    const versions = npm.json.versions || {};
    npmInfo = {
      rawLatest: tags.latest ?? null,
      rawRc: tags.rc ?? null,
      present: intended != null && Object.keys(versions).some((v) => canonical(v) === intended),
      note: '',
    };
  } else npmInfo.note = npm.err;

  const pypi = await fetchJson(`https://pypi.org/pypi/${PACKAGE}/json`);
  if (pypi.json) {
    const releases = pypi.json.releases || {};
    pypiInfo = {
      rawStable: pypi.json.info?.version ?? null,
      present: intended != null && Object.keys(releases).some((v) => canonical(v) === intended),
      note: '',
    };
  } else pypiInfo.note = pypi.err;
}

// ---- verdict ---------------------------------------------------------------
const localCanons = sources.slice(0, 4).map((s) => s.canon);
const localCoherent = localCanons.every((c) => c != null && c === localCanons[0]);
const tagCanon = sources[4].canon;
const tagAligned = tagCanon != null && tagCanon === intended;
const npmPublished = npmInfo.present === true;
const pypiPublished = pypiInfo.present === true;

const problems = [];
if (!localCoherent) problems.push('local sources disagree (node triple / pyproject)');
if (!tagAligned) problems.push(`latest git tag (${tagCanon ?? 'none'}) != intended (${intended})`);
if (!OFFLINE) {
  if (npmInfo.note) problems.push(`npm registry unreachable: ${npmInfo.note}`);
  else if (!npmPublished) problems.push(`intended ${intended} NOT published on npm`);
  if (pypiInfo.note) problems.push(`PyPI registry unreachable: ${pypiInfo.note}`);
  else if (!pypiPublished) problems.push(`intended ${intended} NOT published on PyPI`);
}

const exitCode = !localCoherent ? 2 : problems.length ? 1 : 0;

if (JSON_OUT) {
  console.log(JSON.stringify({ intended, localCoherent, tagAligned, npm: npmInfo, pypi: pypiInfo, problems, exitCode }, null, 2));
  process.exit(exitCode);
}

// ---- human table -----------------------------------------------------------
const pad = (s, n) => String(s ?? '—').padEnd(n);
console.log(`\naegis-trust version parity  (intended = local npm = ${intended ?? '?'})\n`);
console.log('  ' + pad('SOURCE', 30) + pad('RAW', 16) + pad('CANONICAL', 14) + 'MATCH');
console.log('  ' + '-'.repeat(72));
for (const s of sources) {
  const match = s.canon == null ? '?' : s.canon === intended ? 'OK' : 'DRIFT';
  console.log('  ' + pad(s.label, 30) + pad(s.raw, 16) + pad(s.canon, 14) + match + (s.note ? `  (${s.note})` : ''));
}
if (!OFFLINE) {
  const npmVer = npmInfo.note ? `(${npmInfo.note})` : `latest=${npmInfo.rawLatest} rc=${npmInfo.rawRc}`;
  console.log('  ' + pad('npm registry (live)', 30) + pad(npmVer, 30) + (npmInfo.note ? '?' : npmPublished ? 'PUBLISHED' : 'NOT PUBLISHED'));
  const pypiVer = pypiInfo.note ? `(${pypiInfo.note})` : `stable=${pypiInfo.rawStable}`;
  console.log('  ' + pad('PyPI registry (live)', 30) + pad(pypiVer, 30) + (pypiInfo.note ? '?' : pypiPublished ? 'PUBLISHED' : 'NOT PUBLISHED'));
} else {
  console.log('  (registries skipped — --offline)');
}
console.log('');
if (exitCode === 0) {
  const scope = OFFLINE ? 'local + tag (registries skipped)' : 'local + tag + npm + PyPI';
  console.log(`  ✅ FULL PARITY: ${scope} all agree on ${intended}.\n`);
} else {
  console.log(`  ${exitCode === 2 ? '⛔ LOCAL INCOHERENT' : '⚠️  DRIFT'} — ${problems.length} issue(s):`);
  for (const p of problems) console.log(`     - ${p}`);
  console.log('');
}
process.exit(exitCode);

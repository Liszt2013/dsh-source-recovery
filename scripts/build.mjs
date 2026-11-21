/**
 * Build/validation pass: syntax-check every JavaScript module, parse every JSON
 * document, validate the core self-test and enumerate package files. The package
 * has no bundling step by design: browser and host files are authored ESM.
 */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const checks = [];
function record(id, ok, detail) {
  checks.push({ id, ok, detail });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${id}${detail ? ` — ${detail}` : ''}`);
}

async function walk(dir, out = []) {
  for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
    if (['node_modules', '.git', 'reports', 'work'].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { await walk(full, out); continue; }
    out.push(full);
  }
  return out;
}

const files = await walk(ROOT);
for (const file of files.filter((entry) => entry.endsWith('.js') || entry.endsWith('.mjs'))) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8', windowsHide: true });
  record(`syntax:${path.relative(ROOT, file)}`, result.status === 0, result.status === 0 ? '' : (result.stderr || '').split(/\r?\n/)[0]);
}
for (const file of files.filter((entry) => entry.endsWith('.json'))) {
  try {
    JSON.parse(await fsp.readFile(file, 'utf8'));
    record(`json:${path.relative(ROOT, file)}`, true, '');
  } catch (error) {
    record(`json:${path.relative(ROOT, file)}`, false, error.message);
  }
}
const selftest = spawnSync(process.execPath, [path.join(ROOT, 'bin', 'cli.js'), 'selftest', '--json'], { encoding: 'utf8', windowsHide: true, timeout: 180000 });
let selftestOk = false;
try {
  const line = selftest.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
  selftestOk = JSON.parse(line).ok === true;
} catch { selftestOk = false; }
record('selftest:core', selftest.status === 0 && selftestOk, selftestOk ? 'all core checks passed' : (selftest.stderr || '').split(/\r?\n/)[0]);
const report = { generatedAt: new Date().toISOString(), ok: checks.every((check) => check.ok), checks };
await fsp.mkdir(path.join(ROOT, 'reports'), { recursive: true });
await fsp.writeFile(path.join(ROOT, 'reports', 'build.json'), `${JSON.stringify(report, null, 2)}\n`);
if (!report.ok) process.exitCode = 1;

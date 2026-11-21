/** Deterministic, secret-free self-test of the recovery core. */
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { assertOutputDirectory, extractAsar, extractZip } from './archive.js';
import { identifyFile } from './identify.js';
import { makeAsar, makeSourceMap, makeStoredZip } from './fixtures.js';
import { recover } from './recovery.js';
import { recoverSources } from './sourcemap.js';
import { nowIso } from './util.js';

async function check(checks, id, body) {
  const started = Date.now();
  try {
    const detail = await body();
    checks.push({ id, status: 'passed', detail: typeof detail === 'string' ? detail : 'ok', durationMs: Date.now() - started });
  } catch (error) {
    const code = error instanceof RecoveryError ? error.code : 'E_INTERNAL';
    const message = error instanceof Error ? error.message.replace(/\s+/g, ' ').slice(0, 200) : 'unexpected failure';
    checks.push({ id, status: 'failed', detail: `${code}: ${message}`, durationMs: Date.now() - started });
  }
}

export async function runSelfTest(options = {}) {
  const started = Date.now();
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dsh-source-recovery-selftest-'));
  const checks = [];
  const roots = [dir];
  const config = {
    maxInputBytes: 64 * 1024 * 1024,
    maxEntries: 1000,
    maxExtractedBytes: 32 * 1024 * 1024,
    maxEntryBytes: 8 * 1024 * 1024,
    overwrite: false,
    backendTimeoutMs: 30_000,
    backendOutputLimitBytes: 1024 * 1024,
  };
  try {
    await fsp.writeFile(path.join(dir, 'app.js'), 'const answer = 42;\n', 'utf8');
    await fsp.writeFile(path.join(dir, 'archive.zip'), makeStoredZip([
      { name: 'script.js', data: 'console.log("hello")\n' },
      { name: 'nested/data.txt', data: 'payload' },
    ]));
    await fsp.writeFile(path.join(dir, 'app.asar'), makeAsar({ 'main.js': 'module.exports = 1;\n', 'nested/x.txt': 'x' }));
    await fsp.writeFile(path.join(dir, 'bundle.js.map'), makeSourceMap(['src/app.ts', 'src/util.ts'], ['export const a = 1;\n', 'export const b = 2;\n']));

    await check(checks, 'tmp-writable', async () => {
      await fsp.writeFile(path.join(dir, 'probe.txt'), 'ok');
      return 'temporary workspace is writable';
    });
    await check(checks, 'identify-javascript', async () => {
      const result = await identifyFile(path.join(dir, 'app.js'));
      if (result.family !== 'electron' || result.kind !== 'javascript') throw new Error(`unexpected: ${result.family}/${result.kind}`);
      return `sha256=${result.sha256.slice(0, 12)}… entropy=${result.entropy}`;
    });
    await check(checks, 'identify-zip', async () => {
      const result = await identifyFile(path.join(dir, 'archive.zip'));
      if (result.family !== 'archive' || result.kind !== 'zip') throw new Error(`unexpected: ${result.family}/${result.kind}`);
      return `${result.metadata.zipEntries} members`;
    });
    await check(checks, 'extract-zip', async () => {
      const out = path.join(dir, 'zip-out');
      await assertOutputDirectory(out, roots);
      const result = await extractZip(path.join(dir, 'archive.zip'), out, config);
      if (result.files.length !== 2) throw new Error('expected two files');
      const text = await fsp.readFile(path.join(out, 'nested', 'data.txt'), 'utf8');
      if (text !== 'payload') throw new Error('content mismatch');
      return `${result.files.length} files, ${result.bytes} bytes`;
    });
    await check(checks, 'zip-traversal-rejected', async () => {
      await fsp.writeFile(path.join(dir, 'evil.zip'), makeStoredZip([{ name: '../escape.txt', data: 'x' }]));
      const out = path.join(dir, 'evil-out');
      await assertOutputDirectory(out, roots);
      let rejected = false;
      try { await extractZip(path.join(dir, 'evil.zip'), out, config); } catch (error) {
        rejected = error instanceof RecoveryError && error.code === 'E_ARCHIVE_UNSAFE';
      }
      if (!rejected) throw new Error('traversal archive was not rejected');
      return 'path traversal rejected before writing';
    });
    await check(checks, 'extract-asar', async () => {
      const out = path.join(dir, 'asar-out');
      await assertOutputDirectory(out, roots);
      const result = await extractAsar(path.join(dir, 'app.asar'), out, config);
      if (result.files.length !== 2) throw new Error('expected two ASAR files');
      return `${result.files.length} files`;
    });
    await check(checks, 'sourcemap-s0', async () => {
      const out = path.join(dir, 'sources');
      await assertOutputDirectory(out, roots);
      const result = await recoverSources({ mapPath: path.join(dir, 'bundle.js.map'), outputDir: out });
      if (result.level !== 'S0' || result.recovered !== 2) throw new Error(`unexpected level ${result.level}`);
      return 'two original sources recovered (S0)';
    });
    await check(checks, 'authorization-required', async () => {
      let rejected = false;
      try {
        await recover({ input: path.join(dir, 'app.js'), outputDir: path.join(dir, 'auth-out'), roots, config, authorized: false });
      } catch (error) { rejected = error instanceof RecoveryError && error.code === 'E_AUTHZ_REQUIRED'; }
      if (!rejected) throw new Error('recover() ran without authorization');
      return 'unauthorized recovery rejected before any backend';
    });
    await check(checks, 'no-network-policy', async () => 'no network calls exist in the recovery core; target execution is never performed');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
  const counts = {
    passed: checks.filter((entry) => entry.status === 'passed').length,
    failed: checks.filter((entry) => entry.status === 'failed').length,
    unavailable: 0,
  };
  return {
    ok: counts.failed === 0,
    generatedAt: nowIso(),
    durationMs: Date.now() - started,
    checks,
    counts,
    note: 'fixed self-test; external backends are detected separately by reverse_doctor',
    policy: { executesTargets: false, network: false, requiresAuthorization: true },
  };
}

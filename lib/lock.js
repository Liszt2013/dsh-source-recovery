/** Cross-process output locks: one writer per output path. */
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { sha256 } from './util.js';

const LOCK_ROOT = path.join(os.tmpdir(), 'dsh-source-recovery-locks');

/**
 * Run fn while holding an exclusive lock for the target output path. A second
 * process/operation gets E_BUSY instead of interleaving writes.
 */
export async function withOutputLock(target, fn) {
  if (typeof target !== 'string' || target.length === 0) throw new RecoveryError('E_ARGS', 'lock target is required');
  await fsp.mkdir(LOCK_ROOT, { recursive: true, mode: 0o700 });
  const key = sha256(Buffer.from(path.resolve(target))).toString('hex');
  const lockFile = path.join(LOCK_ROOT, `${key}.lock`);
  let handle;
  try {
    handle = await fsp.open(lockFile, 'wx', 0o600);
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    // Recover a lock left by a crashed process after a short grace period.
    let stale = false;
    try {
      const stat = await fsp.stat(lockFile);
      const content = JSON.parse(await fsp.readFile(lockFile, 'utf8'));
      let alive = false;
      if (Number.isSafeInteger(content.pid) && content.pid > 0) {
        try { process.kill(content.pid, 0); alive = true; } catch { alive = false; }
      }
      stale = !alive || Date.now() - stat.mtimeMs > 60 * 60 * 1000;
    } catch { stale = true; }
    if (!stale) throw new RecoveryError('E_BUSY', 'another recovery operation is already writing this output', { exitCode: 5 });
    const quarantine = `${lockFile}.stale-${process.pid}-${Date.now()}`;
    try { await fsp.rename(lockFile, quarantine); } catch { throw new RecoveryError('E_BUSY', 'another recovery operation is already writing this output', { exitCode: 5 }); }
    await fsp.rm(quarantine, { force: true }).catch(() => {});
    handle = await fsp.open(lockFile, 'wx', 0o600);
  }
  try {
    await handle.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString(), target: path.resolve(target) }));
    return await fn();
  } finally {
    await handle.close().catch(() => {});
    await fsp.rm(lockFile, { force: true }).catch(() => {});
  }
}

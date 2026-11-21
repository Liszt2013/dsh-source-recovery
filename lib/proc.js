/**
 * Bounded child-process execution used for diagnostics and language adapters.
 *
 * No shell is ever used. The environment is an explicit allowlist, output is
 * capped, a deadline is enforced, and a best-effort process-tree kill follows
 * a timeout. Standard output is never logged by this module.
 */
import { spawn } from 'node:child_process';
import { RecoveryError } from './errors.js';

/** Environment variables kept for child processes (no secrets, no profile paths). */
export const CHILD_ENV_ALLOWLIST = Object.freeze([
  'PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'SystemDrive', 'windir', 'WINDIR',
  'PATHEXT', 'ComSpec', 'COMSPEC', 'TEMP', 'TMP', 'TMPDIR',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE',
]);

/**
 * Build the child environment from an allowlist plus explicit additions.
 * @param {Record<string,string>} [extra]
 * @returns {Record<string,string>}
 */
export function childEnvironment(extra = {}) {
  /** @type {Record<string,string>} */
  const env = {};
  for (const key of CHILD_ENV_ALLOWLIST) {
    const value = process.env[key];
    if (typeof value === 'string') env[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new RecoveryError('E_ARGS', 'invalid environment variable name');
    if (typeof value !== 'string') throw new RecoveryError('E_ARGS', 'environment values must be strings');
    env[key] = value;
  }
  return env;
}

/**
 * Best-effort process-tree termination.
 * @param {number|undefined} pid
 */
export function killProcessTree(pid) {
  if (pid === undefined) return;
  if (process.platform === 'win32') {
    const killer = spawn('taskkill', ['/pid', String(pid), '/T', '/F'], {
      stdio: 'ignore',
      windowsHide: true,
      shell: false,
      env: childEnvironment(),
    });
    killer.on('error', () => {});
  } else {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
    }
  }
}

/**
 * Run a command with structured argv, bounded output and a timeout.
 * @param {string} command absolute executable path or a bare name resolved by the OS
 * @param {string[]} args
 * @param {{cwd?:string, timeoutMs?:number, maxOutputBytes?:number, env?:Record<string,string>, signal?:AbortSignal, input?:Buffer}} [options]
 * @returns {Promise<{code:number|null, signal:string|null, stdout:string, stderr:string, timedOut:boolean, truncated:boolean, durationMs:number}>}
 */
export function runProcess(command, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? 30000;
  const maxOutputBytes = options.maxOutputBytes ?? 1024 * 1024;
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let truncated = false;
    /** @type {Buffer[]} */
    const stdoutChunks = [];
    /** @type {Buffer[]} */
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let child;
    try {
      child = spawn(command, args, {
        cwd: options.cwd,
        env: options.env ?? childEnvironment(),
        stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
        windowsHide: true,
        windowsVerbatimArguments: options.verbatim === true,
        shell: false,
        detached: process.platform !== 'win32',
      });
    } catch (error) {
      resolve({
        code: null, signal: null, stdout: '', stderr: '', timedOut: false, truncated: false,
        durationMs: Date.now() - started, spawnError: error instanceof Error ? error.message : 'spawn failed',
      });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessTree(child.pid);
    }, timeoutMs);
    const onAbort = () => {
      timedOut = true;
      killProcessTree(child.pid);
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    const collect = (chunks, bytes, chunk) => {
      const buf = Buffer.from(chunk);
      const remaining = maxOutputBytes - bytes;
      if (remaining <= 0) { truncated = true; return { bytes, chunks }; }
      if (buf.length > remaining) {
        truncated = true;
        chunks.push(buf.subarray(0, remaining));
        return { bytes: maxOutputBytes, chunks };
      }
      chunks.push(buf);
      return { bytes: bytes + buf.length, chunks };
    };
    child.stdout?.on('data', (chunk) => { const next = collect(stdoutChunks, stdoutBytes, chunk); stdoutBytes = next.bytes; });
    child.stderr?.on('data', (chunk) => { const next = collect(stderrChunks, stderrBytes, chunk); stderrBytes = next.bytes; });
    if (options.input !== undefined) {
      child.stdin?.on('error', () => {});
      child.stdin?.end(options.input);
    }
    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      resolve({
        ...result,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
        truncated,
        durationMs: Date.now() - started,
      });
    };
    child.on('error', (error) => settle({ code: null, signal: null, spawnError: error.message }));
    child.on('close', (code, signal) => settle({ code, signal }));
  });
}

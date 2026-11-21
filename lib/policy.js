/**
 * Filesystem policy: absolute paths only, containment in configured roots,
 * symlink and special-file rejection, atomic no-overwrite finalization.
 *
 * The plugin runs inside the DSH host process, so DSH's file sandbox does NOT
 * automatically apply to these Node fs calls. This module is the plugin-owned
 * boundary; it is intentionally conservative and fails closed.
 */
import { constants as fsConstants, promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { random } from './util.js';

/** Environment variable holding extra allowed roots, separated by path.delimiter. */
export const ROOTS_ENV = 'DSH_SOURCE_RECOVERY_ROOTS';

/** Default maximum input size (8 GiB). */
export const DEFAULT_MAX_BYTES = 8 * 1024 * 1024 * 1024;

/**
 * Resolve allowed roots from explicit configuration, environment and cwd.
 * @param {string[]|undefined} explicit
 * @param {{cwd?:string}} [options]
 * @returns {Promise<string[]>}
 */
export async function resolveRoots(explicit, options = {}) {
  const cwd = options.cwd ?? process.cwd();
  /** @type {string[]} */
  let raw = [];
  if (Array.isArray(explicit) && explicit.length > 0) raw = explicit.slice();
  else if (typeof process.env[ROOTS_ENV] === 'string' && process.env[ROOTS_ENV].trim() !== '') {
    raw = process.env[ROOTS_ENV].split(path.delimiter).filter((entry) => entry.trim() !== '');
  } else raw = [cwd];
  const roots = [];
  for (const entry of raw) {
    const absolute = path.resolve(cwd, entry);
    const real = await fsp.realpath(absolute).catch(() => undefined);
    if (real === undefined) throw new RecoveryError('E_PATH_OUTSIDE_ROOT', `configured root does not exist: ${absolute}`);
    const stat = await fsp.stat(real);
    if (!stat.isDirectory()) throw new RecoveryError('E_PATH_OUTSIDE_ROOT', `configured root is not a directory: ${absolute}`);
    if (!roots.includes(real)) roots.push(real);
  }
  if (roots.length === 0) throw new RecoveryError('E_PATH_OUTSIDE_ROOT', 'no allowed filesystem roots are configured');
  return roots;
}

/**
 * Whether target is inside root (equality included), case-insensitively on
 * Windows. Both arguments must be canonical absolute paths.
 * @param {string} root
 * @param {string} target
 */
export function isInside(root, target) {
  const relative = path.relative(root, target);
  if (relative === '') return true;
  if (relative.startsWith('..') || path.isAbsolute(relative)) return false;
  return true;
}

/**
 * Require an absolute, NUL-free path spelling.
 * @param {string} candidate
 * @param {string} label
 * @returns {string}
 */
export function requireAbsolutePath(candidate, label) {
  if (typeof candidate !== 'string' || candidate.length === 0) throw new RecoveryError('E_ARGS', `${label} is required`);
  if (candidate.includes('\u0000')) throw new RecoveryError('E_ARGS', `${label} must not contain NUL bytes`);
  if (!path.isAbsolute(candidate)) throw new RecoveryError('E_PATH_ABSOLUTE', `${label} must be an absolute path`);
  return path.resolve(candidate);
}

/**
 * Validate an input file: regular file, not a symlink, inside an allowed root,
 * within the byte limit. Returns the canonical path and size.
 * @param {string} candidate
 * @param {{roots:string[], maxBytes?:number, label?:string}} options
 * @returns {Promise<{path:string,size:number}>}
 */
export async function assertInputFile(candidate, options) {
  const label = options.label ?? 'input file';
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const absolute = requireAbsolutePath(candidate, label);
  const stat = await fsp.lstat(absolute).catch((error) => {
    throw new RecoveryError('E_IO', `${label} does not exist or cannot be inspected`, { cause: error });
  });
  if (stat.isSymbolicLink()) throw new RecoveryError('E_PATH_SYMLINK', `${label} must not be a symbolic link`);
  if (!stat.isFile()) throw new RecoveryError('E_PATH_SPECIAL', `${label} must be a regular file`);
  const real = await fsp.realpath(absolute);
  if (!options.roots.some((root) => isInside(root, real))) {
    throw new RecoveryError('E_PATH_OUTSIDE_ROOT', `${label} is outside the configured allowed roots`);
  }
  if (stat.size > maxBytes) throw new RecoveryError('E_LIMIT_INPUT', `${label} exceeds the ${maxBytes}-byte limit`);
  return { path: real, size: stat.size };
}

/**
 * Validate an output file location. The parent directory must exist, be a
 * real directory inside an allowed root, and the final path must not be an
 * existing directory or symlink. Overwrite is opt-in.
 * @param {string} candidate
 * @param {{roots:string[], overwrite?:boolean, label?:string}} options
 * @returns {Promise<{path:string, existed:boolean}>}
 */
export async function assertOutputFile(candidate, options) {
  const label = options.label ?? 'output file';
  const absolute = requireAbsolutePath(candidate, label);
  const parent = path.dirname(absolute);
  const parentReal = await fsp.realpath(parent).catch(() => undefined);
  if (parentReal === undefined) throw new RecoveryError('E_IO', `${label} parent directory does not exist`);
  const parentStat = await fsp.stat(parentReal);
  if (!parentStat.isDirectory()) throw new RecoveryError('E_IO', `${label} parent is not a directory`);
  if (!options.roots.some((root) => isInside(root, parentReal))) {
    throw new RecoveryError('E_PATH_OUTSIDE_ROOT', `${label} is outside the configured allowed roots`);
  }
  const finalPath = path.join(parentReal, path.basename(absolute));
  let existed = false;
  try {
    const stat = await fsp.lstat(finalPath);
    existed = true;
    if (stat.isSymbolicLink()) throw new RecoveryError('E_PATH_SYMLINK', `${label} must not be a symbolic link`);
    if (stat.isDirectory()) throw new RecoveryError('E_PATH_EXISTS', `${label} is an existing directory`);
  } catch (error) {
    if (error instanceof RecoveryError) throw error;
    if (error.code !== 'ENOENT') throw new RecoveryError('E_IO', `${label} cannot be inspected`, { cause: error });
  }
  if (existed && options.overwrite !== true) {
    throw new RecoveryError('E_PATH_EXISTS', `${label} already exists; overwrite is disabled by default`);
  }
  return { path: finalPath, existed };
}

/**
 * Create a 0600 temporary file in the destination directory with an
 * unpredictable name. The caller must remove it on failure.
 * @param {string} directory canonical absolute directory
 * @param {string} tag
 */
export async function createTempFile(directory, tag) {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const name = `.dspc-${tag}-${random(12).toString('hex')}.tmp`;
    const candidate = path.join(directory, name);
    try {
      const handle = await fsp.open(candidate, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
      return { path: candidate, handle };
    } catch (error) {
      if (error.code !== 'EEXIST') throw new RecoveryError('E_IO', 'failed to create a temporary output file', { cause: error });
    }
  }
  throw new RecoveryError('E_IO', 'failed to allocate a unique temporary output file');
}

/**
 * Atomically publish a fully written temporary file without overwriting an
 * existing target. Uses an exclusive hard link where supported, then falls
 * back to an existence check plus rename on filesystems without hard links.
 * @param {string} tempPath
 * @param {string} finalPath
 * @param {boolean} overwrite
 */
export async function publishTempFile(tempPath, finalPath, overwrite) {
  if (overwrite === true) {
    await fsp.rename(tempPath, finalPath);
    return;
  }
  try {
    await fsp.link(tempPath, finalPath);
    await fsp.unlink(tempPath).catch(() => {});
    return;
  } catch (error) {
    if (error.code === 'EEXIST') throw new RecoveryError('E_PATH_EXISTS', 'output file already exists; overwrite is disabled');
    // Filesystems without hard links: a pre-checked rename. The window is small
    // and documented; the exclusive link path remains the default.
    const exists = await fsp.lstat(finalPath).then(() => true).catch(() => false);
    if (exists) throw new RecoveryError('E_PATH_EXISTS', 'output file already exists; overwrite is disabled');
    await fsp.rename(tempPath, finalPath);
  }
}

/**
 * Remove a temporary file, ignoring absence.
 * @param {string} tempPath
 */
export async function removeTempFile(tempPath) {
  if (typeof tempPath !== 'string' || tempPath.length === 0) return;
  await fsp.rm(tempPath, { force: true }).catch(() => {});
}

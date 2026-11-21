/** Safe archive/ASAR extraction and metadata scanning (no target execution). */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { RecoveryError } from './errors.js';
import { isInside } from './policy.js';
import { sha256 } from './util.js';

/**
 * Electron patches `node:fs` so any path ending in `.asar` is treated as an
 * application archive and validated, which breaks analysis of arbitrary ASAR
 * files. `original-fs` bypasses that interception; plain Node falls back to the
 * standard implementation.
 */
export const TARGET_FS = await import('original-fs')
  .then((module) => module.promises ?? module.default?.promises ?? null)
  .catch(() => null) ?? fsp;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buffer) {
  let c = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function readAt(handle, position, length) {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  return buffer.subarray(0, bytesRead);
}

/** Reject absolute, drive-qualified, traversal and NUL names; return safe segments. */
export function safeSegments(name) {
  const normalized = String(name).replace(/\\/g, '/');
  if (normalized.includes('\0')) throw new RecoveryError('E_ARCHIVE_UNSAFE', 'archive member name contains NUL');
  const segments = normalized.split('/').filter((segment) => segment !== '');
  if (segments.length === 0) throw new RecoveryError('E_ARCHIVE_UNSAFE', 'archive member has an empty name');
  for (const segment of segments) {
    if (segment === '.' || segment === '..') throw new RecoveryError('E_ARCHIVE_UNSAFE', `archive member escapes the output directory: ${name}`);
    if (/^[A-Za-z]:/.test(segment)) throw new RecoveryError('E_ARCHIVE_UNSAFE', `archive member uses a drive letter: ${name}`);
  }
  return segments;
}

export function safeJoin(root, segments) {
  const target = path.resolve(root, ...segments);
  if (!isInside(root, target)) throw new RecoveryError('E_ARCHIVE_UNSAFE', 'archive member escapes the output directory');
  return target;
}

export async function assertOutputDirectory(target, roots, overwrite = false) {
  const requested = path.resolve(target);
  const parent = path.dirname(requested);
  const realParent = await fsp.realpath(parent).catch(() => null);
  if (realParent === null) throw new RecoveryError('E_IO', 'output directory parent does not exist', { exitCode: 5 });
  const parentStat = await fsp.lstat(realParent);
  if (!parentStat.isDirectory()) throw new RecoveryError('E_PATH_UNSAFE', 'output directory parent is not a directory', { exitCode: 5 });
  if (!roots.some((root) => isInside(root, realParent))) {
    throw new RecoveryError('E_PATH_OUTSIDE_ROOT', 'output directory must be inside an allowed root', { exitCode: 5 });
  }
  const resolved = path.join(realParent, path.basename(requested));
  try {
    const stat = await fsp.lstat(resolved);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new RecoveryError('E_PATH_EXISTS', 'output directory exists and is not a plain directory');
    }
    const entries = await fsp.readdir(resolved);
    if (entries.length > 0 && overwrite !== true) {
      throw new RecoveryError('E_PATH_EXISTS', 'output directory is not empty; choose a new directory or enable overwrite');
    }
    if (entries.length > 0) throw new RecoveryError('E_PATH_EXISTS', 'overwriting a non-empty directory is not supported');
    return { path: resolved, created: false };
  } catch (error) {
    if (error instanceof RecoveryError) throw error;
    if (error?.code !== 'ENOENT') throw error;
  }
  await fsp.mkdir(resolved, { recursive: true, mode: 0o700 });
  return { path: resolved, created: true };
}

/** Read ZIP central directory metadata without extracting. */
export async function scanZip(filePath) {
  const handle = await fsp.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    if (stat.size < 22) throw new RecoveryError('E_ARCHIVE_INVALID', 'file is too small to be a ZIP');
    const tailSize = Math.min(stat.size, 65557 + 22);
    const tail = await readAt(handle, stat.size - tailSize, tailSize);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i -= 1) {
      if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new RecoveryError('E_ARCHIVE_INVALID', 'ZIP end-of-central-directory record not found');
    const diskNumber = tail.readUInt16LE(eocd + 4);
    const cdDisk = tail.readUInt16LE(eocd + 6);
    const totalEntries = tail.readUInt16LE(eocd + 10);
    const cdSize = tail.readUInt32LE(eocd + 12);
    const cdOffset = tail.readUInt32LE(eocd + 16);
    if (diskNumber !== 0 || cdDisk !== 0 || totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      throw new RecoveryError('E_UNSUPPORTED', 'multi-disk or ZIP64 archives are not supported by the built-in extractor');
    }
    if (cdOffset + cdSize > stat.size || cdSize === 0) throw new RecoveryError('E_ARCHIVE_INVALID', 'ZIP central directory is out of bounds');
    const central = await readAt(handle, cdOffset, cdSize);
    const entries = [];
    let offset = 0;
    for (let index = 0; index < totalEntries; index += 1) {
      if (offset + 46 > central.length || central.readUInt32LE(offset) !== 0x02014b50) {
        throw new RecoveryError('E_ARCHIVE_INVALID', `invalid ZIP central directory entry ${index}`);
      }
      const versionMadeBy = central.readUInt16LE(offset + 4);
      const flags = central.readUInt16LE(offset + 8);
      const method = central.readUInt16LE(offset + 10);
      const crc = central.readUInt32LE(offset + 16);
      const compressedSize = central.readUInt32LE(offset + 20);
      const uncompressedSize = central.readUInt32LE(offset + 24);
      const nameLength = central.readUInt16LE(offset + 28);
      const extraLength = central.readUInt16LE(offset + 30);
      const commentLength = central.readUInt16LE(offset + 32);
      const externalAttributes = central.readUInt32LE(offset + 38);
      const localOffset = central.readUInt32LE(offset + 42);
      const name = central.subarray(offset + 46, offset + 46 + nameLength).toString('utf8');
      entries.push({ name, flags, method, crc, compressedSize, uncompressedSize, externalAttributes, localOffset, versionMadeBy });
      offset += 46 + nameLength + extraLength + commentLength;
    }
    const seen = new Set();
    for (const entry of entries) {
      const key = entry.name.replace(/\\\\/g, '/').toLowerCase();
      if (seen.has(key)) throw new RecoveryError('E_ARCHIVE_INVALID', `duplicate ZIP member name: ${entry.name}`);
      seen.add(key);
    }
    return { entries, size: stat.size };
  } finally {
    await handle.close();
  }
}

function checkZipEntry(entry, limits, total) {
  if ((entry.flags & 0x1) !== 0) throw new RecoveryError('E_ARCHIVE_ENCRYPTED', `encrypted ZIP member is not supported: ${entry.name}`);
  const unixMode = (entry.externalAttributes >>> 16) & 0o170000;
  if (unixMode === 0o120000) throw new RecoveryError('E_ARCHIVE_SYMLINK', `archive contains a symlink: ${entry.name}`);
  if (entry.uncompressedSize > limits.maxEntryBytes) throw new RecoveryError('E_LIMIT', `archive member exceeds the entry size limit: ${entry.name}`);
  if (total.bytes + entry.uncompressedSize > limits.maxExtractedBytes) throw new RecoveryError('E_LIMIT', 'archive exceeds the total extraction limit');
  if (entry.method !== 0 && entry.method !== 8) throw new RecoveryError('E_UNSUPPORTED', `unsupported ZIP compression method ${entry.method}: ${entry.name}`);
  if (entry.uncompressedSize > 1024 * 1024 && entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > 100) {
    throw new RecoveryError('E_ARCHIVE_BOMB', `suspicious compression ratio for ${entry.name}`);
  }
}

/** Extract a ZIP under a new/empty output directory. */
export async function extractZip(filePath, outputDir, limits) {
  const { entries } = await scanZip(filePath);
  if (entries.length > limits.maxEntries) throw new RecoveryError('E_LIMIT', 'archive has too many members');
  const handle = await fsp.open(filePath, 'r');
  const written = [];
  const total = { bytes: 0 };
  try {
    for (const entry of entries) {
      const segments = safeSegments(entry.name);
      if (entry.name.endsWith('/')) {
        await fsp.mkdir(safeJoin(outputDir, segments), { recursive: true, mode: 0o700 });
        continue;
      }
      checkZipEntry(entry, limits, total);
      const local = await readAt(handle, entry.localOffset, 30);
      if (local.length < 30 || local.readUInt32LE(0) !== 0x04034b50) throw new RecoveryError('E_ARCHIVE_INVALID', `invalid local header: ${entry.name}`);
      const nameLength = local.readUInt16LE(26);
      const extraLength = local.readUInt16LE(28);
      const localName = (await readAt(handle, entry.localOffset + 30, nameLength)).toString('utf8');       if (localName !== entry.name) throw new RecoveryError('E_ARCHIVE_INVALID', 'local/central name mismatch: ' + entry.name);
      const dataStart = entry.localOffset + 30 + nameLength + extraLength;
      if (dataStart + entry.compressedSize > (await handle.stat()).size) throw new RecoveryError('E_ARCHIVE_INVALID', `member data out of bounds: ${entry.name}`);
      const compressed = await readAt(handle, dataStart, entry.compressedSize);
      let content;
      try {
        content = entry.method === 0 ? compressed : zlib.inflateRawSync(compressed, { maxOutputLength: Math.min(limits.maxEntryBytes, entry.uncompressedSize) + 1 });
      } catch {
        throw new RecoveryError('E_ARCHIVE_INVALID', `cannot inflate member: ${entry.name}`);
      }
      if (content.length !== entry.uncompressedSize) throw new RecoveryError('E_ARCHIVE_INVALID', `size mismatch for ${entry.name}`);
      if (crc32(content) !== entry.crc) throw new RecoveryError('E_ARCHIVE_INTEGRITY', `CRC mismatch for ${entry.name}`);
      const target = safeJoin(outputDir, segments);
      await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await fsp.writeFile(target, content, { flag: 'wx', mode: 0o600 });
      total.bytes += content.length;
      written.push({ path: segments.join('/'), bytes: content.length, sha256: sha256(content) });
    }
  } catch (error) {
    await fsp.rm(outputDir, { recursive: true, force: true }).catch(() => {});
    throw error;
  } finally {
    await handle.close();
  }
  return { files: written, bytes: total.bytes, entries: entries.length };
}

/** Read one ZIP member into memory with CRC/size verification. */
export async function readZipEntry(filePath, entry, options = {}) {
  const maxOutputBytes = options.maxOutputBytes ?? 512 * 1024 * 1024;
  const handle = await TARGET_FS.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const local = await readAt(handle, entry.localOffset, 30);
    if (local.length < 30 || local.readUInt32LE(0) !== 0x04034b50) throw new RecoveryError('E_ARCHIVE_INVALID', `invalid local header: ${entry.name}`);
    const nameLength = local.readUInt16LE(26);
    const extraLength = local.readUInt16LE(28);
    const localName = (await readAt(handle, entry.localOffset + 30, nameLength)).toString('utf8');     if (localName !== entry.name) throw new RecoveryError('E_ARCHIVE_INVALID', 'local/central name mismatch: ' + entry.name);
    const dataStart = entry.localOffset + 30 + nameLength + extraLength;
    if (dataStart + entry.compressedSize > stat.size) throw new RecoveryError('E_ARCHIVE_INVALID', `member data out of bounds: ${entry.name}`);
    const compressed = await readAt(handle, dataStart, entry.compressedSize);
    let content;
    try {
      content = entry.method === 0 ? compressed : zlib.inflateRawSync(compressed, { maxOutputLength: Math.min(maxOutputBytes, entry.uncompressedSize) + 1 });
    } catch {
      throw new RecoveryError('E_ARCHIVE_INVALID', `cannot inflate member: ${entry.name}`);
    }
    if (content.length !== entry.uncompressedSize) throw new RecoveryError('E_ARCHIVE_INVALID', `size mismatch for ${entry.name}`);
    if (crc32(content) !== entry.crc) throw new RecoveryError('E_ARCHIVE_INTEGRITY', `CRC mismatch for ${entry.name}`);
    return content;
  } finally {
    await handle.close();
  }
}

const ASAR_HEADER_LIMIT = 64 * 1024 * 1024;

/** Parse an Electron ASAR header. Returns null when the file is not ASAR. */
export async function readAsarHeader(filePath) {
  const handle = await TARGET_FS.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    if (stat.size < 16) return null;
    const prefix = await readAt(handle, 0, 16);
    if (prefix.readUInt32LE(0) !== 4) return null;
    const headerSize = prefix.readUInt32LE(4);
    if (headerSize <= 0 || headerSize > ASAR_HEADER_LIMIT || 8 + headerSize > stat.size) return null;
    const headerText = (await readAt(handle, 8, headerSize)).toString('utf8').replace(/\0+$/, '');
    if (!headerText.trimStart().startsWith('{')) return null;
    let header;
    try { header = JSON.parse(headerText); } catch { return null; }
    if (header === null || typeof header !== 'object' || header.files === null || typeof header.files !== 'object') return null;
    return { header, dataStart: 8 + headerSize, size: stat.size };
  } finally {
    await handle.close();
  }
}

function flattenAsar(nodes, prefix = [], out = []) {
  for (const [name, node] of Object.entries(nodes)) {
    const segments = safeSegments(name);
    if (node?.files !== undefined) {
      flattenAsar(node.files, [...prefix, ...segments], out);
    } else if (node?.link !== undefined) {
      out.push({ path: [...prefix, ...segments].join('/'), link: String(node.link) });
    } else {
      const offset = Number(node?.offset);
      const size = Number(node?.size);
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0) {
        throw new RecoveryError('E_ARCHIVE_INVALID', `invalid ASAR entry: ${[...prefix, ...segments].join('/')}`);
      }
      out.push({ path: [...prefix, ...segments].join('/'), offset, size });
    }
  }
  return out;
}

/** Extract an ASAR into an output directory; unpacked entries are reported, not read. */
export async function extractAsar(filePath, outputDir, limits) {
  const parsed = await readAsarHeader(filePath);
  if (parsed === null) throw new RecoveryError('E_ARCHIVE_INVALID', 'file is not a supported ASAR archive');
  const entries = flattenAsar(parsed.header.files);
  if (entries.length > limits.maxEntries) throw new RecoveryError('E_LIMIT', 'ASAR has too many members');
  const handle = await TARGET_FS.open(filePath, 'r');
  const written = [];
  let bytes = 0;
  try {
    for (const entry of entries) {
      const segments = safeSegments(entry.path);
      if (entry.link !== undefined) {
        written.push({ path: entry.path, link: entry.link, skipped: 'link not materialized' });
        continue;
      }
      if (entry.size > limits.maxEntryBytes) throw new RecoveryError('E_LIMIT', `ASAR member exceeds the entry size limit: ${entry.path}`);
      if (bytes + entry.size > limits.maxExtractedBytes) throw new RecoveryError('E_LIMIT', 'ASAR exceeds the total extraction limit');
      const absolute = parsed.dataStart + entry.offset;
      if (absolute + entry.size > parsed.size) throw new RecoveryError('E_ARCHIVE_INVALID', `ASAR member out of bounds: ${entry.path}`);
      const content = await readAt(handle, absolute, entry.size);
      const target = safeJoin(outputDir, segments);
      await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      await fsp.writeFile(target, content, { flag: 'wx', mode: 0o600 });
      bytes += content.length;
      written.push({ path: entry.path, bytes: content.length, sha256: sha256(content) });
    }
  } catch (error) {
    await fsp.rm(outputDir, { recursive: true, force: true }).catch(() => {});
    throw error;
  } finally {
    await handle.close();
  }
  return { files: written, bytes, entries: entries.length, unpacked: entries.filter((entry) => entry.offset === undefined).length };
}

/** Extract a tar buffer into an output directory. */
export async function extractTarBuffer(buffer, outputDir, limits) {
  let offset = 0;
  let longName = null;
  const written = [];
  let total = 0;
  let count = 0;
  try {
    while (offset + 512 <= buffer.length) {
      const header = buffer.subarray(offset, offset + 512);
      if (header.every((byte) => byte === 0)) break;
      const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
      const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
      const name = longName ?? (prefix.length > 0 ? `${prefix}/${rawName}` : rawName);
      longName = null;
      const sizeText = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
      const size = sizeText === '' ? 0 : parseInt(sizeText, 8);
      if (!Number.isSafeInteger(size) || size < 0) throw new RecoveryError('E_ARCHIVE_INVALID', 'invalid tar member size');
      const type = String.fromCharCode(header[156] || 0x30);
      offset += 512;
      if (type === 'L') {
        longName = buffer.subarray(offset, offset + size).toString('utf8').replace(/\0.*$/, '');
        offset += Math.ceil(size / 512) * 512;
        continue;
      }
      if (type === '0' || type === '\0') {
        count += 1;
        if (count > limits.maxEntries) throw new RecoveryError('E_LIMIT', 'archive has too many members');
        if (size > limits.maxEntryBytes || total + size > limits.maxExtractedBytes) throw new RecoveryError('E_LIMIT', 'archive exceeds the extraction limit');
        const content = buffer.subarray(offset, offset + size);
        if (content.length !== size) throw new RecoveryError('E_ARCHIVE_INVALID', 'tar member is truncated');
        const target = safeJoin(outputDir, safeSegments(name));
        await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        await fsp.writeFile(target, content, { flag: 'wx', mode: 0o600 });
        total += size;
        written.push({ path: name, bytes: size, sha256: sha256(content) });
      } else if (type === '5') {
        await fsp.mkdir(safeJoin(outputDir, safeSegments(name)), { recursive: true, mode: 0o700 });
      }
      offset += Math.ceil(size / 512) * 512;
    }
  } catch (error) {
    await fsp.rm(outputDir, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  return { files: written, bytes: total, entries: count };
}

/** Extract a gzip file; tar contents are expanded, other payloads become one file. */
export async function extractGzip(filePath, outputDir, limits) {
  const compressed = await fsp.readFile(filePath);
  let payload;
  try {
    payload = zlib.gunzipSync(compressed, { maxOutputLength: limits.maxExtractedBytes });
  } catch (error) {
    throw new RecoveryError('E_ARCHIVE_INVALID', `cannot decompress gzip: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
  if (payload.length > 512 && payload.subarray(257, 262).toString('latin1') === 'ustar') {
    return extractTarBuffer(payload, outputDir, limits);
  }
  const base = path.basename(filePath).replace(/\.gz$/i, '') || 'payload.bin';
  const target = safeJoin(outputDir, safeSegments(base));
  await fsp.writeFile(target, payload, { flag: 'wx', mode: 0o600 });
  return { files: [{ path: base, bytes: payload.length, sha256: sha256(payload) }], bytes: payload.length, entries: 1 };
}

/** Extract a CPIO newc/crc archive buffer (common inside firmware). */
export async function extractCpioBuffer(buffer, outputDir, limits) {
  let offset = 0;
  let count = 0;
  let total = 0;
  const written = [];
  const align4 = (value) => (value + 3) & ~3;
  try {
    while (offset + 110 <= buffer.length) {
      const magic = buffer.toString('latin1', offset, offset + 6);
      if (magic !== '070701' && magic !== '070702') {
        if (count === 0) throw new RecoveryError('E_ARCHIVE_INVALID', 'not a CPIO newc archive');
        break;
      }
      const field = (index) => Number.parseInt(buffer.toString('latin1', offset + 6 + index * 8, offset + 6 + (index + 1) * 8), 16);
      const mode = field(1);
      const fileSize = field(6);
      const nameSize = field(11);
      if (!Number.isSafeInteger(fileSize) || fileSize < 0 || !Number.isSafeInteger(nameSize) || nameSize <= 0) {
        throw new RecoveryError('E_ARCHIVE_INVALID', 'invalid CPIO header');
      }
      const nameStart = offset + 110;
      const name = buffer.toString('utf8', nameStart, nameStart + nameSize - 1);
      const dataStart = align4(nameStart + nameSize);
      if (name === 'TRAILER!!!') break;
      count += 1;
      if (count > limits.maxEntries) throw new RecoveryError('E_LIMIT', 'CPIO has too many members');
      const type = mode & 0o170000;
      if (type === 0o120000) throw new RecoveryError('E_ARCHIVE_SYMLINK', `CPIO contains a symlink: ${name}`);
      if (type === 0o040000) {
        await fsp.mkdir(safeJoin(outputDir, safeSegments(name)), { recursive: true, mode: 0o700 });
      } else if (type === 0o100000 || type === 0) {
        if (fileSize > limits.maxEntryBytes || total + fileSize > limits.maxExtractedBytes) throw new RecoveryError('E_LIMIT', 'CPIO exceeds the extraction limit');
        if (dataStart + fileSize > buffer.length) throw new RecoveryError('E_ARCHIVE_INVALID', `CPIO member is truncated: ${name}`);
        const content = buffer.subarray(dataStart, dataStart + fileSize);
        const target = safeJoin(outputDir, safeSegments(name));
        await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        await fsp.writeFile(target, content, { flag: 'wx', mode: 0o600 });
        total += content.length;
        written.push({ path: name, bytes: content.length, sha256: sha256(content) });
      }
      offset = align4(dataStart + fileSize);
    }
  } catch (error) {
    await fsp.rm(outputDir, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  return { files: written, bytes: total, entries: count };
}

/** Extract any supported container by kind. */
export async function extractByKind(filePath, kind, outputDir, limits) {
  if (kind === 'apk' || kind === 'jar' || kind === 'zip') return extractZip(filePath, outputDir, limits);
  if (kind === 'asar') return extractAsar(filePath, outputDir, limits);
  if (kind === 'gzip') return extractGzip(filePath, outputDir, limits);
  if (kind === 'tar') {
    const buffer = await fsp.readFile(filePath);
    return extractTarBuffer(buffer, outputDir, limits);
  }
  throw new RecoveryError('E_UNSUPPORTED', `built-in extraction does not support ${kind}; use an external trusted toolchain`);
}
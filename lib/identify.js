/** Target identification: hashes, container magic, architecture, entropy and family. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { TARGET_FS, readAsarHeader, scanZip } from './archive.js';
import { sha256 } from './util.js';

const SAMPLE = 256 * 1024;
const FIRMWARE_MAGIC = [
  { magic: Buffer.from('hsqs', 'latin1'), id: 'squashfs', label: 'SquashFS filesystem' },
  { magic: Buffer.from('UBI#', 'latin1'), id: 'ubi', label: 'UBI image' },
  { magic: Buffer.from('HDR0', 'latin1'), id: 'trx', label: 'TRX firmware' },
  { magic: Buffer.from([0x27, 0x05, 0x19, 0x56]), id: 'uimage', label: 'U-Boot uImage' },
  { magic: Buffer.from([0x45, 0x3d, 0xcd, 0x28]), id: 'cramfs', label: 'CramFS' },
  { magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]), id: 'elf', label: 'ELF image' },
];
const ARCH_ELF = { 3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'arm64', 8: 'mips', 243: 'riscv' };
const ARCH_PE = { 0x14c: 'x86', 0x8664: 'x86_64', 0xaa64: 'arm64', 0x1c0: 'arm' };

export function shannonEntropy(buffer) {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return Number(entropy.toFixed(3));
}

export function stringStats(buffer) {
  let asciiRuns = 0;
  let asciiBytes = 0;
  let current = 0;
  let utf16Runs = 0;
  for (let i = 0; i < buffer.length; i += 1) {
    const byte = buffer[i];
    if (byte >= 0x20 && byte <= 0x7e) {
      current += 1;
      if (current === 4) asciiRuns += 1;
      if (current >= 4) asciiBytes += 1;
    } else {
      if (current >= 4) asciiBytes += 1;
      current = 0;
    }
    if (i + 1 < buffer.length && byte >= 0x20 && byte <= 0x7e && buffer[i + 1] === 0) utf16Runs += 1;
  }
  return { asciiRuns, asciiBytes, utf16Runs, sampledBytes: buffer.length };
}

function decodeText(pathName, buffer) {
  const ext = path.extname(pathName).toLowerCase();
  if (!['.js', '.mjs', '.cjs', '.json', '.map', '.xml', '.html', '.txt', '.md', '.ts', '.cs', '.java', '.kt', '.py', '.sh', '.ps1'].includes(ext)) return null;
  if (buffer.includes(0)) return null;
  return buffer.toString('utf8', 0, Math.min(buffer.length, 64 * 1024));
}

function peInfo(prefix) {
  if (prefix.length < 0x40 || prefix.readUInt16LE(0) !== 0x5a4d) return null;
  const peOffset = prefix.readUInt32LE(0x3c);
  if (peOffset + 24 > prefix.length || prefix.readUInt32LE(peOffset) !== 0x00004550) return null;
  const machine = prefix.readUInt16LE(peOffset + 4);
  const characteristics = prefix.readUInt16LE(peOffset + 22);
  const optionalOffset = peOffset + 24;
  let bits = null;
  let dotnet = false;
  let subsystem = null;
  if (optionalOffset + 2 <= prefix.length) {
    const magic = prefix.readUInt16LE(optionalOffset);
    bits = magic === 0x20b ? 64 : magic === 0x10b ? 32 : null;
    const dataDirectoryOffset = optionalOffset + (magic === 0x20b ? 112 : 96);
    if (dataDirectoryOffset + 15 * 8 <= prefix.length) {
      const clrRva = prefix.readUInt32LE(dataDirectoryOffset + 14 * 8);
      const clrSize = prefix.readUInt32LE(dataDirectoryOffset + 14 * 8 + 4);
      dotnet = clrRva !== 0 && clrSize !== 0;
    }
    if (optionalOffset + 70 <= prefix.length) subsystem = prefix.readUInt16LE(optionalOffset + 68);
  }
  return {
    format: 'PE',
    arch: ARCH_PE[machine] ?? `machine_0x${machine.toString(16)}`,
    bits,
    dotnet,
    subsystem,
    dll: (characteristics & 0x2000) !== 0,
  };
}

function elfInfo(prefix) {
  if (prefix.length < 20 || prefix.readUInt32BE(0) !== 0x7f454c46) return null;
  const bits = prefix[4] === 2 ? 64 : 32;
  const little = prefix[5] === 1;
  const read16 = (offset) => little ? prefix.readUInt16LE(offset) : prefix.readUInt16BE(offset);
  return { format: 'ELF', arch: ARCH_ELF[read16(18)] ?? `machine_${read16(18)}`, bits, type: read16(16) };
}

function machoInfo(prefix) {
  if (prefix.length < 8) return null;
  const magic = prefix.readUInt32LE(0);
  const table = {
    0xfeedface: { format: 'Mach-O 32', arch: 'x86/arm' },
    0xfeedfacf: { format: 'Mach-O 64', arch: 'x86_64/arm64' },
    0xcafebabe: { format: 'Mach-O universal', arch: 'universal' },
    0xbebafeca: { format: 'Mach-O universal', arch: 'universal' },
  };
  return table[magic] ?? null;
}

function firmwareKind(prefix) {
  for (const entry of FIRMWARE_MAGIC) {
    if (prefix.subarray(0, entry.magic.length).equals(entry.magic)) return entry;
  }
  return null;
}

function textKind(text) {
  if (text === null) return null;
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      if (parsed?.version === 3 && Array.isArray(parsed.sources) && typeof parsed.mappings === 'string') return 'sourcemap';
      return 'json';
    } catch {
      return 'json';
    }
  }
  if (trimmed.startsWith('<?xml')) return 'xml';
  if (/^<!doctype html/i.test(trimmed) || /^<html/i.test(trimmed)) return 'html';
  if (/^(import|export|const|let|var|function|class|\(function|!function|\/\*|#!)/.test(trimmed)) return 'javascript';
  return null;
}

async function hashFile(filePath) {
  const handle = await TARGET_FS.open(filePath, 'r');
  try {
    const hash = (await import('node:crypto')).createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let position = 0;
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

/** Identify one target without executing it. */
export async function identifyFile(filePath, options = {}) {
  const stat = await TARGET_FS.lstat(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new RecoveryError('E_PATH_UNSAFE', 'target must be a regular file, not a symlink or special file');
  const maxBytes = options.maxInputBytes ?? 4 * 1024 * 1024 * 1024;
  if (stat.size > maxBytes) throw new RecoveryError('E_LIMIT', 'target exceeds the configured input size limit');
  const handle = await TARGET_FS.open(filePath, 'r');
  let head;
  let tail = Buffer.alloc(0);
  try {
    head = Buffer.alloc(Math.min(stat.size, SAMPLE));
    await handle.read(head, 0, head.length, 0);
    if (stat.size > SAMPLE) {
      tail = Buffer.alloc(Math.min(stat.size - SAMPLE, 64 * 1024));
      await handle.read(tail, 0, tail.length, stat.size - tail.length);
    }
  } finally {
    await handle.close();
  }
  const sample = Buffer.concat([head, tail]);
  const digest = await hashFile(filePath);
  const text = decodeText(filePath, head);
  const asar = await readAsarHeader(filePath);
  let zip = null;
  if (head.length >= 4 && head.readUInt32LE(0) === 0x04034b50) {
    try { zip = await scanZip(filePath); } catch { zip = null; }
  }
  const pe = peInfo(head);
  const elf = elfInfo(head);
  const macho = machoInfo(head);
  const firmware = firmwareKind(head);
  const ext = path.extname(filePath).toLowerCase();
  const kindText = ext === '.map' && text !== null && text.trimStart().startsWith('{') ? 'sourcemap' : textKind(text);
  const isJsExt = /\.(js|mjs|cjs)$/i.test(filePath);
  let family = 'unknown';
  let kind = 'unknown';
  let metadata = {};
  if (zip !== null) {
    const names = zip.entries.map((entry) => entry.name.replace(/\\/g, '/'));
    const hasManifest = names.includes('AndroidManifest.xml');
    const hasDex = names.some((name) => /^classes\d*\.dex$/.test(name));
    const hasClass = names.some((name) => name.endsWith('.class'));
    if (hasManifest && hasDex) { family = 'apk'; kind = 'apk'; }
    else if (hasClass) { family = 'archive'; kind = 'jar'; }
    else { family = 'archive'; kind = 'zip'; }
    metadata = { zipEntries: zip.entries.length, zipSample: names.slice(0, 100), hasManifest, hasDex, hasClass };
  } else if (asar !== null) {
    family = 'electron'; kind = 'asar';
    metadata = { asarDataStart: asar.dataStart, asarRoots: Object.keys(asar.header.files).slice(0, 50) };
  } else if (pe !== null) {
    family = pe.dotnet ? 'dotnet' : 'native';
    kind = pe.dotnet ? 'dotnet-assembly' : 'pe';
    metadata = pe;
  } else if (elf !== null) {
    family = 'native'; kind = 'elf'; metadata = elf;
  } else if (macho !== null) {
    family = 'native'; kind = 'macho'; metadata = macho;
  } else if (head.length >= 4 && head.readUInt32BE(0) === 0x1f8b0800 || (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b)) {
    family = 'archive'; kind = 'gzip'; metadata = { compressed: true };
  } else if (head.length > 262 && head.subarray(257, 262).toString('latin1') === 'ustar') {
    family = 'archive'; kind = 'tar'; metadata = {};
  } else if (head.subarray(0, 4).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf]))) {
    family = 'archive'; kind = '7z'; metadata = {};
  } else if (head.subarray(0, 4).toString('latin1') === 'Rar!') {
    family = 'archive'; kind = 'rar'; metadata = {};
  } else if (firmware !== null) {
    family = 'firmware'; kind = firmware.id; metadata = { label: firmware.label };
  } else if (kindText === 'sourcemap') {
    family = 'electron'; kind = 'sourcemap'; metadata = { exactSourcePossible: true };
  } else if (kindText === 'javascript' || (kindText === null && isJsExt)) {
    family = 'electron'; kind = 'javascript'; metadata = {};
  } else if (kindText !== null) {
    family = 'text'; kind = kindText; metadata = {};
  }
  if (family === 'native' && kind !== 'unknown') family = 'native';
  const entropy = shannonEntropy(sample);
  const strings = stringStats(sample);
  return {
    path: filePath,
    name: path.basename(filePath),
    size: stat.size,
    sha256: digest,
    family,
    kind,
    magic: head.subarray(0, 16).toString('hex'),
    entropy,
    strings,
    metadata,
    evidence: {
      observed: ['size', 'sha256', 'magic bytes', 'entropy sample', 'container metadata'],
      inferred: [`family=${family}`, `kind=${kind}`],
      unknown: ['original source text', 'runtime behavior', 'authorship'],
    },
  };
}

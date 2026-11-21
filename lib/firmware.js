/** Firmware signature scanning and bounded carving (no target execution). */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { RecoveryError } from './errors.js';
import { extractCpioBuffer, extractTarBuffer, extractZip, scanZip } from './archive.js';

const MAX_SCAN_BYTES = 256 * 1024 * 1024;
const MAX_FINDINGS = 20;
const MAX_CARVE_BYTES = 128 * 1024 * 1024;

function makeCpio(files) {
  const chunks = [];
  const align4 = (value) => (value + 3) & ~3;
  const hex = (value) => value.toString(16).padStart(8, '0');
  let ino = 1;
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text, 'utf8');
    const nameBytes = Buffer.from(`${name}\0`, 'utf8');
    const header = Buffer.from(`070701${hex(ino)}${hex(0o100644)}${hex(0)}${hex(0)}${hex(1)}${hex(0)}${hex(data.length)}${hex(0)}${hex(0)}${hex(0)}${hex(0)}${hex(nameBytes.length)}${hex(0)}`, 'latin1');
    chunks.push(header, nameBytes);
    const pad = (4 - ((110 + nameBytes.length) % 4)) % 4;
    if (pad > 0) chunks.push(Buffer.alloc(pad));
    chunks.push(data);
    const dataPad = (4 - (data.length % 4)) % 4;
    if (dataPad > 0) chunks.push(Buffer.alloc(dataPad));
    ino += 1;
  }
  const trailerName = Buffer.from('TRAILER!!!\0', 'utf8');
  chunks.push(Buffer.from(`070701${hex(0)}${hex(0)}${hex(0)}${hex(0)}${hex(1)}${hex(0)}${hex(0)}${hex(0)}${hex(0)}${hex(0)}${hex(0)}${hex(trailerName.length)}${hex(0)}`, 'latin1'), trailerName);
  while (chunks.reduce((sum, entry) => sum + entry.length, 0) % 512 !== 0) chunks.push(Buffer.alloc(1));
  return Buffer.concat(chunks);
}

function indexOfAll(buffer, magicBuffer, limit) {
  const offsets = [];
  let offset = buffer.indexOf(magicBuffer);
  while (offset !== -1 && offsets.length < limit) {
    offsets.push(offset);
    offset = buffer.indexOf(magicBuffer, offset + 1);
  }
  return offsets;
}

/** Scan and carve common firmware payloads into outDir/firmware/<offset>-<type>/ . */
export async function extractFirmware(filePath, outDir, limits) {
  const stat = await fsp.stat(filePath);
  if (stat.size > MAX_SCAN_BYTES) {
    throw new RecoveryError('E_LIMIT', `firmware exceeds the ${MAX_SCAN_BYTES}-byte carving limit; use binwalk/unblob for large images`);
  }
  const buffer = await fsp.readFile(filePath);
  const findings = [];
  const extracted = [];
  let totalBytes = 0;
  const carveBudget = () => totalBytes < MAX_CARVE_BYTES;

  const carveDir = async (offset, type) => {
    const target = path.join(outDir, 'firmware', `${offset.toString(16).padStart(8, '0')}-${type}`);
    await fsp.mkdir(target, { recursive: true, mode: 0o700 });
    return target;
  };

  for (const offset of indexOfAll(buffer, Buffer.from([0x1f, 0x8b, 0x08]), MAX_FINDINGS)) {
    if (!carveBudget() || findings.length >= MAX_FINDINGS) break;
    try {
      const payload = zlib.gunzipSync(buffer.subarray(offset), { maxOutputLength: 64 * 1024 * 1024 });
      const target = await carveDir(offset, 'gzip');
      if (payload.length > 512 && payload.subarray(257, 262).toString('latin1') === 'ustar') {
        const result = await extractTarBuffer(payload, target, limits);
        extracted.push({ type: 'gzip+tar', offset, bytes: result.bytes, files: result.files.length, dir: target });
      } else {
        await fsp.writeFile(path.join(target, 'payload.bin'), payload, { flag: 'wx', mode: 0o600 });
        extracted.push({ type: 'gzip', offset, bytes: payload.length, files: 1, dir: target });
      }
      totalBytes += payload.length;
      findings.push({ type: 'gzip', offset, bytes: payload.length, label: 'gzip stream' });
    } catch { /* candidate is not a valid gzip stream */ }
  }

  for (const offset of indexOfAll(buffer, Buffer.from('PK\x03\x04', 'latin1'), MAX_FINDINGS)) {
    if (!carveBudget() || findings.length >= MAX_FINDINGS) break;
    const eocd = buffer.indexOf(Buffer.from('PK\x05\x06', 'latin1'), offset + 4);
    if (eocd < 0 || eocd + 22 > buffer.length) continue;
    const commentLength = buffer.readUInt16LE(eocd + 20);
    const end = Math.min(buffer.length, eocd + 22 + commentLength);
    const slice = buffer.subarray(offset, end);
    const temp = path.join(outDir, 'firmware', `.carve-${offset}.zip`);
    await fsp.writeFile(temp, slice, { flag: 'wx', mode: 0o600 });
    try {
      const target = await carveDir(offset, 'zip');
      const result = await extractZip(temp, target, limits);
      extracted.push({ type: 'zip', offset, bytes: result.bytes, files: result.files.length, dir: target });
      totalBytes += result.bytes;
      findings.push({ type: 'zip', offset, bytes: result.bytes, label: 'ZIP/APK container' });
    } catch { /* candidate is not a valid ZIP */ }
    await fsp.rm(temp, { force: true }).catch(() => {});
  }

  for (const magic of ['070701', '070702']) {
    for (const offset of indexOfAll(buffer, Buffer.from(magic, 'latin1'), MAX_FINDINGS)) {
      if (!carveBudget() || findings.length >= MAX_FINDINGS) break;
      try {
        const target = await carveDir(offset, `cpio-${magic}`);
        const result = await extractCpioBuffer(buffer.subarray(offset), target, limits);
        extracted.push({ type: 'cpio', offset, bytes: result.bytes, files: result.files.length, dir: target });
        totalBytes += result.bytes;
        findings.push({ type: 'cpio', offset, bytes: result.bytes, label: `CPIO ${magic}` });
      } catch { /* candidate is not a valid CPIO */ }
    }
  }

  for (const offset of indexOfAll(buffer, Buffer.from('ustar', 'latin1'), MAX_FINDINGS)) {
    if (!carveBudget() || findings.length >= MAX_FINDINGS) break;
    const tarStart = offset - 257;
    if (tarStart < 0) continue;
    try {
      const target = await carveDir(tarStart, 'tar');
      const result = await extractTarBuffer(buffer.subarray(tarStart), target, limits);
      extracted.push({ type: 'tar', offset: tarStart, bytes: result.bytes, files: result.files.length, dir: target });
      totalBytes += result.bytes;
      findings.push({ type: 'tar', offset: tarStart, bytes: result.bytes, label: 'tar archive' });
    } catch { /* not a valid tar */ }
  }

  const signatures = [];
  const known = [
    ['squashfs', 'hsqs'], ['UBI', 'UBI#'], ['uImage', '\x27\x05\x19\x56'], ['TRX', 'HDR0'],
    ['gzip', '\x1f\x8b'], ['cpio', '070701'], ['zip', 'PK\x03\x04'], ['tar', 'ustar'],
  ];
  for (const [type, magic] of known) {
    const offset = buffer.indexOf(Buffer.from(magic, 'latin1'));
    if (offset >= 0) signatures.push({ type, offset });
  }
  findings.sort((a, b) => a.offset - b.offset);
  return { findings, extracted, signatures, scannedBytes: buffer.length, totalExtractedBytes: totalBytes, limited: stat.size > MAX_SCAN_BYTES };
}

export { makeCpio };

/** Deterministic fixtures for tests and self-test. No binary blobs in git. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { crc32 } from './archive.js';
import { sha256 } from './util.js';

/** Build a ZIP using stored (method 0) entries. */
export function makeStoredZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data), 'utf8');
    const name = Buffer.from(entry.name, 'utf8');
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(entry.flags ?? 0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(entry.flags ?? 0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(entry.unixMode === undefined ? 0 : (entry.unixMode << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

/** Build a minimal ASAR archive from a flat name map. */
export function makeAsar(files) {
  const tree = { files: {} };
  const payloads = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    const segments = name.split('/');
    let node = tree;
    for (let index = 0; index < segments.length - 1; index += 1) {
      const segment = segments[index];
      if (node.files[segment]?.files === undefined) node.files[segment] = { files: {} };
      node = node.files[segment];
    }
    node.files[segments[segments.length - 1]] = { size: data.length, offset };
    payloads.push(data);
    offset += data.length;
  }
  const header = Buffer.from(JSON.stringify(tree), 'utf8');
  const sizePrefix = Buffer.alloc(8);
  sizePrefix.writeUInt32LE(4, 0);
  sizePrefix.writeUInt32LE(header.length, 4);
  return Buffer.concat([sizePrefix, header, ...payloads]);
}

/** Build a v3 source map with optional sourcesContent. */
export function makeSourceMap(sources, contents, extra = {}) {
  return JSON.stringify({
    version: 3,
    file: extra.file ?? 'bundle.js',
    sourceRoot: extra.sourceRoot ?? '',
    sources,
    ...(contents === undefined ? {} : { sourcesContent: contents }),
    names: [],
    mappings: 'AAAA',
  });
}

/** Write an object of relative paths → content below dir. */
export async function writeTree(dir, files) {
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(dir, ...relative.split('/'));
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.writeFile(target, content);
  }
}

export function fixtureHash(buffer) {
  return sha256(buffer);
}

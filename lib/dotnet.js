/** Minimal .NET / CLR metadata reader: assembly identity, type/method names, user strings. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { sha256 } from './util.js';

const CODED = {
  TypeDefOrRef: { tables: [2, 1, 27], bits: 2 },
  HasConstant: { tables: [4, 8, 23], bits: 2 },
  HasCustomAttribute: { tables: [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 43], bits: 5 },
  HasFieldMarshal: { tables: [4, 8], bits: 1 },
  HasDeclSecurity: { tables: [2, 6, 32], bits: 2 },
  MemberRefParent: { tables: [2, 1, 26, 6, 27], bits: 3 },
  HasSemantics: { tables: [20, 23], bits: 1 },
  MethodDefOrRef: { tables: [6, 10], bits: 1 },
  MemberForwarded: { tables: [4, 6], bits: 1 },
  Implementation: { tables: [38, 35, 39], bits: 2 },
  CustomAttributeType: { tables: [6, 10], bits: 3 },
  ResolutionScope: { tables: [0, 26, 35, 1], bits: 2 },
  TypeOrMethodDef: { tables: [2, 6], bits: 1 },
};

function align4(value) { return (value + 3) & ~3; }

function readCompressedUInt(buffer, offset) {
  const first = buffer[offset];
  if (first === undefined) return null;
  if ((first & 0x80) === 0) return { value: first, length: 1 };
  if ((first & 0xc0) === 0x80) return { value: ((first & 0x3f) << 8) | buffer[offset + 1], length: 2 };
  if ((first & 0xe0) === 0xc0) return { value: ((first & 0x1f) << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3], length: 4 };
  return null;
}

function peLayout(buffer) {
  if (buffer.length < 0x40 || buffer.readUInt16LE(0) !== 0x5a4d) return null;
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length || buffer.readUInt32LE(peOffset) !== 0x00004550) return null;
  const sectionCount = buffer.readUInt16LE(peOffset + 6);
  const optionalSize = buffer.readUInt16LE(peOffset + 20);
  const optionalOffset = peOffset + 24;
  const magic = buffer.readUInt16LE(optionalOffset);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const pe32Plus = magic === 0x20b;
  const dataDirectories = optionalOffset + (pe32Plus ? 112 : 96);
  const clrRva = dataDirectories + 14 * 8 + 8 <= buffer.length ? buffer.readUInt32LE(dataDirectories + 14 * 8) : 0;
  const clrSize = dataDirectories + 14 * 8 + 8 <= buffer.length ? buffer.readUInt32LE(dataDirectories + 14 * 8 + 4) : 0;
  const sizeOfHeaders = buffer.readUInt32LE(optionalOffset + 60);
  const sectionTable = optionalOffset + optionalSize;
  const sections = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const base = sectionTable + index * 40;
    if (base + 40 > buffer.length) break;
    const virtualSize = buffer.readUInt32LE(base + 8);
    const virtualAddress = buffer.readUInt32LE(base + 12);
    const rawSize = buffer.readUInt32LE(base + 16);
    const rawPointer = buffer.readUInt32LE(base + 20);
    sections.push({ virtualSize, virtualAddress, rawSize, rawPointer, name: buffer.subarray(base, base + 8).toString('latin1').replace(/\0.*$/, '') });
  }
  const rvaToOffset = (rva) => {
    if (rva < sizeOfHeaders) return rva;
    for (const section of sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
        return section.rawPointer + (rva - section.virtualAddress);
      }
    }
    return -1;
  };
  return { peOffset, pe32Plus, clrRva, clrSize, sections, rvaToOffset };
}

function readDotnetMetadata(buffer) {
  const pe = peLayout(buffer);
  if (pe === null) throw new RecoveryError('E_NOT_MANAGED', 'not a PE image');
  if (pe.clrRva === 0 || pe.clrSize === 0) throw new RecoveryError('E_NOT_MANAGED', 'PE image has no CLR metadata directory');
  const clrOffset = pe.rvaToOffset(pe.clrRva);
  if (clrOffset < 0 || clrOffset + 16 > buffer.length) throw new RecoveryError('E_METADATA_INVALID', 'CLR header is out of bounds');
  const metadataRva = buffer.readUInt32LE(clrOffset + 8);
  const metadataSize = buffer.readUInt32LE(clrOffset + 12);
  const metadataOffset = pe.rvaToOffset(metadataRva);
  if (metadataOffset < 0 || metadataOffset + metadataSize > buffer.length) throw new RecoveryError('E_METADATA_INVALID', 'metadata root is out of bounds');
  if (buffer.readUInt32LE(metadataOffset) !== 0x424a5342) throw new RecoveryError('E_METADATA_INVALID', 'metadata signature mismatch');
  const versionLength = buffer.readUInt32LE(metadataOffset + 12);
  const version = buffer.toString('utf8', metadataOffset + 16, metadataOffset + 16 + versionLength).replace(/\0.*$/, '');
  let cursor = align4(metadataOffset + 16 + versionLength);
  const streamCount = buffer.readUInt16LE(cursor + 2);
  cursor += 4;
  const streams = {};
  for (let index = 0; index < streamCount; index += 1) {
    const offset = buffer.readUInt32LE(cursor);
    const size = buffer.readUInt32LE(cursor + 4);
    const nameEnd = buffer.indexOf(0, cursor + 8);
    if (nameEnd < 0) throw new RecoveryError('E_METADATA_INVALID', 'stream name is not terminated');
    const name = buffer.toString('latin1', cursor + 8, nameEnd);
    streams[name] = { offset: metadataOffset + offset, size };
    cursor = align4(nameEnd + 1);
  }
  if (streams['#~'] === undefined || streams['#Strings'] === undefined) throw new RecoveryError('E_METADATA_INVALID', 'metadata streams #~ or #Strings are missing');
  return { pe, version, streams };
}

function tableSizes(rows, heapSizes, streams) {
  const str = (heapSizes & 0x01) !== 0 ? 4 : 2;
  const guid = (heapSizes & 0x02) !== 0 ? 4 : 2;
  const blob = (heapSizes & 0x04) !== 0 ? 4 : 2;
  const tbl = (index) => (rows[index] < 0x10000 ? 2 : 4);
  const coded = (name) => {
    const { tables, bits } = CODED[name];
    const max = tables.reduce((value, index) => Math.max(value, rows[index] ?? 0), 0);
    return max < (1 << (16 - bits)) ? 2 : 4;
  };
  const sizes = new Array(64).fill(0);
  sizes[0] = 2 + str + guid * 3;
  sizes[1] = coded('ResolutionScope') + str * 2;
  sizes[2] = 4 + str * 2 + coded('TypeDefOrRef') + tbl(4) + tbl(6);
  sizes[3] = tbl(4);
  sizes[4] = 2 + str + blob;
  sizes[5] = tbl(6);
  sizes[6] = 4 + 2 + 2 + str + blob + tbl(8);
  sizes[7] = tbl(8);
  sizes[8] = 2 + 2 + str;
  sizes[9] = tbl(2) + coded('TypeDefOrRef');
  sizes[10] = coded('MemberRefParent') + str + blob;
  sizes[11] = 2 + coded('HasConstant') + blob;
  sizes[12] = coded('HasCustomAttribute') + coded('CustomAttributeType') + blob;
  sizes[13] = coded('HasFieldMarshal') + blob;
  sizes[14] = 2 + coded('HasDeclSecurity') + blob;
  sizes[15] = 2 + 4 + tbl(2);
  sizes[16] = 4 + tbl(4);
  sizes[17] = blob;
  sizes[18] = tbl(2) + tbl(20);
  sizes[19] = tbl(20);
  sizes[20] = 2 + str + coded('TypeDefOrRef');
  sizes[21] = tbl(2) + tbl(23);
  sizes[22] = tbl(23);
  sizes[23] = 2 + str + blob;
  sizes[24] = 2 + tbl(6) + coded('HasSemantics');
  sizes[25] = tbl(2) + coded('MethodDefOrRef') * 2;
  sizes[26] = str;
  sizes[27] = blob;
  sizes[28] = 2 + coded('MemberForwarded') + str + tbl(26);
  sizes[29] = 4 + tbl(4);
  sizes[30] = 4 + 4;
  sizes[31] = 4;
  sizes[32] = 4 + 8 + 4 + blob + str * 2;
  sizes[33] = 4;
  sizes[34] = 4 * 3;
  sizes[35] = 8 + 4 + blob + str * 2 + blob;
  sizes[36] = 4 + tbl(35);
  sizes[37] = 4 * 3 + tbl(35);
  sizes[38] = 4 + str + blob;
  sizes[39] = 4 + 4 + str * 2 + coded('Implementation');
  sizes[40] = 4 + 4 + str + coded('Implementation');
  sizes[41] = tbl(2) * 2;
  sizes[42] = 2 + 2 + coded('TypeOrMethodDef') + str;
  sizes[43] = coded('MethodDefOrRef') + blob;
  sizes[44] = tbl(42) + coded('TypeDefOrRef');
  void streams;
  return sizes;
}

function parseTables(buffer, metadata) {
  const heap = metadata.streams['#~'];
  if (heap.offset + 24 > buffer.length) throw new RecoveryError('E_METADATA_INVALID', '#~ stream is truncated');
  const heapSizes = buffer[heap.offset + 6];
  const valid = buffer.readBigUInt64LE(heap.offset + 8);
  let cursor = heap.offset + 24;
  const rows = new Array(64).fill(0);
  for (let index = 0; index < 64; index += 1) {
    if ((valid & (1n << BigInt(index))) !== 0n) {
      rows[index] = buffer.readUInt32LE(cursor);
      cursor += 4;
    }
  }
  const sizes = tableSizes(rows, heapSizes, metadata.streams);
  const offsets = new Array(64).fill(0);
  let offset = cursor;
  for (let index = 0; index < 64; index += 1) {
    offsets[index] = offset;
    offset += sizes[index] * rows[index];
  }
  const str = (heapSizes & 0x01) !== 0 ? 4 : 2;
  const guid = (heapSizes & 0x02) !== 0 ? 4 : 2;
  const blobSize = (heapSizes & 0x04) !== 0 ? 4 : 2;
  const stringsHeap = metadata.streams['#Strings'];
  const getString = (index) => {
    const start = stringsHeap.offset + index;
    const end = buffer.indexOf(0, start);
    return buffer.toString('utf8', start, end < 0 ? start : end);
  };
  const getGuid = (index) => {
    const heap = metadata.streams['#GUID'];
    if (heap === undefined || index === 0) return null;
    const start = heap.offset + (index - 1) * 16;
    if (start + 16 > buffer.length) return null;
    const bytes = buffer.subarray(start, start + 16);
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  };
  const tidx = (table) => (rows[table] < 0x10000 ? 2 : 4);
  const codedSize = (name) => {
    const { tables, bits } = CODED[name];
    const max = tables.reduce((value, index) => Math.max(value, rows[index] ?? 0), 0);
    return max < (1 << (16 - bits)) ? 2 : 4;
  };
  const readAt = (table, index) => offsets[table] + sizes[table] * (index - 1);
  const rowField = (table, index, fieldOffset, width) => {
    const start = readAt(table, index) + fieldOffset;
    if (width === 2) return buffer.readUInt16LE(start);
    return buffer.readUInt32LE(start);
  };
  const parseTypeRefs = [];
  for (let index = 1; index <= rows[1]; index += 1) {
    const start = readAt(1, index);
    let position = start;
    position += codedSize('ResolutionScope');
    const nameIndex = str === 4 ? buffer.readUInt32LE(position) : buffer.readUInt16LE(position);
    position += str;
    const namespaceIndex = str === 4 ? buffer.readUInt32LE(position) : buffer.readUInt16LE(position);
    parseTypeRefs.push({ name: getString(nameIndex), namespace: getString(namespaceIndex) });
  }
  const methods = [];
  for (let index = 1; index <= rows[6]; index += 1) {
    const start = readAt(6, index);
    let position = start + 8;
    const nameIndex = str === 4 ? buffer.readUInt32LE(position) : buffer.readUInt16LE(position);
    position += str;
    position += blobSize;
    const paramList = rowField(6, index, 8 + str + blobSize, tidx(8));
    methods.push({ name: getString(nameIndex), paramList });
  }
  const types = [];
  for (let index = 1; index <= rows[2]; index += 1) {
    const start = readAt(2, index);
    let position = start + 4;
    const nameIndex = str === 4 ? buffer.readUInt32LE(position) : buffer.readUInt16LE(position);
    position += str;
    const namespaceIndex = str === 4 ? buffer.readUInt32LE(position) : buffer.readUInt16LE(position);
    position += str;
    position += codedSize('TypeDefOrRef');
    position += tidx(4) + tidx(6);
    const methodListOffset = 4 + str * 2 + codedSize('TypeDefOrRef') + tidx(4);
    const methodList = rowField(2, index, methodListOffset, tidx(6)) || 1;
    const nextMethodList = index < rows[2] ? (rowField(2, index + 1, methodListOffset, tidx(6)) || (rows[6] + 1)) : rows[6] + 1;
    const typeMethods = methods.slice(methodList - 1, Math.max(methodList - 1, nextMethodList - 1)).map((method) => method.name);
    types.push({ namespace: getString(namespaceIndex), name: getString(nameIndex), methods: typeMethods });
  }
  let assembly = null;
  if (rows[32] > 0) {
    const start = readAt(32, 1);
    const nameIndex = str === 4 ? buffer.readUInt32LE(start + 16 + blobSize) : buffer.readUInt16LE(start + 16 + blobSize);
    assembly = {
      name: getString(nameIndex),
      version: `${buffer.readUInt16LE(start + 4)}.${buffer.readUInt16LE(start + 6)}.${buffer.readUInt16LE(start + 8)}.${buffer.readUInt16LE(start + 10)}`,
    };
  }
  const assemblyRefs = [];
  for (let index = 1; index <= rows[35]; index += 1) {
    const start = readAt(35, index);
    const nameIndex = str === 4 ? buffer.readUInt32LE(start + 12 + blobSize) : buffer.readUInt16LE(start + 12 + blobSize);
    assemblyRefs.push(getString(nameIndex));
  }
  let moduleName = null;
  if (rows[0] > 0) {
    const start = readAt(0, 1);
    const nameIndex = str === 4 ? buffer.readUInt32LE(start + 2) : buffer.readUInt16LE(start + 2);
    moduleName = getString(nameIndex);
  }
  const userStrings = [];
  const us = metadata.streams['#US'];
  if (us !== undefined) {
    let position = us.offset + 1;
    const end = Math.min(us.offset + us.size, buffer.length);
    while (position < end && userStrings.length < 500) {
      const header = readCompressedUInt(buffer, position);
      if (header === null || header.value === 0) break;
      position += header.length;
      const length = header.value;
      if (length > 1 && position + length <= end) {
        const text = buffer.toString('utf16le', position, position + length - 1);
        if (/[\x20-\x7e]{3,}/.test(text)) userStrings.push(text.replace(/\0/g, ''));
      }
      position += length;
    }
  }
  return {
    rows: Object.fromEntries([0, 1, 2, 6, 32, 35].map((index) => [index, rows[index]])),
    moduleName, assembly, assemblyRefs, types, typeRefs: parseTypeRefs, methods: methods.map((method) => method.name), userStrings,
    heapSizes, streamNames: Object.keys(metadata.streams),
  };
}

/** Parse a managed PE file and write metadata.json/types.txt/strings.txt under outputDir. */
export async function recoverDotnetMetadata(buffer, outputDir) {
  const metadata = readDotnetMetadata(buffer);
  const parsed = parseTables(buffer, metadata);
  const result = {
    format: 'dotnet-cli',
    metadataVersion: metadata.version,
    module: parsed.moduleName,
    assembly: parsed.assembly,
    assemblyRefs: parsed.assemblyRefs,
    counts: { types: parsed.types.length, methods: parsed.methods.length, typeRefs: parsed.typeRefs.length, strings: parsed.userStrings.length },
    types: parsed.types.slice(0, 5000).map((type) => ({
      ...type,
      methods: type.methods.slice(0, 500),
    })),
    typeRefs: parsed.typeRefs.slice(0, 2000),
    strings: parsed.userStrings.slice(0, 500),
    sourceLevel: 'S3',
    note: 'CLI metadata and names are not C# source; install ilspycmd or use REA MCP managed tools for S1.',
  };
  const typeLines = [
    `// assembly: ${parsed.assembly?.name ?? '?'} ${parsed.assembly?.version ?? ''}`,
    `// module: ${parsed.moduleName ?? '?'}  metadata: ${metadata.version}`,
    `// refs: ${parsed.assemblyRefs.join(', ')}`,
    '',
    ...result.types.map((type) => `${type.namespace ? `${type.namespace}.` : ''}${type.name}${type.methods.length > 0 ? ` : ${type.methods.join(', ')}` : ''}`),
  ];
  await fsp.writeFile(path.join(outputDir, 'dotnet-types.txt'), typeLines.join('\n'), { flag: 'wx', mode: 0o600 });
  await fsp.writeFile(path.join(outputDir, 'dotnet-strings.txt'), result.strings.join('\n'), { flag: 'wx', mode: 0o600 });
  const text = `${JSON.stringify(result, null, 2)}\n`;
  await fsp.writeFile(path.join(outputDir, 'dotnet-metadata.json'), text, { flag: 'wx', mode: 0o600 });
  return { ...result, files: [
    { path: 'dotnet-metadata.json', bytes: Buffer.byteLength(text), sha256: sha256(text).toString('hex') },
    { path: 'dotnet-types.txt', sha256: sha256(typeLines.join('\n')).toString('hex') },
    { path: 'dotnet-strings.txt', sha256: sha256(result.strings.join('\n')).toString('hex') },
  ] };
}

export { readDotnetMetadata, parseTables, peLayout };

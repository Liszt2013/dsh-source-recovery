/** Core recovery tests: identification, safe extraction, source maps, authorization, reports. */
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import * as api from '../lib/api.js';
import { RecoveryError } from '../lib/errors.js';
import { makeAsar, makeSourceMap, makeStoredZip } from '../lib/fixtures.js';
import { readZipEntry, scanZip } from '../lib/archive.js';
import { crc32 } from '../lib/archive.js';

function makeDeflateZip(name, payload, declaredSize) {
  const compressed = zlib.deflateRawSync(payload);
  const nameBytes = Buffer.from(name, 'utf8');
  const crc = crc32(payload);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6);
  local.writeUInt16LE(8, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(compressed.length, 18);
  local.writeUInt32LE(declaredSize, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(0x0314, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x0800, 8);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(compressed.length, 20);
  central.writeUInt32LE(declaredSize, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length + nameBytes.length, 12);
  eocd.writeUInt32LE(local.length + nameBytes.length + compressed.length, 16);
  return Buffer.concat([local, nameBytes, compressed, central, nameBytes, eocd]);
}
import { identifyFile } from '../lib/identify.js';

async function tempDir(prefix = 'dspc-test-') {
  return fsp.mkdtemp(path.join(tmpdir(), prefix));
}

function makePe({ dotnet = false } = {}) {
  const buffer = Buffer.alloc(0x400);
  buffer.writeUInt16LE(0x5a4d, 0);
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.writeUInt32LE(0x00004550, 0x80);
  buffer.writeUInt16LE(0x8664, 0x84);
  buffer.writeUInt16LE(0, 0x86);
  buffer.writeUInt16LE(0, 0x94);
  buffer.writeUInt16LE(0x20b, 0x98);
  buffer.writeUInt16LE(0x22, 0x96);
  const dataDirectory = 0x98 + 112;
  if (dotnet) {
    buffer.writeUInt32LE(0x2000, dataDirectory + 14 * 8);
    buffer.writeUInt32LE(0x48, dataDirectory + 14 * 8 + 4);
  }
  return buffer;
}

export default function register(test) {
  test('identify distinguishes JS, ZIP, APK-like ZIP, ASAR, PE and .NET without executing', async () => {
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'app.js'), 'const a = 1;\n');
      await fsp.writeFile(path.join(dir, 'plain.zip'), makeStoredZip([{ name: 'a.txt', data: 'a' }]));
      await fsp.writeFile(path.join(dir, 'app.apk'), makeStoredZip([
        { name: 'AndroidManifest.xml', data: '<manifest/>' },
        { name: 'classes.dex', data: 'dex\n035\0' },
      ]));
      await fsp.writeFile(path.join(dir, 'app.asar'), makeAsar({ 'main.js': 'x' }));
      await fsp.writeFile(path.join(dir, 'native.exe'), makePe({ dotnet: false }));
      await fsp.writeFile(path.join(dir, 'managed.exe'), makePe({ dotnet: true }));
      await fsp.writeFile(path.join(dir, 'firmware.bin'), Buffer.concat([Buffer.from('hsqs'), Buffer.alloc(64, 0)]));
      const js = await identifyFile(path.join(dir, 'app.js'));
      assert.equal(js.family, 'electron');
      assert.equal(js.kind, 'javascript');
      const zip = await identifyFile(path.join(dir, 'plain.zip'));
      assert.equal(zip.family, 'archive');
      assert.equal(zip.kind, 'zip');
      const apk = await identifyFile(path.join(dir, 'app.apk'));
      assert.equal(apk.family, 'apk');
      assert.equal(apk.kind, 'apk');
      const asar = await identifyFile(path.join(dir, 'app.asar'));
      assert.equal(asar.family, 'electron');
      assert.equal(asar.kind, 'asar');
      const native = await identifyFile(path.join(dir, 'native.exe'));
      assert.equal(native.family, 'native');
      assert.equal(native.kind, 'pe');
      const managed = await identifyFile(path.join(dir, 'managed.exe'));
      assert.equal(managed.family, 'dotnet');
      const firmware = await identifyFile(path.join(dir, 'firmware.bin'));
      assert.equal(firmware.family, 'firmware');
      assert.equal(firmware.kind, 'squashfs');
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('safe ZIP extraction round-trips and rejects traversal, symlink and encryption', async () => {
    const dir = await tempDir();
    try {
      const zipPath = path.join(dir, 'ok.zip');
      await fsp.writeFile(zipPath, makeStoredZip([
        { name: 'src/app.js', data: 'console.log(1)\n' },
        { name: 'nested/readme.txt', data: 'hello' },
      ]));
      const okOut = path.join(dir, 'ok');
      await assert.rejects(() => api.extract({ input: zipPath, outputDir: okOut, authorized: false, roots: [dir] }), (error) => error instanceof RecoveryError && error.code === 'E_AUTHZ_REQUIRED');
      const result = await api.extract({ input: zipPath, outputDir: okOut, authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.files.length, 2);
      assert.equal(await fsp.readFile(path.join(okOut, 'src', 'app.js'), 'utf8'), 'console.log(1)\n');

      const traversal = path.join(dir, 'traversal.zip');
      await fsp.writeFile(traversal, makeStoredZip([{ name: '../escape.txt', data: 'x' }]));
      await assert.rejects(() => api.extract({ input: traversal, outputDir: path.join(dir, 't1'), authorized: true, roots: [dir] }), (error) => error.code === 'E_ARCHIVE_UNSAFE');

      const symlink = path.join(dir, 'symlink.zip');
      await fsp.writeFile(symlink, makeStoredZip([{ name: 'link', data: 'target', unixMode: 0o120777 }]));
      await assert.rejects(() => api.extract({ input: symlink, outputDir: path.join(dir, 't2'), authorized: true, roots: [dir] }), (error) => error.code === 'E_ARCHIVE_SYMLINK');

      const encrypted = path.join(dir, 'encrypted.zip');
      await fsp.writeFile(encrypted, makeStoredZip([{ name: 'a.txt', data: 'x', flags: 0x0801 }]));
      await assert.rejects(() => api.extract({ input: encrypted, outputDir: path.join(dir, 't3'), authorized: true, roots: [dir] }), (error) => error.code === 'E_ARCHIVE_ENCRYPTED');

      // Duplicate names are ambiguous and rejected.
      const duplicate = path.join(dir, 'duplicate.zip');
      await fsp.writeFile(duplicate, makeStoredZip([
        { name: 'a.txt', data: 'one' },
        { name: 'A.TXT', data: 'two' },
      ]));
      await assert.rejects(() => api.extract({ input: duplicate, outputDir: path.join(dir, 't4'), authorized: true, roots: [dir] }), (error) => error.code === 'E_ARCHIVE_INVALID');

      // A deflate stream that lies about its uncompressed size is bounded by zlib's maxOutputLength.
      const bomb = path.join(dir, 'bomb.zip');
      await fsp.writeFile(bomb, makeDeflateZip('bomb.bin', Buffer.alloc(8 * 1024 * 1024, 0x41), 1024));
      await assert.rejects(() => api.extract({ input: bomb, outputDir: path.join(dir, 't5'), authorized: true, roots: [dir] }), (error) => error.code === 'E_ARCHIVE_INVALID');
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('ASAR extraction and source-map recovery reach S0 only with sourcesContent', async () => {
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'app.asar'), makeAsar({ 'main.js': 'module.exports = 1;\n', 'nested/data.json': '{"a":1}' }));
      const asarOut = path.join(dir, 'asar-out');
      const asar = await api.extract({ input: path.join(dir, 'app.asar'), outputDir: asarOut, authorized: true, roots: [dir] });
      assert.equal(asar.ok, true, JSON.stringify(asar));
      assert.equal(await fsp.readFile(path.join(asarOut, 'main.js'), 'utf8'), 'module.exports = 1;\n');

      await fsp.writeFile(path.join(dir, 'bundle.js'), 'console.log(1);\n//# sourceMappingURL=bundle.js.map\n');
      await fsp.writeFile(path.join(dir, 'bundle.js.map'), makeSourceMap(['src/a.ts', 'src/b.ts'], ['export const a = 1;\n', 'export const b = 2;\n']));
      const sourceOut = path.join(dir, 'sources');
      const recovered = await api.sourcemap({ js: path.join(dir, 'bundle.js'), outputDir: sourceOut, authorized: true, roots: [dir] });
      assert.equal(recovered.ok, true, JSON.stringify(recovered));
      assert.equal(recovered.level, 'S0');
      assert.equal(recovered.recovered, 2);
      assert.equal(await fsp.readFile(path.join(sourceOut, 'src', 'a.ts'), 'utf8'), 'export const a = 1;\n');

      await fsp.writeFile(path.join(dir, 'no-content.map'), makeSourceMap(['src/x.ts']));
      const noOut = path.join(dir, 'no-content');
      const missing = await api.sourcemap({ map: path.join(dir, 'no-content.map'), outputDir: noOut, authorized: true, roots: [dir] });
      assert.equal(missing.ok, true, JSON.stringify(missing));
      assert.equal(missing.level, 'S3');
      assert.equal(missing.recovered, 0);

      // A large map (>64 KiB) must still be classified as a source map, not text.
      const largeContents = ['export const a = "' + 'a'.repeat(80 * 1024) + '";\n', 'export const b = 2;\n'];
      const largeMap = makeSourceMap(['src/large.ts', 'src/small.ts'], largeContents);
      assert.ok(Buffer.byteLength(largeMap) > 64 * 1024);
      await fsp.writeFile(path.join(dir, 'large.js.map'), largeMap);
      const largeOut = path.join(dir, 'large-sources');
      const large = await api.decompile({ input: path.join(dir, 'large.js.map'), outputDir: largeOut, authorized: true, roots: [dir] });
      assert.equal(large.ok, true, JSON.stringify(large));
      assert.equal(large.family, 'electron');
      assert.equal(large.kind, 'sourcemap');
      assert.equal(large.level, 'S0');
      assert.equal(await fsp.readFile(path.join(largeOut, 'src', 'large.ts'), 'utf8'), largeContents[0]);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('GZIP extraction and text recovery work; report writes JSON+Markdown', async () => {
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'payload.gz'), zlib.gzipSync(Buffer.from('hello gzip\n')));
      const gzOut = path.join(dir, 'gz-out');
      const gz = await api.extract({ input: path.join(dir, 'payload.gz'), outputDir: gzOut, authorized: true, roots: [dir] });
      assert.equal(gz.ok, true, JSON.stringify(gz));
      assert.equal(await fsp.readFile(path.join(gzOut, 'payload'), 'utf8'), 'hello gzip\n');

      await fsp.writeFile(path.join(dir, 'source.ts'), 'export const x = 1;\n');
      const sourceOut = path.join(dir, 'text-out');
      const text = await api.decompile({ input: path.join(dir, 'source.ts'), outputDir: sourceOut, authorized: true, roots: [dir] });
      assert.equal(text.ok, true, JSON.stringify(text));
      assert.equal(text.level, 'S0');

      const reportFile = path.join(dir, 'report.md');
      const report = await api.report({ input: path.join(dir, 'source.ts'), output: reportFile, authorized: true, roots: [dir], authorizationNote: 'unit test fixture' });
      assert.equal(report.ok, true, JSON.stringify(report));
      assert.match(await fsp.readFile(reportFile, 'utf8'), /Recovery ceiling/);
      assert.equal(JSON.parse(await fsp.readFile(path.join(dir, 'report.json'), 'utf8')).target.name, 'source.ts');
      await assert.rejects(() => api.report({ input: path.join(dir, 'source.ts'), output: reportFile, authorized: true, roots: [dir] }), (error) => error.code === 'E_PATH_EXISTS');
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('evidence bundle is portable, hash-verified and detects tampering', async () => {
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'sample.js'), 'export const answer = 42;\n');
      const artifacts = path.join(dir, 'artifacts');
      await fsp.mkdir(path.join(artifacts, 'nested'), { recursive: true });
      await fsp.writeFile(path.join(artifacts, 'nested', 'out.txt'), 'artifact\n');
      const bundlePath = path.join(dir, 'evidence.zip');
      const created = await api.bundle({
        input: path.join(dir, 'sample.js'), output: bundlePath, artifactsDir: artifacts,
        authorized: true, roots: [dir], authorizationNote: 'unit test fixture',
      });
      assert.equal(created.ok, true, JSON.stringify(created));
      assert.equal(created.artifactCount, 1);
      assert.match(created.sha256, /^[0-9a-f]{64}$/);
      const verified = await api.verifyBundle({ bundle: bundlePath, roots: [dir] });
      assert.equal(verified.ok, true, JSON.stringify(verified));
      assert.equal(verified.artifactCount, 1);
      assert.equal(verified.mismatches.length, 0);

      // A plain ZIP (or any other archive) is not an evidence bundle.
      const plain = path.join(dir, 'plain.zip');
      await fsp.writeFile(plain, makeStoredZip([{ name: 'a.txt', data: 'a' }]));
      await assert.rejects(() => api.verifyBundle({ bundle: plain, roots: [dir] }), (error) => error.code === 'E_BUNDLE_INVALID');

      // No silent overwrite.
      await assert.rejects(() => api.bundle({
        input: path.join(dir, 'sample.js'), output: bundlePath, authorized: true, roots: [dir],
      }), (error) => error.code === 'E_PATH_EXISTS');

      // Changing a byte inside the stored bundle must fail verification.
      const bytes = await fsp.readFile(bundlePath);
      const marker = bytes.indexOf(Buffer.from('# Source recovery report'));
      assert.ok(marker > 0);
      bytes[marker + 2] = 0x58;
      const tampered = path.join(dir, 'tampered.zip');
      await fsp.writeFile(tampered, bytes);
      await assert.rejects(() => api.verifyBundle({ bundle: tampered, roots: [dir] }), (error) => error.code === 'E_ARCHIVE_INTEGRITY');

      // Rewriting a manifest field without recomputing the digest must fail closed.
      const base = await scanZip(bundlePath);
      const entries = [];
      for (const entry of base.entries) {
        if (entry.name.endsWith('/')) continue;
        let data = await readZipEntry(bundlePath, entry);
        if (entry.name === 'manifest.json') {
          const manifest = JSON.parse(data.toString('utf8'));
          manifest.recovery.ceiling.level = 'S0';
          manifest.authorizationNote = 'forged';
          data = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
        }
        entries.push({ name: entry.name, data });
      }
      const forged = path.join(dir, 'forged.zip');
      await fsp.writeFile(forged, makeStoredZip(entries));
      const forgedResult = await api.verifyBundle({ bundle: forged, roots: [dir] });
      assert.equal(forgedResult.ok, false);
      assert.equal(forgedResult.code, 'E_BUNDLE_INVALID');
      assert.ok(forgedResult.mismatches.some((mismatch) => mismatch.problem === 'bundle-digest'));

      // Undeclared files are never ignored.
      const extra = path.join(dir, 'extra.zip');
      await fsp.writeFile(extra, makeStoredZip([...entries, { name: 'dropped-payload.exe', data: 'MZ' }]));
      const extraResult = await api.verifyBundle({ bundle: extra, roots: [dir] });
      assert.equal(extraResult.ok, false);
      assert.ok(extraResult.mismatches.some((mismatch) => mismatch.problem === 'undeclared-entry'));
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('firmware carving extracts embedded gzip and CPIO payloads without binwalk', async () => {
    const dir = await tempDir();
    try {
      const { makeCpio } = await import('../lib/firmware.js');
      const gzipPayload = zlib.gzipSync(Buffer.from('firmware config\n'));
      const cpioPayload = makeCpio({ 'etc/config.txt': 'admin=1\n' });
      const firmware = Buffer.concat([
        Buffer.from('hsqs'), Buffer.alloc(64, 0),
        Buffer.from([0x1f, 0x8b, 0x08]), gzipPayload.subarray(3),
        Buffer.alloc(32, 0), cpioPayload,
      ]);
      const target = path.join(dir, 'firmware.bin');
      await fsp.writeFile(target, firmware);
      const result = await api.decompile({ input: target, outputDir: path.join(dir, 'out'), authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.family, 'firmware');
      assert.equal(result.level, 'S3');
      const firmwareAction = result.actions.find((action) => action.backend === 'builtin-firmware');
      assert.ok(firmwareAction, 'no builtin-firmware action');
      assert.ok(firmwareAction.findings.length >= 2, JSON.stringify(firmwareAction));
      const files = [];
      const walk = async (root) => {
        for (const entry of await fsp.readdir(root, { withFileTypes: true })) {
          const full = path.join(root, entry.name);
          if (entry.isDirectory()) await walk(full); else files.push(full);
        }
      };
      await walk(path.join(dir, 'out'));
      assert.ok(files.some((file) => file.endsWith('payload.bin')), 'gzip payload was not carved');
      assert.ok(files.some((file) => file.endsWith('config.txt')), 'CPIO member was not extracted');
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('concurrent writers to one output directory are rejected, not interleaved', async () => {
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'a.js'), 'export const a = 1;\n');
      const outputDir = path.join(dir, 'out');
      const results = await Promise.allSettled([
        api.decompile({ input: path.join(dir, 'a.js'), outputDir, authorized: true, roots: [dir] }),
        api.decompile({ input: path.join(dir, 'a.js'), outputDir, authorized: true, roots: [dir] }),
      ]);
      const fulfilled = results.filter((entry) => entry.status === 'fulfilled');
      const rejected = results.filter((entry) => entry.status === 'rejected');
      assert.equal(fulfilled.length, 1, JSON.stringify(results));
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason?.code, 'E_BUSY');
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('unauthorized operations fail before any backend; unknown or unsafe paths fail closed', async () => {
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'a.js'), 'x');
      await assert.rejects(() => api.decompile({ input: path.join(dir, 'a.js'), outputDir: path.join(dir, 'out'), roots: [dir] }), (error) => error.code === 'E_AUTHZ_REQUIRED');
      await assert.rejects(() => api.identify({ input: path.join(dir, 'missing.bin'), roots: [dir] }), (error) => error.code === 'E_IO');
      await assert.rejects(() => api.identify({ input: 'relative.bin', roots: [dir] }), (error) => error.code === 'E_PATH_ABSOLUTE');
      const outside = path.join(path.dirname(dir), `outside-${Date.now()}.js`);
      await fsp.writeFile(outside, 'x');
      await assert.rejects(() => api.identify({ input: outside, roots: [dir] }), (error) => error.code === 'E_PATH_OUTSIDE_ROOT');
      await fsp.rm(outside, { force: true });
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('self-test passes with zero failures and no external backend requirement', async () => {
    const result = await api.selftest();
    assert.equal(result.ok, true);
    assert.equal(result.counts.failed, 0);
    assert.ok(result.counts.passed >= 8);
    assert.equal(result.policy.executesTargets, false);
    assert.equal(result.policy.network, false);
  });
}

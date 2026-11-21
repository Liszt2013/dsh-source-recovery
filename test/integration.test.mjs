/** Plugin contract, CLI, real backend execution, docs/code consistency and secret hygiene. */
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { apply, buildToolDefinitions, parseSkillMarkdown } from '../index.js';

import { buildLaunch, detectTools } from '../lib/backends.js';
import { makeStoredZip } from '../lib/fixtures.js';
import { readZipEntry, scanZip } from '../lib/archive.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function tempDir(prefix = 'dsh-source-recovery-test-') {
  return fsp.mkdtemp(path.join(tmpdir(), prefix));
}

function fakeContext() {
  const tools = [];
  const skills = [];
  const routes = [];
  const webServer = { register(route) { routes.push(route); return () => {}; } };
  const ctx = {
    tools: { register(definition) { tools.push(definition); return () => {}; } },
    skills: { register(skill) { skills.push(skill); return () => {}; } },
    effect(callback) { const disposer = callback(); return () => { try { disposer?.(); } catch { /* disposed */ } }; },
    get(name) { return name === 'webServer' ? webServer : undefined; },
    logger: { debug() {}, warn() {} },
  };
  return { ctx, tools, skills, routes };
}

function request(url, remoteAddress = '127.0.0.1', method = 'GET') {
  return { method, url, headers: { host: '127.0.0.1:12345' }, socket: { remoteAddress } };
}

function fakeResponse() {
  const state = { status: 0, body: '' };
  return { state, writeHead(status) { state.status = status; }, end(body) { state.body = body ?? ''; } };
}

function runCli(args, options = {}) {
  return spawnSync(process.execPath, [path.join(ROOT, 'bin', 'cli.js'), ...args], {
    encoding: 'utf8', windowsHide: true, timeout: 120000, ...options,
  });
}

function makeMinimalElf() {
  // ELF64 x86-64 little-endian executable with one R-X PT_LOAD and a .text
  // section containing: mov eax,60; xor edi,edi; syscall (exit(0)).
  const code = Buffer.from([0xb8, 0x3c, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05]);
  const codeOffset = 120;
  const shstr = Buffer.from('\0.text\0.shstrtab\0', 'utf8');
  const shstrOffset = codeOffset + code.length;
  const shoff = Math.ceil((shstrOffset + shstr.length) / 8) * 8;
  const fileSize = shoff + 3 * 64;
  const buffer = Buffer.alloc(fileSize);
  buffer.writeUInt32BE(0x7f454c46, 0);
  buffer[4] = 2; buffer[5] = 1; buffer[6] = 1;
  buffer.writeUInt16LE(2, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x400000n + BigInt(codeOffset), 24);
  buffer.writeBigUInt64LE(64n, 32);
  buffer.writeBigUInt64LE(BigInt(shoff), 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(1, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(3, 60);
  buffer.writeUInt16LE(2, 62);
  buffer.writeUInt32LE(1, 64);
  buffer.writeUInt32LE(5, 68);
  buffer.writeBigUInt64LE(0n, 72);
  buffer.writeBigUInt64LE(0x400000n, 80);
  buffer.writeBigUInt64LE(0x400000n, 88);
  buffer.writeBigUInt64LE(BigInt(fileSize), 96);
  buffer.writeBigUInt64LE(BigInt(fileSize), 104);
  buffer.writeBigUInt64LE(0x1000n, 112);
  code.copy(buffer, codeOffset);
  shstr.copy(buffer, shstrOffset);
  const section = (index, name, type, flags, addr, offset, size, align) => {
    const base = shoff + index * 64;
    buffer.writeUInt32LE(name, base);
    buffer.writeUInt32LE(type, base + 4);
    buffer.writeBigUInt64LE(BigInt(flags), base + 8);
    buffer.writeBigUInt64LE(BigInt(addr), base + 16);
    buffer.writeBigUInt64LE(BigInt(offset), base + 24);
    buffer.writeBigUInt64LE(BigInt(size), base + 32);
    buffer.writeBigUInt64LE(BigInt(align), base + 48);
  };
  section(1, 1, 1, 6, 0x400000 + codeOffset, codeOffset, code.length, 16);
  section(2, 7, 3, 0, 0, shstrOffset, shstr.length, 1);
  return buffer;
}

export default function register(test) {
  test('plugin registers ten strict reverse_* tools, the skill and four loopback routes', async () => {
    const { ctx, tools, skills, routes } = fakeContext();
    await apply(ctx, {});
    const expected = [
      'reverse_capabilities', 'reverse_doctor', 'reverse_identify', 'reverse_extract',
      'reverse_decompile', 'reverse_sourcemap', 'reverse_report', 'reverse_bundle', 'reverse_verify', 'reverse_selftest',
    ];
    assert.deepEqual(tools.map((tool) => tool.name).sort(), expected.slice().sort());
    for (const tool of tools) {
      assert.equal(tool.parameters.additionalProperties, false);
      assert.equal(typeof tool.execute, 'function');
      assert.equal(tool.output.schema.type, 'object');
      assert.equal(tool.output.render === undefined, false);
    }
    const extract = tools.find((tool) => tool.name === 'reverse_extract');
    assert.equal(extract.parameters.required.includes('authorized'), true);
    assert.equal(Object.keys(extract.parameters.properties).includes('passphrase'), false);
    assert.equal(skills.length, 1);
    assert.equal(skills[0].name, 'dsh-source-recovery');
    // DSH's loader later validates this field; a missing/incorrect `source`
    // produces the "loaded skill ... source must be a string" failure.
    assert.equal(typeof skills[0].source, 'string');
    assert.ok(skills[0].source.length > 0);
    assert.equal(typeof skills[0].content, 'string');
    assert.equal(typeof skills[0].description, 'string');
    const markdown = await fsp.readFile(path.join(ROOT, 'skills', 'dsh-source-recovery', 'SKILL.md'), 'utf8');
    assert.equal(skills[0].description, parseSkillMarkdown(markdown).description);
    assert.match(skills[0].content, /Security red lines/);
    assert.deepEqual(routes.map((route) => route.path).sort(), [
      '/plugins/dsh-source-recovery/api/capabilities',
      '/plugins/dsh-source-recovery/api/doctor',
      '/plugins/dsh-source-recovery/api/health',
      '/plugins/dsh-source-recovery/api/selftest',
    ]);
  });

  test('workbench routes are loopback same-origin, read-only and JSON', async () => {
    const { ctx, routes } = fakeContext();
    await apply(ctx, {});
    const health = routes.find((route) => route.path.endsWith('/health'));
    const good = fakeResponse();
    await health.handler(request(health.path), good);
    assert.equal(good.state.status, 200);
    const payload = JSON.parse(good.state.body);
    assert.equal(payload.ok, true);
    assert.equal(payload.toolCount, 10);
    assert.equal(payload.executesTargets, false);
    const denied = fakeResponse();
    await health.handler(request(health.path, '10.0.0.8'), denied);
    assert.equal(denied.state.status, 403);
    const post = fakeResponse();
    await health.handler(request(health.path, '127.0.0.1', 'POST'), post);
    assert.equal(post.state.status, 405);
    const selftest = routes.find((route) => route.path.endsWith('/selftest'));
    const response = fakeResponse();
    await selftest.handler(request(selftest.path), response);
    const selftestPayload = JSON.parse(response.state.body);
    assert.equal(selftestPayload.ok, true);
    assert.equal(selftestPayload.counts.failed, 0);
  });

  test('tool execution returns envelopes and enforces authorization without throwing', async () => {
    const dir = await tempDir();
    try {
      const target = path.join(dir, 'sample.js');
      await fsp.writeFile(target, 'const x = 1;\n');
      const tools = Object.fromEntries(buildToolDefinitions(() => [dir]).map((tool) => [tool.name, tool]));
      const exec = { agent: { session: { meta: { cwd: dir } } } };
      const identify = await tools.reverse_identify.execute({ input: target }, exec);
      assert.equal(identify.ok, true, JSON.stringify(identify));
      assert.equal(identify.family, 'electron');
      const capabilities = await tools.reverse_capabilities.execute({}, exec);
      assert.equal(capabilities.ok, true);
      assert.ok(capabilities.families.length >= 6);
      const denied = await tools.reverse_decompile.execute({ input: target, outputDir: path.join(dir, 'out') }, exec);
      assert.equal(denied.ok, false);
      assert.equal(denied.code, 'E_AUTHZ_REQUIRED');
      const outside = await tools.reverse_identify.execute({ input: path.join(path.dirname(dir), 'nope') }, exec);
      assert.equal(outside.ok, false);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('CLI emits stable JSON and correct authorization exit codes', async () => {
    const dir = await tempDir();
    try {
      const target = path.join(dir, 'a.js');
      await fsp.writeFile(target, 'x');
      const capabilities = runCli(['capabilities', '--json'], { cwd: dir });
      assert.equal(capabilities.status, 0, capabilities.stderr);
      assert.equal(JSON.parse(capabilities.stdout).ok, true);
      const identify = runCli(['identify', '--in', target, '--json'], { cwd: dir });
      assert.equal(identify.status, 0, identify.stderr);
      assert.equal(JSON.parse(identify.stdout).family, 'electron');
      const unauthorized = runCli(['decompile', '--in', target, '--out', path.join(dir, 'out'), '--json'], { cwd: dir });
      assert.equal(unauthorized.status, 2);
      assert.equal(JSON.parse(unauthorized.stdout).code, 'E_AUTHZ_REQUIRED');
      // Minimal P0 CLI form: <target> --output <dir> --authorized
      const minimal = runCli([target, '--output', path.join(dir, 'minimal-out'), '--authorized', '--report', path.join(dir, 'minimal.md'), '--json'], { cwd: dir });
      assert.equal(minimal.status, 0, minimal.stdout + minimal.stderr);
      const minimalPayload = JSON.parse(minimal.stdout);
      assert.equal(minimalPayload.ok, true);
      assert.equal(minimalPayload.identify.family, 'electron');
      assert.equal(minimalPayload.level, 'S3');
      assert.equal(minimalPayload.report.ok, true);
      assert.equal(minimalPayload.report.markdownPath, path.join(dir, 'minimal.md'));
      const version = runCli(['--version'], { cwd: dir });
      assert.equal(version.status, 0);
      assert.match(version.stdout, /^dsh-source-recovery 0\.2\.0/);
      const badCommand = runCli(['not-a-command'], { cwd: dir });
      assert.equal(badCommand.status, 2);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('Windows .bat/.cmd toolchains are launched through cmd.exe, not spawned directly', async () => {
    if (process.platform !== 'win32') return { skipped: true, reason: 'Windows-only launcher path' };
    const launch = buildLaunch('C:\\tools\\jadx.bat', ['--version']);
    assert.match(launch.command, /cmd\.exe$/i);
    assert.deepEqual(launch.args.slice(0, 3), ['/d', '/s', '/c']);
    assert.equal(launch.verbatim, true);
    assert.match(launch.args[3], /jadx\.bat/);
    assert.match(launch.args[3], /--version/);
    const plain = buildLaunch('C:\\tools\\jadx.exe', ['-d']);
    assert.equal(plain.verbatim, false);
    assert.equal(plain.command, 'C:\\tools\\jadx.exe');
  });

  test('real JADX decompiles a compiled JAR to Java source (S1)', async () => {    const tools = await detectTools();
    const javac = spawnSync('javac', ['-version'], { encoding: 'utf8', windowsHide: true });
    if (tools.jadx?.available !== true || javac.status !== 0) {
      return { skipped: true, unavailable: true, reason: 'jadx and javac are both required for the real Java decompile test' };
    }
    const dir = await tempDir();
    try {
      const javaFile = path.join(dir, 'Hello.java');
      await fsp.writeFile(javaFile, 'public class Hello { public static int answer() { return 42; } }\n');
      const compiled = spawnSync('javac', ['-d', dir, javaFile], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
      if (compiled.status !== 0) return { skipped: true, unavailable: true, reason: `javac failed: ${compiled.stderr?.slice(0, 200)}` };
      const classBytes = await fsp.readFile(path.join(dir, 'Hello.class'));
      const jar = path.join(dir, 'hello.jar');
      await fsp.writeFile(jar, makeStoredZip([{ name: 'Hello.class', data: classBytes }]));
      const api = await import('../lib/api.js');
      const result = await api.decompile({ input: jar, outputDir: path.join(dir, 'out'), authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.level, 'S1');
      const files = [];
      const walk = async (root) => {
        for (const entry of await fsp.readdir(root, { withFileTypes: true })) {
          const full = path.join(root, entry.name);
          if (entry.isDirectory()) await walk(full);
          else if (entry.name.endsWith('.java')) files.push(full);
        }
      };
      await walk(path.join(dir, 'out'));
      assert.ok(files.length > 0, 'JADX produced no Java source');
      const source = await fsp.readFile(files[0], 'utf8');
      assert.match(source, /class Hello/);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('real APK (real DEX) decompiles with JADX to Java source (S1)', async () => {
    const tools = await detectTools();
    const javac = spawnSync('javac', ['-version'], { encoding: 'utf8', windowsHide: true });
    let d8 = null;
    const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT ?? path.join(process.env.LOCALAPPDATA ?? '', 'Android', 'Sdk');
    const buildTools = path.join(sdk, 'build-tools');
    try {
      const versions = (await fsp.readdir(buildTools)).sort().reverse();
      for (const version of versions) {
        const candidate = path.join(buildTools, version, process.platform === 'win32' ? 'd8.bat' : 'd8');
        if (await fsp.lstat(candidate).then((stat) => stat.isFile()).catch(() => false)) { d8 = candidate; break; }
      }
    } catch { /* no SDK */ }
    if (tools.jadx?.available !== true || javac.status !== 0 || d8 === null) {
      return { skipped: true, unavailable: true, reason: 'jadx, javac and Android build-tools d8 are all required for the real APK test' };
    }
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'Hello.java'), 'public class Hello { public static int answer() { return 42; } }\n');
      const compiled = spawnSync('javac', ['Hello.java'], { cwd: dir, encoding: 'utf8', windowsHide: true, timeout: 60000 });
      if (compiled.status !== 0) return { skipped: true, unavailable: true, reason: `javac failed: ${compiled.stderr?.slice(0, 160)}` };
      const d8Result = spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `""${d8}" --output "${dir}" Hello.class"`], {
        cwd: dir, encoding: 'utf8', windowsHide: true, timeout: 120000, windowsVerbatimArguments: true,
      });
      const dex = path.join(dir, 'classes.dex');
      if (!(await fsp.lstat(dex).then(() => true).catch(() => false))) {
        return { skipped: true, unavailable: true, reason: `d8 produced no classes.dex: ${d8Result.stderr?.slice(0, 160)}` };
      }
      const apk = path.join(dir, 'hello.apk');
      await fsp.writeFile(apk, makeStoredZip([
        { name: 'AndroidManifest.xml', data: '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.hello"/>' },
        { name: 'classes.dex', data: await fsp.readFile(dex) },
      ]));
      const api = await import('../lib/api.js');
      const result = await api.decompile({ input: apk, outputDir: path.join(dir, 'out'), authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.family, 'apk');
      assert.equal(result.level, 'S1');
      const files = [];
      const walk = async (root) => {
        for (const entry of await fsp.readdir(root, { withFileTypes: true })) {
          const full = path.join(root, entry.name);
          if (entry.isDirectory()) await walk(full);
          else if (entry.name.endsWith('.java')) files.push(full);
        }
      };
      await walk(path.join(dir, 'out'));
      assert.ok(files.length > 0, 'JADX produced no Java source from the APK');
      assert.match(await fsp.readFile(files[0], 'utf8'), /class Hello/);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('real objdump recovers disassembly (S3) without claiming source', async () => {
    const tools = await detectTools();
    if (tools.objdump?.available !== true) return { skipped: true, unavailable: true, reason: 'objdump is not installed' };
    const dir = await tempDir();
    try {
      const cFile = path.join(dir, 'sample.c');
      await fsp.writeFile(cFile, 'int recovery_probe(int x) { return x * 7 + 3; }\nint main(void) { return recovery_probe(1); }\n');
      const exe = path.join(dir, process.platform === 'win32' ? 'sample.exe' : 'sample');
      const compiled = spawnSync('gcc', ['-O1', '-o', exe, cFile], { encoding: 'utf8', windowsHide: true, timeout: 60000 });
      if (compiled.status !== 0) return { skipped: true, unavailable: true, reason: `gcc unavailable or failed: ${compiled.stderr?.slice(0, 120)}` };
      const api = await import('../lib/api.js');
      const result = await api.decompile({ input: exe, outputDir: path.join(dir, 'out'), authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.level, 'S3');
      const disassembly = await fsp.readFile(path.join(dir, 'out', 'disassembly.txt'), 'utf8');
      assert.match(disassembly, /recovery_probe/);
      assert.equal(/original source recovered/i.test(result.reason), false);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('real objdump recovers disassembly from a real ELF binary (S3)', async () => {
    const tools = await detectTools();
    if (tools.objdump?.available !== true) return { skipped: true, unavailable: true, reason: 'objdump is not installed' };
    const dir = await tempDir();
    try {
      const elf = path.join(dir, 'sample.elf');
      await fsp.writeFile(elf, makeMinimalElf());
      const api = await import('../lib/api.js');
      const result = await api.decompile({ input: elf, outputDir: path.join(dir, 'out'), authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.family, 'native');
      assert.equal(result.kind, 'elf');
      assert.equal(result.level, 'S3');
      const disassembly = await fsp.readFile(path.join(dir, 'out', 'disassembly.txt'), 'utf8');
      assert.match(disassembly, /syscall|mov/i);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('real APK resources decode with apktool alongside JADX (S1)', async () => {
    const tools = await detectTools();
    const javac = spawnSync('javac', ['-version'], { encoding: 'utf8', windowsHide: true });
    const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT ?? path.join(process.env.LOCALAPPDATA ?? '', 'Android', 'Sdk');
    const buildToolsRoot = path.join(sdk, 'build-tools');
    let d8 = null;
    let aapt2 = null;
    try {
      const versions = (await fsp.readdir(buildToolsRoot)).sort().reverse();
      for (const version of versions) {
        const dir = path.join(buildToolsRoot, version);
        const d8Candidate = path.join(dir, process.platform === 'win32' ? 'd8.bat' : 'd8');
        const aapt2Candidate = path.join(dir, process.platform === 'win32' ? 'aapt2.exe' : 'aapt2');
        if (d8 === null && await fsp.lstat(d8Candidate).then((stat) => stat.isFile()).catch(() => false)) d8 = d8Candidate;
        if (aapt2 === null && await fsp.lstat(aapt2Candidate).then((stat) => stat.isFile()).catch(() => false)) aapt2 = aapt2Candidate;
      }
    } catch { /* no SDK */ }
    let androidJar = null;
    try {
      const platforms = (await fsp.readdir(path.join(sdk, 'platforms'))).sort().reverse();
      for (const platform of platforms) {
        const candidate = path.join(sdk, 'platforms', platform, 'android.jar');
        if (await fsp.lstat(candidate).then((stat) => stat.isFile()).catch(() => false)) { androidJar = candidate; break; }
      }
    } catch { /* no platforms */ }
    if (tools.jadx?.available !== true || tools.apktool?.available !== true || javac.status !== 0 || d8 === null || aapt2 === null || androidJar === null) {
      return { skipped: true, unavailable: true, reason: 'JADX, apktool, javac, d8, aapt2 and android.jar are all required for the APK resources test' };
    }
    const dir = await tempDir();
    try {
      await fsp.writeFile(path.join(dir, 'Hello.java'), 'public class Hello { public static int answer() { return 42; } }\n');
      assert.equal(spawnSync('javac', ['Hello.java'], { cwd: dir, windowsHide: true, timeout: 60000 }).status, 0);
      const d8Result = spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `""${d8}" --output "${dir}" Hello.class"`], {
        cwd: dir, windowsHide: true, timeout: 120000, windowsVerbatimArguments: true,
      });
      assert.ok(await fsp.lstat(path.join(dir, 'classes.dex')).then(() => true).catch(() => false), `d8 failed: ${d8Result.stderr?.slice(0, 200)}`);
      await fsp.writeFile(path.join(dir, 'AndroidManifest.xml'), '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.hello"><application android:label="Hello"/></manifest>\n');
      const linked = spawnSync(aapt2, ['link', '-o', path.join(dir, 'base.apk'), '--manifest', path.join(dir, 'AndroidManifest.xml'), '-I', androidJar], {
        cwd: dir, encoding: 'utf8', timeout: 120000, windowsHide: true,
      });
      assert.equal(linked.status, 0, linked.stderr?.slice(0, 500));
      const base = await scanZip(path.join(dir, 'base.apk'));
      const entries = [];
      for (const entry of base.entries) {
        if (entry.name.endsWith('/')) continue;
        entries.push({ name: entry.name, data: await readZipEntry(path.join(dir, 'base.apk'), entry) });
      }
      entries.push({ name: 'classes.dex', data: await fsp.readFile(path.join(dir, 'classes.dex')) });
      const apk = path.join(dir, 'hello.apk');
      await fsp.writeFile(apk, makeStoredZip(entries));
      const api = await import('../lib/api.js');
      const result = await api.decompile({ input: apk, outputDir: path.join(dir, 'out'), authorized: true, roots: [dir] });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.level, 'S1');
      assert.ok(result.actions.some((action) => action.backend === 'jadx' && action.code === 0), JSON.stringify(result.actions));
      const apktoolAction = result.actions.find((action) => action.backend === 'apktool');
      assert.ok(apktoolAction, 'apktool did not run');
      assert.equal(apktoolAction.code, 0, JSON.stringify(apktoolAction).slice(0, 600));
      const smali = [];
      const walk = async (root) => {
        for (const entry of await fsp.readdir(root, { withFileTypes: true })) {
          const full = path.join(root, entry.name);
          if (entry.isDirectory()) await walk(full);
          else smali.push(full);
        }
      };
      await walk(path.join(dir, 'out', 'apktool'));
      assert.ok(smali.some((file) => file.endsWith('.smali')), 'apktool produced no smali');
      assert.ok(smali.some((file) => path.basename(file) === 'AndroidManifest.xml'), 'apktool produced no decoded manifest');
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('built-in .NET CLI metadata recovers assembly, types, methods and strings (S3)', async () => {
    const roots = [];
    if (process.env.DOTNET_ROOT) roots.push(process.env.DOTNET_ROOT);
    roots.push('C:\\Program Files\\dotnet');
    let assembly = null;
    for (const root of roots) {
      const shared = path.join(root, 'shared', 'Microsoft.NETCore.App');
      try {
        const versions = (await fsp.readdir(shared)).sort().reverse();
        for (const version of versions) {
          const candidate = path.join(shared, version, 'System.Console.dll');
          if (await fsp.lstat(candidate).then((stat) => stat.isFile()).catch(() => false)) { assembly = candidate; break; }
        }
      } catch { /* not this root */ }
      if (assembly !== null) break;
    }
    if (assembly === null) return { skipped: true, unavailable: true, reason: 'no .NET runtime assembly is available on this host' };
    const dir = await tempDir();
    try {
      const api = await import('../lib/api.js');
      const result = await api.decompile({
        input: assembly, outputDir: path.join(dir, 'out'), authorized: true,
        roots: [path.dirname(assembly), dir],
      });
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.family, 'dotnet');
      assert.equal(result.level, 'S3');
      assert.ok(result.actions.some((action) => action.backend === 'builtin-dotnet-metadata'));
      const metadata = JSON.parse(await fsp.readFile(path.join(dir, 'out', 'dotnet-metadata.json'), 'utf8'));
      assert.ok(metadata.counts.types > 0);
      assert.ok(metadata.counts.methods > 0);
      assert.ok(metadata.assembly && typeof metadata.assembly.name === 'string');
      const types = await fsp.readFile(path.join(dir, 'out', 'dotnet-types.txt'), 'utf8');
      assert.match(types, /System\./);
    } finally { await fsp.rm(dir, { recursive: true, force: true }); }
  });

  test('documentation and packaged files match code', async () => {
    const pkg = JSON.parse(await fsp.readFile(path.join(ROOT, 'package.json'), 'utf8'));
    const manifest = JSON.parse(await fsp.readFile(path.join(ROOT, 'dsh.plugin.json'), 'utf8'));
    const tools = buildToolDefinitions(() => undefined).map((tool) => tool.name);
    assert.deepEqual(manifest.contributes.tools.sort(), tools.slice().sort());
    for (const required of ['index.js', 'client.js', 'bin', 'lib', 'skills', 'locale/*.json', 'cordis.patch.yml', 'dsh.plugin.json']) {
      assert.ok(pkg.files.includes(required), `package files missing ${required}`);
    }
    assert.equal(pkg.dsh.bundle.patch, './cordis.patch.yml');
    assert.equal(pkg.dsh.client.platform, 'web');
    const client = await fsp.readFile(path.join(ROOT, 'client.js'), 'utf8');
    assert.match(client, /__ModuleLoader__\.load/);
    assert.match(client, /sidebar\.panellist/);
    assert.match(client, /label: 'Reverse'/);
    const patch = await fsp.readFile(path.join(ROOT, 'cordis.patch.yml'), 'utf8');
    assert.match(patch, /name: dsh-source-recovery/);
    for (const reference of ['workflow.md', 'levels.md', 'tools.md', 'security.md', 'troubleshooting.md']) {
      const stat = await fsp.lstat(path.join(ROOT, 'skills', 'dsh-source-recovery', 'references', reference));
      assert.equal(stat.isFile(), true);
    }
    for (const file of ['README.md', 'README.en.md', 'THREAT-MODEL.md', 'SECURITY.md', 'COMPATIBILITY.md', 'KNOWN-LIMITATIONS.md', 'THIRD-PARTY-NOTICES.md', 'LICENSE']) {
      assert.equal((await fsp.lstat(path.join(ROOT, file))).isFile(), true, `${file} is missing`);
    }
    // Versioned JSON schemas must exist and stay parseable.
    const schemas = {};
    for (const name of ['envelope', 'report', 'evidence']) {
      const schema = JSON.parse(await fsp.readFile(path.join(ROOT, 'schemas', `${name}.schema.json`), 'utf8'));
      assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
      assert.ok(schema.required.length > 0);
      schemas[name] = schema;
    }
    assert.equal(schemas.evidence.properties.schema.const, 'dsh-source-recovery/evidence/1');
    assert.equal(schemas.report.properties.schema.const, 'dsh-source-recovery/report/1');
    const cli = await fsp.readFile(path.join(ROOT, 'bin', 'cli.js'), 'utf8');
    assert.equal(cli.includes('shell: true'), false);
    assert.equal(cli.includes('Invoke-Expression'), false);
    const source = await fsp.readFile(path.join(ROOT, 'lib', 'recovery.js'), 'utf8');
    assert.equal(/spawn\(|exec\(/.test(source), false, 'recovery core must not spawn directly; use lib/proc.js');
  });

  test('repository contains no private keys or long embedded credentials', async () => {
    const findings = [];
    const walk = async (dir) => {
      for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
        if (['node_modules', '.git', 'reports', '.dsh-verify'].includes(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) { await walk(full); continue; }
        if (entry.name.endsWith('.tgz')) continue;
        const stat = await fsp.stat(full);
        if (stat.size > 2 * 1024 * 1024) continue;
        const text = await fsp.readFile(full, 'utf8').catch(() => '');
        if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text)) findings.push(`${full}: private key block`);
        if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) findings.push(`${full}: AWS access key pattern`);
        if (/sk-[A-Za-z0-9]{24,}/.test(text)) findings.push(`${full}: API key pattern`);
      }
    };
    await walk(ROOT);
    assert.deepEqual(findings, []);
  });
}

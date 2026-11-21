/** Orchestrate source recovery toward the highest honest level. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { assertOutputDirectory, extractAsar, extractByKind, safeJoin, safeSegments, scanZip } from './archive.js';
import { detectTools, runTool } from './backends.js';
import { identifyFile } from './identify.js';
import { LEVELS, RECOVERY_POLICY } from './levels.js';
import { recoverSources } from './sourcemap.js';
import { extractFirmware } from './firmware.js';
import { sha256 } from './util.js';

async function countTree(root, limits = { files: 100_000 }) {
  let files = 0;
  let bytes = 0;
  const walk = async (dir) => {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (files >= limits.files) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { await walk(full); continue; }
      if (!entry.isFile()) continue;
      const stat = await fsp.stat(full);
      files += 1;
      bytes += stat.size;
    }
  };
  await walk(root).catch(() => {});
  return { files, bytes };
}

async function writeTextFile(root, name, text, mode = 0o600) {
  const target = safeJoin(root, safeSegments(name));
  await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await fsp.writeFile(target, text, { flag: 'wx', mode });
  return { path: name, bytes: Buffer.byteLength(text), sha256: sha256(text) };
}

async function findFiles(root, predicate, out = []) {
  let entries;
  try { entries = await fsp.readdir(root, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) await findFiles(full, predicate, out);
    else if (entry.isFile() && predicate(full)) out.push(full);
  }
  return out;
}

async function recoverEmbeddedSources(jsFiles, outputDir, allowedRoots) {
  const recovered = [];
  for (const jsFile of jsFiles.slice(0, 200)) {
    try {
      const result = await recoverSources({ jsPath: jsFile, outputDir, allowedRoots });
      if (result.recovered > 0) recovered.push({ jsFile: path.relative(outputDir, jsFile), recovered: result.recovered, files: result.files });
    } catch { /* no or invalid map is a normal outcome */ }
  }
  return recovered;
}

/** Build a machine-readable plan from identification and backend availability. */
export async function buildPlan(identification, tools) {
  const family = identification.family;
  const steps = [];
  const gaps = [];
  const available = (id) => tools[id]?.available === true;
  const push = (step, backend, level, availableNow, reason, delegatedTo = null) => {
    steps.push({ step, backend, level, available: availableNow, delegatedTo, reason });
    if (!availableNow) gaps.push({ missing: backend, step, alternatives: reason, delegatedTo });
  };
  if (family === 'apk') {
    push('decompile Java/Kotlin sources', 'jadx', 'S1', available('jadx'), available('jadx') ? 'available' : 'install JADX or use REA MCP APK tools');
    push('decode resources and smali', 'apktool', 'S2', available('apktool'), available('apktool') ? 'available (smali is not Java source)' : 'install apktool or use REA MCP');
    push('extract raw contents', 'builtin-archive', 'S3', true, 'always available');
  } else if (family === 'dotnet') {
    push('decompile C# near-source', 'ilspycmd', 'S1', available('ilspycmd'), 'install ilspycmd, or use REA MCP managed reconstruction', tools.rea?.available === true ? 'REA MCP managed tools' : null);
    push('recover CLI metadata and names', 'builtin-dotnet-metadata', 'S3', true, 'always available');
  } else if (family === 'native') {
    push('disassemble', 'objdump', 'S3', available('objdump'), 'install binutils');
    push('ELF headers and sections', 'readelf', 'S3', available('readelf'), 'install binutils');
    push('decompile pseudo-C', 'ghidra', 'S2', available('ghidra'), 'this plugin does not run Ghidra/REA; delegated analysis requires the model to call mcp__rea__* or an installed Ghidra', tools.rea?.available === true ? 'REA MCP native tools' : null);
  } else if (family === 'electron') {
    push('extract ASAR or JS bundle', 'builtin-asar', 'S3', true, 'always available');
    push('recover original sources from source maps', 'builtin-sourcemap', 'S0', identification.kind === 'sourcemap', 'requires a source map with sourcesContent (detected maps only)');
  } else if (family === 'firmware') {
    push('carve embedded gzip/ZIP/CPIO/tar payloads', 'builtin-firmware', 'S3', true, 'always available');
    push('extract exotic filesystems', 'binwalk/unblob', 'S3', available('binwalk') || available('unblob'), 'install binwalk or unblob');
    push('extract printable strings', 'strings', 'S3', available('strings'), 'install binutils');
    push('source recovery', 'none', 'S4', false, 'compiled firmware cannot yield original source');
  } else if (family === 'archive') {
    push('extract container', 'builtin-archive', identification.kind, true, 'always available');
  } else if (family === 'malware') {
    push('static triage only', 'builtin-static', 'S3', true, 'target execution is never performed');
  } else {
    push('unknown target', 'none', 'S4', false, 'identification did not match a supported family');
  }
  const order = ['S0', 'S1', 'S2', 'S3', 'S4'];
  const best = steps.filter((step) => step.available).reduce((level, step) => (order.indexOf(step.level) < order.indexOf(level) ? step.level : level), 'S4');
  return { bestLevel: best, steps, gaps, policy: RECOVERY_POLICY };
}
/**
 * Recover artifacts into a new output directory.
 * @param {{input:string, outputDir:string, roots:string[], config:object, authorized:boolean, authorizationNote?:string}} options
 */
export async function recover(options) {
  if (options.authorized !== true) {
    throw new RecoveryError('E_AUTHZ_REQUIRED', 'explicit authorization is required: pass authorized=true only for targets you are allowed to analyze', { exitCode: 2 });
  }
  const identification = await identifyFile(options.input, { maxInputBytes: options.config.maxInputBytes });
  const tools = await detectTools();
  const plan = await buildPlan(identification, tools);
  const limits = {
    maxEntries: options.config.maxEntries,
    maxExtractedBytes: options.config.maxExtractedBytes,
    maxEntryBytes: options.config.maxEntryBytes,
  };
  const created = await assertOutputDirectory(options.outputDir, options.roots, options.config.overwrite === true);
  const outputDir = created.path;
  const actions = [];
  let level = 'S4';
  let reason = 'no local recovery backend produced source-form output';
  const warnings = [];
  try {
    if (identification.family === 'apk') {
      let ran = 0;
      if (tools.jadx?.available === true) {
        const run = await runTool('jadx', ['-d', path.join(outputDir, 'jadx'), '--no-res', '--no-debug-info', options.input], {
          timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: options.config.backendOutputLimitBytes, signal: options.signal,
        });
        actions.push({ backend: 'jadx', ...run });
        ran += 1;
        const sources = await findFiles(outputDir, (file) => file.endsWith('.java') || file.endsWith('.kt'));
        if (run.code === 0 && sources.length > 0) { level = 'S1'; reason = `jadx produced ${sources.length} Java/Kotlin files`; }
        else warnings.push('jadx did not produce source files; see action stderr');
      }
      if (tools.apktool?.available === true && options.resources !== false) {
        const run = await runTool('apktool', ['d', '-f', '-o', path.join(outputDir, 'apktool'), options.input], {
          timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: options.config.backendOutputLimitBytes, signal: options.signal,
        });
        actions.push({ backend: 'apktool', ...run });
        ran += 1;
        const smali = await findFiles(outputDir, (file) => file.endsWith('.smali'));
        const manifest = await findFiles(outputDir, (file) => path.basename(file) === 'AndroidManifest.xml');
        if (run.code === 0 && smali.length > 0) {
          if (level !== 'S1') { level = 'S1'; reason = `apktool produced ${smali.length} smali files and ${manifest.length} manifest(s) (not Java source)`; }
          else reason += `; apktool also decoded ${smali.length} smali files/resources`;
        } else warnings.push('apktool did not produce smali/resources; see action stderr');
        if (level === 'S4' && run.code === 0 && smali.length > 0) {
          level = 'S2';
          reason = "apktool produced " + smali.length + " smali files/resources; smali is not Java source";
        }
      }
      if (ran === 0) {
        warnings.push('no APK source backend installed; falling back to raw extraction');
        const raw = await extractByKind(options.input, 'apk', outputDir, limits);
        actions.push({ backend: 'builtin-archive', files: raw.files.length, bytes: raw.bytes });
        level = 'S3';
        reason = 'raw APK contents only; install JADX/apktool or use REA MCP for source';
      } else if (level === 'S4') {
        warnings.push('APK backends ran but produced no source-form output');
      }
    } else if (identification.family === 'electron' || identification.family === 'archive' && identification.kind === 'jar') {
      if (identification.kind === 'asar') {
        const raw = await extractAsar(options.input, outputDir, limits);
        actions.push({ backend: 'builtin-asar', files: raw.files.length, bytes: raw.bytes });
        const maps = await findFiles(outputDir, (file) => file.endsWith('.map'));
        const js = await findFiles(outputDir, (file) => /\.(js|mjs|cjs)$/.test(file));
        const recovered = await recoverEmbeddedSources(js, outputDir, options.roots);
        if (recovered.length > 0) { level = 'S0'; reason = `recovered sourcesContent for ${recovered.length} bundles`; }
        else { level = 'S3'; reason = `ASAR bundled JS extracted (${js.length} files); no original source maps with sourcesContent`; }
        actions.push({ backend: 'builtin-sourcemap', maps: maps.length, recovered });
      } else if (identification.kind === 'javascript' || identification.kind === 'sourcemap') {
        if (identification.kind === 'sourcemap') {
          const result = await recoverSources({ mapPath: options.input, outputDir });
          level = result.level;
          reason = result.note;
          actions.push({ backend: 'builtin-sourcemap', recovered: result.recovered });
        } else {
          const copy = await fsp.readFile(options.input);
          const target = safeJoin(outputDir, safeSegments(path.basename(options.input)));
          await fsp.writeFile(target, copy, { flag: 'wx', mode: 0o600 });
          const isBundle = /\.(js|mjs|cjs)$/i.test(options.input);
          const recovered = await recoverEmbeddedSources([options.input], outputDir, options.roots);
          if (recovered.length > 0) { level = 'S0'; reason = 'inline/external source map recovered original text'; }
          else if (!isBundle) { level = 'S0'; reason = 'the input is shipped source text (TypeScript/other source extension), copied verbatim'; }
          else { level = 'S3'; reason = 'JavaScript bundle copied; no source map with sourcesContent'; }
          actions.push({ backend: 'builtin-js', recovered });
        }
      } else if (tools.jadx?.available === true) {
        const run = await runTool('jadx', ['-d', path.join(outputDir, 'jadx'), '--no-res', options.input], { timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: options.config.backendOutputLimitBytes });
        actions.push({ backend: 'jadx', ...run });
        const sources = await findFiles(outputDir, (file) => file.endsWith('.java'));
        if (run.code === 0 && sources.length > 0) { level = 'S1'; reason = `jadx produced ${sources.length} Java files from the archive`; }
      } else {
        const raw = await extractByKind(options.input, identification.kind, outputDir, limits);
        actions.push({ backend: 'builtin-archive', files: raw.files.length, bytes: raw.bytes });
        level = 'S3';
        reason = 'archive extracted; install JADX for Java source from class files';
      }
    } else if (identification.family === 'dotnet') {
      if (tools.ilspycmd?.available === true) {
        const run = await runTool('ilspycmd', ['-o', path.join(outputDir, 'ilspy'), options.input], { timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: options.config.backendOutputLimitBytes });
        actions.push({ backend: 'ilspycmd', ...run });
        const cs = await findFiles(outputDir, (file) => file.endsWith('.cs'));
        if (run.code === 0 && cs.length > 0) { level = 'S1'; reason = `ilspycmd produced ${cs.length} C# files`; }
        else warnings.push('ilspycmd ran but produced no C# files; falling back to CLI metadata');
      }
      if (level !== 'S1') {
        try {
          const { recoverDotnetMetadata } = await import('./dotnet.js');
          const buffer = await fsp.readFile(options.input);
          const dotnet = await recoverDotnetMetadata(buffer, outputDir);
          actions.push({
            backend: 'builtin-dotnet-metadata',
            assembly: dotnet.assembly,
            types: dotnet.counts.types,
            methods: dotnet.counts.methods,
            strings: dotnet.counts.strings,
          });
          level = 'S3';
          reason = `CLI metadata: ${dotnet.assembly?.name ?? 'assembly'} ${dotnet.assembly?.version ?? ''}, ${dotnet.counts.types} types and ${dotnet.counts.methods} methods (names only; C# near-source needs ilspycmd or REA)`;
        } catch (error) {
          warnings.push(`CLI metadata parse failed: ${error instanceof Error ? error.message : 'unknown error'}`);
          warnings.push('use REA MCP managed inspection/reconstruction (mcp__rea__inspect_managed_*) for .NET');
          level = 'S4';
          reason = 'managed assembly identified but no local C# decompiler or metadata reader succeeded';
        }
      }
    } else if (identification.family === 'native') {
      if (tools.objdump?.available === true) {
        const run = await runTool('objdump', ['-d', options.input], { timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: 8 * 1024 * 1024, signal: options.signal });
        actions.push({ backend: 'objdump', code: run.code, truncated: run.truncated, bytes: run.stdout.length });
        if (run.code === 0 && run.stdout.length > 0) {
          const file = await writeTextFile(outputDir, 'disassembly.txt', run.stdout + (run.truncated ? '\n; TRUNCATED BY OUTPUT LIMIT\n' : ''));
          actions.push({ backend: 'file', ...file });
          level = 'S3';
          reason = 'disassembly recovered; native source is not recoverable locally (use REA/Ghidra for S2 pseudo-code)';
        }
      } else {
        warnings.push('no disassembler installed; use REA MCP native tools');
      }
      if (tools.strings?.available === true) {
        const run = await runTool('strings', [options.input], { timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: 4 * 1024 * 1024, signal: options.signal });
        if (run.code === 0 && run.stdout.length > 0) {
          const file = await writeTextFile(outputDir, 'strings.txt', run.stdout);
          actions.push({ backend: 'strings', ...file });
        }
      }
    } else if (identification.family === 'firmware') {
      const fw = await extractFirmware(options.input, outputDir, limits);
      actions.push({ backend: 'builtin-firmware', findings: fw.findings, extracted: fw.extracted.length, signatures: fw.signatures });
      if (fw.findings.length > 0) {
        level = 'S3';
        reason = `carved ${fw.findings.length} embedded firmware payload(s): ${fw.findings.map((entry) => entry.type).join(', ')}`;
      } else {
        warnings.push('no carvable gzip/ZIP/CPIO/tar payload found; install binwalk/unblob for deeper firmware extraction');
        level = 'S3';
        reason = 'firmware identified; no source form is recoverable from compiled firmware';
      }
      if (tools.strings?.available === true) {
        const run = await runTool('strings', [options.input], { timeoutMs: options.config.backendTimeoutMs, maxOutputBytes: 4 * 1024 * 1024, signal: options.signal });
        if (run.code === 0 && run.stdout.length > 0) {
          const file = await writeTextFile(outputDir, 'strings.txt', run.stdout);
          actions.push({ backend: 'strings', ...file });
        }
      }
      warnings.push('firmware extraction recovers files/configs, not original source; source recovery is usually impossible');
    } else if (identification.family === 'archive') {
      const raw = await extractByKind(options.input, identification.kind, outputDir, limits);
      actions.push({ backend: 'builtin-archive', files: raw.files.length, bytes: raw.bytes });
      level = 'S3';
      reason = 'container extracted; contents may include source but were not decompiled';
    } else if (identification.family === 'text') {
      const copy = await fsp.readFile(options.input);
      const target = safeJoin(outputDir, safeSegments(path.basename(options.input)));
      await fsp.writeFile(target, copy, { flag: 'wx', mode: 0o600 });
      const sourceExt = /\\.(ts|tsx|jsx|cs|java|kt|kts|c|cc|cpp|h|hpp|py|rb|go|rs|swift|php|sh|ps1)$/i.test(options.input);
      actions.push({ backend: 'builtin-text', file: path.basename(options.input) });
      level = sourceExt ? 'S0' : 'S3';
      reason = sourceExt ? 'shipped source text copied verbatim (exact source)' : 'text/config content copied; it is not source code';
    } else {
      throw new RecoveryError('E_UNSUPPORTED', 'target family is not supported by any local backend', { exitCode: 4 });
    }
    const tree = await countTree(outputDir);
    return {
      input: options.input,
      sha256: identification.sha256,
      family: identification.family,
      kind: identification.kind,
      authorizationNote: options.authorizationNote ?? '',
      level,
      levelName: LEVELS[level].name,
      levelDescription: LEVELS[level].description,
      reason,
      actions,
      warnings,
      plan,
      outputDir,
      output: tree,
      evidence: {
        observed: ['target hash and structure', ...actions.map((action) => `backend:${action.backend}`)],
        inferred: [`recovery level ${level}`],
        unknown: level === 'S0' || level === 'S1' ? ['build settings', 'original repository layout'] : ['original source text', 'symbols removed at build time'],
      },
    };
  } catch (error) {
    const tree = await countTree(outputDir);
    if (tree.files === 0) await fsp.rm(outputDir, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

export { countTree, findFiles };
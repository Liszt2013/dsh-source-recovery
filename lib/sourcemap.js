/** Recover original sources from source maps (the only reliable S0 path for JS). */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { safeJoin, safeSegments } from './archive.js';

function decodeDataUrl(url) {
  const match = /^data:application\/json(?:;charset=[^;,]+)?(;base64)?,(.*)$/s.exec(url);
  if (match === null) return null;
  return match[1] === ';base64' ? Buffer.from(match[2], 'base64').toString('utf8') : decodeURIComponent(match[2]);
}

/** Find a sourceMappingURL comment (inline data URL or relative file). */
export async function findSourceMap(jsPath) {
  const stat = await fsp.stat(jsPath);
  const handle = await fsp.open(jsPath, 'r');
  try {
    const length = Math.min(stat.size, 4 * 1024 * 1024);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, stat.size - length);
    const text = buffer.toString('utf8');
    const matches = [...text.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g)]
      .concat([...text.matchAll(/\/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*\//g)]);
    if (matches.length === 0) return null;
    return matches[matches.length - 1][1];
  } finally {
    await handle.close();
  }
}

export async function loadSourceMap({ mapPath, jsPath, allowedRoots }) {
  if (typeof mapPath === 'string') {
    const text = await fsp.readFile(mapPath, 'utf8');
    return { text, origin: mapPath };
  }
  if (typeof jsPath !== 'string') throw new RecoveryError('E_ARGS', 'provide mapPath or jsPath');
  const reference = await findSourceMap(jsPath);
  if (reference === null) throw new RecoveryError('E_NO_SOURCEMAP', 'no sourceMappingURL was found in the JavaScript file');
  const inline = decodeDataUrl(reference);
  if (inline !== null) return { text: inline, origin: 'inline-data-url' };
  const absolute = path.resolve(path.dirname(jsPath), reference);
  const real = await fsp.realpath(absolute).catch(() => {
    throw new RecoveryError('E_IO', 'referenced source map does not exist');
  });
  if (Array.isArray(allowedRoots) && allowedRoots.length > 0) {
    const contained = allowedRoots.some((root) => {
      const relative = path.relative(root, real);
      return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
    });
    if (!contained) throw new RecoveryError('E_PATH_OUTSIDE_ROOT', 'referenced source map is outside the allowed roots');
  }
  const text = await fsp.readFile(real, 'utf8');
  return { text, origin: real };
}

function sanitizeSourceName(source, index) {
  let value = String(source).replace(/\\/g, '/');
  value = value.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]*\//, '');
  value = value.replace(/^(webpack|rollup|vite|file):\/\//, '');
  value = value.replace(/^\/+/, '');
  const segments = [];
  for (const segment of value.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') continue;
    segments.push(segment.replace(/[\0<>:"|?*]/g, '_').slice(0, 200));
  }
  if (segments.length === 0) return `source-${index}.txt`;
  return segments.join('/');
}

/**
 * Recover original sources into outputDir. Returns level S0 only when
 * sourcesContent supplied at least one non-empty original file.
 */
export async function recoverSources({ mapPath, jsPath, outputDir, allowedRoots, maxBytes = 64 * 1024 * 1024 }) {
  const loaded = await loadSourceMap({ mapPath, jsPath, allowedRoots });
  if (loaded.text.length > maxBytes) throw new RecoveryError('E_LIMIT', 'source map exceeds the configured limit');
  let parsed;
  try {
    parsed = JSON.parse(loaded.text);
  } catch {
    throw new RecoveryError('E_SOURCEMAP_INVALID', 'source map is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || parsed.version !== 3 || !Array.isArray(parsed.sources)) {
    throw new RecoveryError('E_SOURCEMAP_INVALID', 'not a version 3 source map with a sources array');
  }
  const root = typeof parsed.sourceRoot === 'string' ? parsed.sourceRoot : '';
  const contents = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];
  const written = [];
  const missing = [];
  const used = new Set();
  for (let index = 0; index < parsed.sources.length; index += 1) {
    const original = `${root}${parsed.sources[index] ?? ''}`;
    let relative = sanitizeSourceName(original, index);
    if (used.has(relative)) relative = `${index}-${relative}`;
    used.add(relative);
    const content = contents[index];
    if (typeof content !== 'string' || content.length === 0) {
      missing.push(original);
      continue;
    }
    const target = safeJoin(outputDir, safeSegments(relative));
    await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fsp.writeFile(target, content, { flag: 'wx', mode: 0o600 });
    written.push({ path: relative, bytes: Buffer.byteLength(content), original });
  }
  const manifest = {
    mapOrigin: loaded.origin,
    sources: parsed.sources.length,
    recovered: written.length,
    missing,
    names: Array.isArray(parsed.names) ? parsed.names.length : 0,
    hasSourcesContent: contents.some((entry) => typeof entry === 'string' && entry.length > 0),
    mappingsBytes: typeof parsed.mappings === 'string' ? parsed.mappings.length : 0,
  };
  await fsp.writeFile(path.join(outputDir, 'sourcemap-manifest.json'), JSON.stringify(manifest, null, 2), { flag: 'wx', mode: 0o600 });
  return {
    ...manifest,
    files: written,
    level: written.length > 0 ? 'S0' : 'S3',
    note: written.length > 0
      ? 'sourcesContent supplied original text; this is the strongest recovery level'
      : 'the map references sources but contains no sourcesContent; only mappings and names were recovered',
  };
}

/** Source-recovery taxonomy. Never present a lower level as recovered source. */
export const LEVELS = Object.freeze({
  S0: {
    id: 'S0',
    name: 'exact-source',
    description: 'Original source bytes or original source files recovered (embedded source maps with sourcesContent, or shipped source).',
  },
  S1: {
    id: 'S1',
    name: 'near-source',
    description: 'Decompiled source (Java/Kotlin, C#, JS/TS-like) with compiler transformations, lost comments/types or renamed symbols.',
  },
  S2: {
    id: 'S2',
    name: 'pseudo-source',
    description: 'Algorithmic pseudo-code from a native decompiler; useful for logic recovery, not compilable original source.',
  },
  S3: {
    id: 'S3',
    name: 'assembly-metadata',
    description: 'Disassembly, strings, resources, manifests, metadata and protocol observations; no source form.',
  },
  S4: {
    id: 'S4',
    name: 'behavior-only',
    description: 'Observed behavior only; internals remain unknown.',
  },
});

export const TARGET_FAMILIES = Object.freeze([
  {
    id: 'apk',
    title: 'Android APK / DEX / resources',
    markers: ['AndroidManifest.xml', 'classes*.dex'],
    bestLocal: 'S1', bestWithRea: 'S1',
    backends: ['jadx', 'apktool'],
    note: 'jadx yields Java/Kotlin source; apktool yields smali and decoded resources. Neither recovers original Kotlin/Java source exactly.',
  },
  {
    id: 'dotnet',
    title: '.NET / managed assembly',
    markers: ['PE + CLR metadata'],
    bestLocal: 'S3', bestWithRea: 'S1',
    backends: ['ilspycmd', 'rea-managed'],
    note: 'ILSpy-class decompilers reconstruct C# near-source; local ilspycmd not installed, REA MCP managed tools are the expected path.',
  },
  {
    id: 'native',
    title: 'Native PE / ELF / Mach-O',
    markers: ['MZ/PE', '\\x7fELF', 'Mach-O'],
    bestLocal: 'S3', bestWithRea: 'S2',
    backends: ['objdump', 'readelf', 'strings', 'ghidra', 'rea-native'],
    note: 'Optimized native code generally cannot be turned back into original source. Local tools disassemble; REA/Ghidra decomposes to pseudo-C.',
  },
  {
    id: 'electron',
    title: 'Electron / ASAR / JavaScript',
    markers: ['ASAR header', 'sourceMappingURL', '.js'],
    bestLocal: 'S3', bestWithRea: 'S0',
    backends: ['builtin-asar', 'builtin-sourcemap', 'node'],
    note: 'Embedded source maps with sourcesContent are the only reliable exact-source path; ASAR usually contains bundled JS, not original TS/JSX.',
  },
  {
    id: 'firmware',
    title: 'Firmware / embedded images',
    markers: ['hsqs', 'UBI#', '\\x27\\x05\\x19\\x56', 'uImage', 'TRX'],
    bestLocal: 'S3', bestWithRea: 'S3',
    backends: ['binwalk', 'unblob', 'strings'],
    note: 'Firmware extraction recovers files and configs, rarely source. Encryption/compression may prevent extraction entirely.',
  },
  {
    id: 'archive',
    title: 'JAR / ZIP / TAR / GZIP',
    markers: ['PK\\x03\\x04', 'ustar', '\\x1f\\x8b'],
    bestLocal: 'S3', bestWithRea: 'S3',
    backends: ['builtin-archive'],
    note: 'Extraction preserves contained artifacts (including source if shipped); it is not decompilation.',
  },
  {
    id: 'malware',
    title: 'Suspicious sample / forensic artifact',
    markers: ['any identified executable/archive'],
    bestLocal: 'S3', bestWithRea: 'S2',
    backends: ['static-only'],
    note: 'Static analysis only. The plugin never executes a target, never detonates it and never contacts C2 infrastructure.',
  },
]);

export const RECOVERY_POLICY = Object.freeze({
  authorizationRequired: true,
  executionOfTargets: false,
  networkAccess: false,
  externalToolInvocation:
    'only fixed trusted toolchain CLIs (jadx, apktool, objdump, readelf, strings, ilspycmd, binwalk, unblob, ghidra, dotnet) with structured argv, timeouts, output caps and no shell',
  evidenceTags: ['observed', 'derived', 'inferred', 'unknown'],
});

export function levelFor(familyId, backendAvailable = {}) {
  const family = TARGET_FAMILIES.find((entry) => entry.id === familyId);
  if (family === undefined) return { level: 'S4', reason: 'unknown target family' };
  if (familyId === 'apk' && backendAvailable.jadx === true) return { level: 'S1', reason: 'jadx Java/Kotlin decompilation available' };
  if (familyId === 'apk' && backendAvailable.apktool === true) return { level: 'S1', reason: 'apktool smali/resources available (not Java source)' };
  if (familyId === 'electron' && backendAvailable.sourcemap === true) return { level: 'S0', reason: 'source maps with sourcesContent are recoverable' };
  if (familyId === 'dotnet' && backendAvailable.ilspycmd === true) return { level: 'S1', reason: 'ILSpy-class decompilation available' };
  if (familyId === 'native' && backendAvailable.objdump === true) return { level: 'S3', reason: 'disassembly available; no native source decompiler locally' };
  if (familyId === 'firmware' && (backendAvailable.binwalk === true || backendAvailable.unblob === true)) return { level: 'S3', reason: 'firmware extraction available; source is not recoverable from compiled firmware' };
  return { level: family.bestLocal === 'S0' ? 'S3' : family.bestLocal, reason: 'best available local ceiling; see backends' };
}

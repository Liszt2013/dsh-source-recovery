# Three complete examples

All examples are local, offline and assume you own or are authorized to analyze
the target. Recovery commands require `--authorized`.

## 1. JavaScript source map → exact source (S0)

```powershell
# bundle.js ends with: //# sourceMappingURL=bundle.js.map
# bundle.js.map contains sources + sourcesContent
node bin/cli.js sourcemap --js .\bundle.js --out .\recovered --authorized --json
```

Expected:

```json
{ "ok": true, "level": "S0", "sources": 2, "recovered": 2, "outputDir": "...\\recovered" }
```

Result: `recovered/src/app.ts`, `recovered/src/util.ts`, plus
`sourcemap-manifest.json`. If the map has no `sourcesContent`, the level is
`S3` and only mappings/metadata are recovered.

## 2. Native binary → disassembly (S3, not source)

```powershell
gcc -O1 -o .\sample.exe .\sample.c
dsh-source-recovery .\sample.exe --output .\out --authorized --report .\report.md
```

Expected (minimal form):

```text
native/pe → level S3 (assembly-metadata)
output C:\...\out
disassembly recovered; native source is not recoverable locally (use REA/Ghidra for S2 pseudo-code)
report C:\...\report.md
```

Artifacts: `out/disassembly.txt`, `out/strings.txt`, `report.md`, `report.json`.
For pseudo-C (S2) install Ghidra or use the REA MCP (`mcp__rea__analyze_function`).

## 3. APK → Java source + resources (S1)

```powershell
dsh-source-recovery .\authorized-app.apk --output .\apk-out --authorized --report .\apk-report.md
```

Expected:

```text
apk/apk → level S1 (near-source)
output C:\...\apk-out
jadx produced N Java/Kotlin files; apktool also decoded M smali files/resources
```

Artifacts: `apk-out/jadx/sources/**/*.java`, `apk-out/apktool/smali*/`, decoded
`AndroidManifest.xml` and resources. JADX and apktool run together by default.
If neither is installed, the plugin reports S3 raw extraction and the gap —
never a fake success.

> A synthetic APK with a real DEX compiled by Android `d8` and resources linked
> by `aapt2` is used in the test suite to verify both paths end-to-end.

## 4. Evidence bundle for handoff

```powershell
dsh-source-recovery bundle --in .\authorized-app.apk --out .\evidence.zip --artifacts .\apk-out --authorized
dsh-source-recovery verify-bundle --in .\evidence.zip
```

Expected: `VERIFIED: all declared hashes and the bundle digest match`.
The bundle contains `manifest.json`, `report.md`, `report.json` and
`artifacts/**`; every file is listed with SHA-256 and total size. Any changed
declared byte, missing file, extra entry or digest mismatch fails verification.
The digest is unkeyed: someone who rewrites the whole bundle can recompute it,
so sign the bundle externally when authenticity matters.

## 5. Firmware carving and .NET metadata (S3)

```powershell
dsh-source-recovery .\firmware.bin --output .\fw-out --authorized
dsh-source-recovery .\managed.dll --output .\dotnet-out --authorized
```

Firmware: carves gzip/ZIP/CPIO/tar payloads without binwalk.
.NET: reads CLR metadata (assembly, types, methods, user strings) without
ILSpy. Neither is original source: they are S3 metadata/artifacts. Install
binwalk/unblob or ilspycmd (or use REA MCP) for deeper recovery.

## Check the environment first

```powershell
dsh-source-recovery doctor --json
dsh-source-recovery capabilities --json
```

# Compatibility

## Baseline (verified locally)

| Component | Value |
|---|---|
| DSH | `0.2.2-rc.5` |
| Plain Node (CLI/tests) | `v24.22.1` |
| DSH Desktop host (Electron Node) | `v24.21.0` (from doctor) |
| Plugin | `dsh-source-recovery@0.2.0` |
| Host APIs | `ctx.tools.register`, `ctx.skills.register`, `ctx.get('webServer').register`, `ctx.effect` |
| Client | `window.__ModuleLoader__.load`, `ctx.slots.inject/register`, `sidebar.panellist` + keyed `main` |
| Bundle | `package.json.dsh.bundle.patch` → `cordis.patch.yml` insert row; `dsh.plugin.json` |
| Runtime deps | none |
| OS tested | Windows 10 19045 |

## Backends on this host

| Backend | Installed | Effect |
|---|---|---|
| jadx | yes (1.5.6) | APK/JAR/DEX → Java (S1) |
| apktool | yes | APK → smali/resources (S1) |
| objdump/readelf/strings | yes (MinGW) | native disassembly/strings (S3) |
| java / dotnet / python / node | yes | backend runtimes / built-in handlers |
| ilspycmd | no | .NET S1 requires ILSpy-class tooling or REA MCP; the built-in CLR metadata reader gives S3 (assembly/types/methods/strings) |
| ghidra | no | native S2 unavailable locally → use REA MCP |
| binwalk/unblob | no | firmware S3 via built-in gzip/ZIP/CPIO/tar carving plus strings; exotic filesystems need external tools |

## Target families

- APK/JAR/DEX, JS/Electron/ASAR/source maps, PE/ELF/Mach-O, .NET metadata,
  ZIP/GZIP/TAR, firmware signatures, suspicious samples (static only).
- 7z/RAR/XZ/BZ2 and ZIP64/multi-disk are detected but not extracted by the
  built-in extractor; use a trusted external tool.

## Compatibility caveats

- Extracted archives may use formats the built-in extractor does not support;
  this is reported explicitly, never silently skipped.
- JADX/apktool output shape varies by version; the plugin checks produced files
  and otherwise reports a gap.
- REA MCP is detected from installed `dsh-rea`; host code does not call MCP
  tools. The model invokes `mcp__rea__*` directly.

## v0.2.0 capabilities

- Evidence bundles: stored ZIP with manifest.json, report.md/report.json, SHA-256 per artifact and a bundle digest; verify-bundle recomputes every hash.
- Output locks: one writer per output path across processes; stale locks from a dead PID older than one hour are reclaimed.
- Cancellation: tool exec.signal and CLI SIGINT are forwarded to trusted backends; backend timeouts remain enforced.
- JSON Schema: schemas/envelope.schema.json, schemas/report.schema.json, schemas/evidence.schema.json.
- .NET: built-in CLR metadata reader (S3); firmware: built-in gzip/ZIP/CPIO/tar carving (S3).
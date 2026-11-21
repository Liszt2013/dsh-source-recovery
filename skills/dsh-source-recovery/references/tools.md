# Tools and delegation

## Built-in (no installation)`n`n- firmware carving: gzip/ZIP/CPIO/tar payload extraction`n- .NET CLR metadata: assembly, types, methods, user strings (S3)`n- evidence bundles: hash-verified ZIP + independent verification`n- output locks, stale-lock recovery, backend timeouts and cancellation

- identification (PE/ELF/Mach-O/ZIP/APK/ASAR/GZIP/TAR/JS/source maps)
- safe ZIP/ASAR/GZIP/TAR extraction
- source-map source recovery
- evidence reports

## Optional trusted CLIs

| Tool | Enables | Local state (this machine) |
|---|---|---|
| `jadx` | APK/DEX Java/Kotlin source (S1) | installed |
| `apktool` | APK resources + smali (S1), runs alongside JADX by default | installed |
| `objdump` / `readelf` / `strings` | native disassembly (S3) | installed (MinGW) |
| `ilspycmd` | .NET C# (S1); built-in metadata reader gives S3 without it | not installed |
| `ghidra/analyzeHeadless` | native pseudo-C (S2) | not installed |
| `binwalk` / `unblob` | firmware extraction (S3) | not installed |
| `java` / `dotnet` | backend runtimes | installed |

Install hints are operator decisions; this plugin never downloads or installs tools.

## REA MCP delegation

When REA is installed (`dsh-rea`), use its model tools for deeper work:

- Native: `mcp__rea__open_binary`, `mcp__rea__analyze_function`, `mcp__rea__decompile`-family tools, `mcp__rea__get_call_graph`.
- .NET: `mcp__rea__inspect_managed_artifact`, `mcp__rea__inspect_managed_members`, `mcp__rea__import_managed_reconstruction`.
- APK: `mcp__rea__inspect_android_package`, `mcp__rea__inspect_android_class`, `mcp__rea__decompile_jeb_item`.
- Firmware/browser/JS: the corresponding `mcp__rea__*` tools.

The plugin only **detects** REA; host code does not call MCP tools. The model orchestrates them.

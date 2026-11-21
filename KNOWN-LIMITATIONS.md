# Known limitations

> Revision note (fixed in 0.2.0): the earlier 0.1.0 build registered its runtime skill without a `source` string, so DSH failed to load it with `loaded skill "..." source must be a string`. Fixed in this revision; the acceptance suite now loads the skill through DSH's own `SkillRegistry`.

1. **"Source" is often impossible.** Optimized native binaries, obfuscated
   managed code, stripped firmware and minified bundles without source maps do
   not contain original source. The plugin reports S1–S4 honestly.
2. **APK resources are decoded with apktool when installed.** The suite builds a real APK with `d8` + `aapt2` and verifies both JADX Java (S1) and apktool smali/resources (S1). Highly obfuscated or split APKs may still fail partially; the achieved level is reported honestly.
3. **.NET C# decompilation needs ILSpy-class tooling or REA.** The built-in CLR metadata reader recovers assembly identity, type/method names and user strings (S3) without dependencies; it does not reconstruct C# source.
4. **Native pseudo-code (S2) is unavailable locally** (no Ghidra/REA native in this plugin process); objdump gives S3 disassembly. Use REA/Ghidra for S2.
5. **Firmware extraction is built-in only for gzip/ZIP/CPIO/tar payloads.** SquashFS, UBI, JFFS2 and encrypted firmware need binwalk/unblob/vendor tooling; no source is recoverable from compiled firmware.
6. **No 7z/RAR/XZ/BZ2/ZIP64 extraction.** Detection only; documented gap.
7. **No dynamic analysis.** No execution, no sandbox detonation, no Frida, no
   network capture. Those require separate authorized tooling.
8. **Evidence bundles are integrity, not authenticity.** They hash files and
   bind a digest, but are unsigned. A party who can rewrite the whole bundle can
   produce a new self-consistent bundle; sign it externally if provenance matters.
9. **REA MCP is not called by host code.** The plugin detects it; the model must
   invoke `mcp__rea__*` tools itself.
10. **Workbench is read-only** and shows no target paths or contents; operations
    go through tools/CLI.
11. **No browser visual regression** in this environment; the client graph and
    bundle are verified via acceptance, not screenshots.
12. **Only Windows was executed locally.** Linux/macOS behavior is expected but
    not executed in this run; APK/.NET/firmware backends vary by host.
13. **Package is `private`** and not published. Tarball is unsigned; verify its
    SHA-256 manually.
14. **Same-process plugin isolation is out of scope.** DSH approvals are not a
    sandbox for malicious plugins.
15. **Multi-header ASAR archives** are parsed as one header; unusual Electron
    packaging may need external extraction.
16. **Output locks are advisory** to this plugin, not OS mandatory locks, and a
    non-cooperative child can delay teardown until the kill signal is processed.

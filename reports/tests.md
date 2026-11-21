# Test report

Generated: 2026-11-21T08:21:22.597Z

| Status | Count |
|---|---:|
| passed | 22 |
| failed | 0 |
| skipped | 0 |
| unavailable | 0 |

- **passed** — core :: identify distinguishes JS, ZIP, APK-like ZIP, ASAR, PE and .NET without executing
- **passed** — core :: safe ZIP extraction round-trips and rejects traversal, symlink and encryption
- **passed** — core :: ASAR extraction and source-map recovery reach S0 only with sourcesContent
- **passed** — core :: GZIP extraction and text recovery work; report writes JSON+Markdown
- **passed** — core :: evidence bundle is portable, hash-verified and detects tampering
- **passed** — core :: firmware carving extracts embedded gzip and CPIO payloads without binwalk
- **passed** — core :: concurrent writers to one output directory are rejected, not interleaved
- **passed** — core :: unauthorized operations fail before any backend; unknown or unsafe paths fail closed
- **passed** — core :: self-test passes with zero failures and no external backend requirement
- **passed** — integration :: plugin registers ten strict reverse_* tools, the skill and four loopback routes
- **passed** — integration :: workbench routes are loopback same-origin, read-only and JSON
- **passed** — integration :: tool execution returns envelopes and enforces authorization without throwing
- **passed** — integration :: CLI emits stable JSON and correct authorization exit codes
- **passed** — integration :: Windows .bat/.cmd toolchains are launched through cmd.exe, not spawned directly
- **passed** — integration :: real JADX decompiles a compiled JAR to Java source (S1)
- **passed** — integration :: real APK (real DEX) decompiles with JADX to Java source (S1)
- **passed** — integration :: real objdump recovers disassembly (S3) without claiming source
- **passed** — integration :: real objdump recovers disassembly from a real ELF binary (S3)
- **passed** — integration :: real APK resources decode with apktool alongside JADX (S1)
- **passed** — integration :: built-in .NET CLI metadata recovers assembly, types, methods and strings (S3)
- **passed** — integration :: documentation and packaged files match code
- **passed** — integration :: repository contains no private keys or long embedded credentials

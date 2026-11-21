# Third-party notices

`dsh-source-recovery` contains **no third-party source code** and no runtime npm
dependencies. It invokes optional, separately installed toolchains.

## Optional toolchains (not bundled, not installed by this plugin)

| Tool | Role | License (upstream) |
|---|---|---|
| JADX | APK/DEX/JAR → Java | Apache-2.0 |
| apktool | APK resources/smali | Apache-2.0 |
| ILSpy / ilspycmd | .NET → C# | MIT |
| Ghidra | native decompiler | Apache-2.0 |
| binutils (objdump/readelf/strings) | native inspection | GPL-3.0 |
| binwalk / unblob | firmware extraction | MIT / MIT |
| Node.js | runtime | MIT |
| REA / dsh-rea | optional MCP reverse-engineering tools | see upstream project |

The plugin does not redistribute these binaries. Operators install and trust
their own toolchains.

## Specifications referenced

ELF, PE/COFF, Mach-O, ZIP/APK, Electron ASAR, Source Map v3, gzip/tar and UBI /
SquashFS / uImage magic numbers are public formats. No vendor code was copied.

## Ideas studied

The recovery-level taxonomy (S0–S4), evidence tags and authorization workflow
were informed by general reverse-engineering practice and the installed
`reverse-engineering` skill. The implementation, protocol and UI are original.

## Trademarks

DeepSeek Harness, Android, Java, .NET, Electron, Ghidra, JADX, apktool, ILSpy,
IDA and other names belong to their owners; this project is not endorsed by them.

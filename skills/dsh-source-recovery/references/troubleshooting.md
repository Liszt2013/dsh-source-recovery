# Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `E_AUTHZ_REQUIRED` | `authorized` was not true | Only pass `authorized: true` for a target you may analyze. |
| `E_PATH_OUTSIDE_ROOT` | target/output is outside allowed roots | Use the session workspace or set `DSH_SOURCE_RECOVERY_ROOTS`. |
| `E_BACKEND_UNAVAILABLE` | jadx/apktool/ilspycmd/objdump missing | Install the toolchain yourself or use REA MCP tools; do not fake a level. |
| `E_ARCHIVE_UNSAFE` | path traversal, symlink or drive path in archive | Keep the rejection; do not retry with a permissive extractor. |
| `E_ARCHIVE_ENCRYPTED` | ZIP password protection | Built-in extraction does not crack archives; report the gap. |
| `E_ARCHIVE_BOMB` | extreme compression ratio | Inspect metadata only; do not force extraction. |
| `E_NO_SOURCEMAP` | JS has no map | Copy the bundle and report S3; use REA web/JS tools for deeper mapping. |
| `E_SOURCEMAP_INVALID` | malformed map | Validate with a dedicated tool; report S3. |
| path is redacted in doctor | intentional | Paths stay local; use the absolute path in your own command, not in reports. |
| jadx output empty | obfuscated/unsupported DEX | Try apktool smali, then REA/JEB; report the achieved level honestly. |
| native target yields no source | expected | objdump is S3; use Ghidra/REA for S2 pseudo-code, never call it original source. |

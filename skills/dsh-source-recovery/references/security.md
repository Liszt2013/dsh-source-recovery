# Security and authorization

## Required

- Analyze only targets you own or are explicitly authorized to analyze.
- All mutating recovery commands require `authorized: true` / `--authorized`.
- Prefer an offline copy; for malware use an isolated analysis host.
- Keep extracted artifacts local; treat them as untrusted executable content.

## Never

- execute the target, macros, installers or scripts found inside it;
- bypass licensing, DRM, authentication or access controls;
- steal credentials or personal data;
- upload samples or reports to third parties without explicit approval;
- run remote installers or `curl | sh`;
- claim original source for decompiled/pseudo output.

## Boundaries

- The plugin runs inside the DSH host process; tool approval does not isolate malicious same-process plugins.
- Backend CLIs (jadx, apktool, ILSpy, Ghidra) are trusted local processes started with fixed argv, no shell, a whitelisted environment, timeouts and output caps. If one is replaced on `PATH`, that is outside the plugin boundary.
- Extraction rejects traversal, absolute/drive paths, symlinks, encrypted ZIP members, suspicious compression ratios, oversize members and overwrite.
- No network, no telemetry, no automatic installs, no target execution.
- Reports hash targets and summarize artifacts; they do not embed file contents or secrets.

# Acceptance report

Generated: 2026-11-21T08:23:30.305Z

- Plugin: 0.2.0
- Tarball: C:\Users\XPS\Documents\deepseek-harness\default-workspace\dsh-source-recovery\dsh-source-recovery-0.2.0.tgz
- SHA-256: 9cb1350590ac0a2118c5d89e5f6c615d893fe2e0bba6ad7881a0c2b04f50cc2b
- Steps: {"passed":12,"failed":0,"total":12}
- Skill load: {"ok":true,"name":"dsh-source-recovery","source":"bundled","provider":"dsh-source-recovery","contentBytes":3583,"summaryCount":1}
- Evidence bundle: {"artifactCount":1,"sha256":"5d35e85cc9dc92503fe3cd0073700381d76b4887a5f5052ee71ccc8fb3bd3ef0","verified":3}

| Step | Status | Detail |
|---|---|---|
| toolchain | passed | dsh 0.2.2-rc.5; node v24.22.1 |
| pack | passed | dsh-source-recovery-0.2.0.tgz sha256=9cb1350590ac0a21… |
| install | passed | tarball installed into isolated DSH_HOME |
| compose | passed | plugin present in composed profile |
| client-bundle | passed | client.js 12339 bytes |
| skill-load | passed | DSH SkillRegistry loaded "dsh-source-recovery" (source=bundled, 3583 bytes) |
| boot | passed | web profile booted on http://127.0.0.1:50916 |
| http-health | passed | plugin 0.2.0, toolCount=10 |
| http-routes | passed | {"capabilities":{"status":200,"bytes":5974,"families":7},"doctor":{"status":200,"bytes":3084},"selftest":{"status":200,"bytes":1324,"counts":{"passed":9,"failed":0,"unavailable":0} |
| http-client | passed | client bundle served (2037248 bytes); Reverse entry in boot graph |
| installed-cli | passed | self-test {"passed":9,"failed":0,"unavailable":0}; identify electron; report and hash-verified evidence bundle |
| uninstall | passed | plugin removed; composed profile and package.json are clean |

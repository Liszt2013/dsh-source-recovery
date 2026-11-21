# dsh-source-recovery

> 万物皆可逆向，但要如实标注恢复到了哪一层。左侧栏 **Reverse** 工作台 + 八个 `reverse_*` 工具 + 按需加载 Skill + 可安装 DSH 插件。

- 包名/Bundle 名：`dsh-source-recovery`（npm 未占用，GitHub 无同名项目）
- 基线：DSH `0.2.2-rc.5`、Node `>=22.19.0`
- 许可证：MIT；无运行时 npm 依赖
- 目标：**尽可能把目标恢复到源码层**，覆盖 APK、JS/Electron、.NET、原生 PE/ELF/Mach-O、固件、压缩包与可疑样本

## 恢复等级（绝不混淆）

| 等级 | 含义 | 典型来源 |
|---|---|---|
| S0 | 精确源码 | source map 的 `sourcesContent`、随包发布的源码文本 |
| S1 | 近似源码 | JADX Java/Kotlin、apktool smali/资源、ILSpy C# |
| S2 | 伪代码 | Ghidra/REA 对原生代码的 pseudo-C |
| S3 | 汇编/元数据 | objdump、readelf、strings、ZIP/ASAR 内容 |
| S4 | 仅行为 | 动态观察；内部未知 |

**原生优化后的二进制通常无法还原为原始源码。** 本插件不会把 S1/S2/S3 冒充为“源码”。

## 最小 CLI（P0）

```powershell
dsh-source-recovery .\app.apk --output .\out --authorized --report .\report.md
dsh-source-recovery .\app.asar --output .\out --authorized
dsh-source-recovery doctor --json
dsh-source-recovery capabilities --json
```

## 安装

```powershell
cd dsh-source-recovery
npm pack
$env:DSH_HOME = "C:\temp\dsh-source-recovery-accept"
dsh plugin --profile web add "C:\path\to\dsh-source-recovery-0.2.0.tgz"
dsh --profile web --no-open --port 8080
```

左侧栏出现 **Reverse**，主面板为只读工作台（能力矩阵、工具链、自检、策略）。

## 工具

| 工具 | 作用 |
|---|---|
| `reverse_capabilities` | 目标家族、S0–S4、本机工具链、REA 检测 |
| `reverse_doctor` | jadx/apktool/objdump/strings/ilspycmd/binwalk/ghidra 等探测（路径脱敏） |
| `reverse_identify` | 哈希、magic、家族、架构、熵、字符串统计、容器成员、恢复计划 |
| `reverse_extract` | 安全解包 ZIP/APK/JAR/ASAR/GZIP/TAR（防穿越/符号链接/加密/炸弹/覆盖） |
| `reverse_decompile` | 按家族恢复：APK→JADX/apktool，.NET→ILSpy，原生→objdump，Electron→ASAR+sourcemap，固件→strings |
| `reverse_sourcemap` | 从 `.map` 或 JS 内联 map 恢复原始源码；有 `sourcesContent` 才是 S0 |
| `reverse_report` | 生成 Markdown + JSON 证据报告（哈希、上限、计划、缺口、未知项） |
| `reverse_bundle` | 生成可移交证据包 ZIP：哈希清单、报告、工具版本、恢复等级/缺口、可选 artifacts；哈希链可独立校验 |
| `reverse_verify` | 独立校验证据包：缺失/大小/哈希/摘要/未声明 artifact 全部报告；不信任包内声明 |
| `reverse_selftest` | 无目标、无秘密的确定性自检 |

## 世界级能力（v0.2.0）

- **固件内置取证**：不依赖 binwalk/unblob，自动雕刻并安全提取固件中的 gzip、ZIP、CPIO、tar 负载（大小/比例/条目限制）。
- **.NET 内置元数据恢复**：无需 ILSpy 即可解析 CLR metadata，恢复程序集名/版本、类型、方法名、User Strings（S3）；安装 ILSpy 或走 REA 才到 S1。
- **APK 双后端**：JADX 产出 Java/Kotlin（S1），apktool 同时产出 smali/资源/解码 Manifest（S1），真实 APK 测试通过。
- **证据链**：`reverse_bundle`/`verify-bundle` 对目标、报告、每个 artifact 做 SHA-256 清单与 bundle digest 校验；任何缺失/大小/哈希/摘要/未声明文件都会失败。注意：无密钥签名时可被整体重写并重算摘要，真实性需外部签名。
- **并发/超时/取消**：输出目录跨进程锁、陈旧锁回收、后端超时、工具 AbortSignal 取消、CLI Ctrl-C 取消。
- **版本化 JSON Schema**：`schemas/envelope.schema.json`、`report.schema.json`、`evidence.schema.json`。
- **诚实分级**：S0–S4，缺后端只报缺口，不把 S1/S2/S3 冒充源码；不执行目标、不联网、不上传样本。

## CLI

```text
dsh-source-recovery identify --in target --json
dsh-source-recovery decompile --in target --out out-dir --authorized
dsh-source-recovery sourcemap --js bundle.js --out sources --authorized
dsh-source-recovery report --in target --out report.md --authorized
dsh-source-recovery bundle --in target --out evidence.zip --artifacts out --authorized
dsh-source-recovery verify-bundle --in evidence.zip
dsh-source-recovery doctor --json
```

恢复/写盘类命令必须显式 `--authorized`；授权只应针对你有权分析的目标。

## 安全边界

- 仅限授权目标；不提供破解授权、DRM、付费墙或凭据窃取。
- **从不执行被分析目标**；不自动下载、不联网、不上传样本。
- 外部工具链（jadx/apktool/ILSpy/Ghidra）以固定 argv、无 shell、环境白名单、超时和输出上限运行；若 `PATH` 上的程序被替换，超出插件边界。
- 解包产物是不可信内容，不要执行。
- 插件运行在 DSH 宿主进程内；工具审批不能隔离同进程恶意插件。
- 报告只保留哈希与摘要，不嵌入文件内容或秘密。

## 测试

```powershell
npm test                       # passed/failed/skipped/unavailable 四分类
node scripts/build.mjs         # 语法/镜像清单/自检
node scripts/pack-check.mjs    # npm pack 内容与秘密扫描
node scripts/acceptance.mjs    # 临时 DSH Profile 安装、启动、路由、CLI、卸载验收
```

机器可读报告在 `reports/`。本机实测：测试套件 **22/22 passed**；核心自检 **9/9**；真实 APK（真实 DEX + aapt2 资源）经 JADX **Java S1** + apktool **smali/资源 S1**；真实 JAR 解出 Java（S1）；真实 ELF 与 PE 经 `objdump` 反汇编（S3）；真实 .NET 程序集经内置 CLR metadata 恢复 **S3**；固件内置雕刻 gzip/CPIO **S3**；证据包创建+独立校验通过；DSH 自身 SkillRegistry 技能加载通过（source=bundled）；临时 DSH Profile 安装验收 **12/12 passed**。

## 加载修复说明（历史）

早期安装包中的 `SKILL.md` 通过 `ctx.skills.register()` 注册时缺少 `source` 字符串，DSH 技能加载器因此报 `loaded skill "..." source must be a string`。本修订为 runtime skill 显式传入 `source: "bundled"`，并增加契约测试；重新打包后重新安装即可。

## 三个完整案例

见 [examples/README.md](examples/README.md)：JS source map → S0、原生二进制 → S3、APK → S1。

## 相关文档

- [README.en.md](README.en.md)
- [THREAT-MODEL.md](THREAT-MODEL.md)、[SECURITY.md](SECURITY.md)
- [COMPATIBILITY.md](COMPATIBILITY.md)、[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md)、[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
- Skill：[skills/dsh-source-recovery/SKILL.md](skills/dsh-source-recovery/SKILL.md)

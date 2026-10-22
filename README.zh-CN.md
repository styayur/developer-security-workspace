# Developer Security Workspace

本地优先的 SARIF 与扫描器发现调查工作台。

[English](README.md) · [下载](https://github.com/styayur/developer-security-workspace/releases/latest) · [架构](docs/architecture.md) · [演示教程](docs/demo-workspace.md)

**Alpha。** 已有发布及工作流证据，但长期用户验证、升级和恢复审查仍不完整，见[成熟度依据](https://github.com/styayur/styayur/blob/main/portfolio/maturity.json)。

![真实 Windows 原生应用中的 Finding Debugger，显示 Monaco 源码与 SARIF Trace](docs/assets/desktop-trace-v1.png)

截图于 28-09-2026 从实际 Windows GNU 构建捕获，使用内置合成 Demo Workspace；证明界面和 Trace 交互，不证明外部扫描器执行或签名 MSVC 安装包验收。见[来源记录](docs/assets/README.md)。

## 核心流程与能力

1. 打开仓库或导入 SARIF 2.1.0；在 SQLite 分页发现列表中筛选。
2. 用 Monaco 打开发现，选择数据流路径并逐步查看 source / propagation / sink，以及规则、CWE、修复建议和脱敏原始证据。
3. 对比扫描的 New / Existing / Fixed / Reopened / Changed，检查 Native / Exact / Context / Relocated 匹配依据。
4. 在稳定发现身份上保存 triage 和备注，以便重新扫描后沿用。

Security IR v1 统一来源与规范化；歧义身份不会强行合并。SQLite 事务迁移保留预览版项目、历史及 triage；100 条 UI 分页、有界 IPC 和延迟原始结果读取限制交互负担。Try Demo Workspace 生成两次合成扫描，包括 SQL 注入、跨文件 Trace、修复、脱敏秘密、依赖和 IaC 示例，见[教程](docs/demo-workspace.md)。

## 扫描器范围

扫描器二进制须另行安装，DSW 不会静默下载或打包它们。

| 输入 | 支持方式与边界 |
| --- | --- |
| Semgrep | 原生 SARIF；关闭 metrics，规则/配置由用户选择 |
| Trivy | 原生 SARIF；依赖、秘密、配置、容器及许可信息 |
| TruffleHog | 可信 JSON 适配器，移除原始候选值；验证行为取决于扫描器设置 |
| Bandit | SARIF / 可信 JSON 适配器，保留规则、严重性、置信度与 CWE |
| Gitleaks 扩展 | 需显式审批的已审查离线只读 profile；原生 SARIF |
| CodeQL 等 | 导入 SARIF；CodeQL 运行时由用户提供，不捆绑完整数据库分析 |

见[扫描器详情与历史验证版本](docs/scanner-providers.md)和[扩展安全边界](docs/extension-model.md)。权限声明不等于能隔离恶意原生二进制的操作系统沙箱。

## 安装

从 [Releases](https://github.com/styayur/developer-security-workspace/releases) 下载 Windows x64 NSIS 安装器、校验和及公开证书。需要 Windows 10/11 和 WebView2。v1.x 使用自签名 Authenticode，不提供公有 CA 信任、时间戳或消除 SmartScreen 的保证；不要自动导入根证书。按[签名与校验说明](docs/release.md)核验下载。

## 源码开发与测试

使用 CI 对应的 Node.js 22、pnpm 12.4.2、stable Rust。Windows 原生开发还需 C++ Build Tools 和 WebView2。

```powershell
git clone https://github.com/styayur/developer-security-workspace.git
cd developer-security-workspace
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
pnpm tauri dev
```

Windows 桌面测试还使用 `--features desktop`。`pnpm tauri build` 生成安装器；已有 [GNU 构建脚本](scripts/build-windows-gnu.ps1)需要预装 GNU/MinGW。现有 CI 在 Ubuntu / Windows 检查前端及 Rust，Windows 另检查 desktop feature；发布与扫描器集成有独立工作流，见[操作说明](docs/release.md)。

生成合成性能输入：`node scripts/generate-large-sarif.mjs 50000 work/large-50000.sarif`。测量仅代表记录的环境，见[性能与限制](docs/performance.md)。

## 架构、安全与限制

```text
Scanner / SARIF → normalize + redact → Security IR v1
                                    → layered matcher → identity + occurrence
                                    → SQLite → paginated inbox → Monaco / trace / triage
```

React/TypeScript、Monaco、Tauri 2、Rust 与本地 SQLite，无 localhost 后端、数据库服务或 AI 匹配。源码读取限制在规范工作区；扫描器使用 executable + argv，限制日志、时间并支持取消。持久化及 UI 事件前脱敏；上下文指纹只保存哈希。DSW 无账号、遥测或云存储，外部扫描器可能有自己的联网、数据库和凭据验证行为，见[安全模型](docs/security-model.md)。

- SARIF 导入使用可取消的磁盘暂存；输入上限 1 GiB、单结果/值 2 MiB、元数据 8 MiB。扫描器机器输出上限 128 MiB，完整 Raw 查看上限 8 MiB。
- 歧义重复项不匹配；v1 不跨不同规则或冲突符号匹配。
- 扩展执行目前只支持已审查的 Gitleaks profile，任意命令/自定义转换器关闭。
- 100k 合成导入的本地 debug 测量约 1.32 GiB 峰值，不等于低内存或独立机器验收。
- Windows 以外的应用打包、完整 CodeQL 分析及公有 CA 签名不在当前交付中。

## 后续工作、贡献与支持

扩大适配器及 triage/export 覆盖、处理上游桌面依赖告警是后续方向；插件契约及 Linux/macOS 打包属于未来工作。当前已有 SARIF 调查和自签名 Windows 发布，不代表成熟稳定产品。

见[贡献指南](CONTRIBUTING.md)。PR 运行适用检查并说明未验证范围；[Issues](https://github.com/styayur/developer-security-workspace/issues)用于脱敏复现，[Discussions](https://github.com/styayur/developer-security-workspace/discussions)用于设计讨论。不要提交真实发现、源码快照或凭据。漏洞必须按 [SECURITY.md](SECURITY.md) 私下报告。Discord 只用于非正式交流，不承诺响应时间，也不是安全报告渠道。维护者按精确版本 Tag 发布，不由贡献者自行发版。

## 许可证

应用源码为 [AGPL-3.0-only](LICENSE)。扫描器独立安装且保留原许可；见 [NOTICE](NOTICE.md)、[第三方许可](THIRD_PARTY_LICENSES.md)与[许可边界](docs/licensing.md)。项目不隶属任何扫描器厂商，也未获其背书。

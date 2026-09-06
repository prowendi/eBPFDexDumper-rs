# 贡献指南

感谢你关注 `eBPFDexDumper-rs`。这个项目的目标是提供稳定、可维护、可发布的
Android eBPF DEX dump 工具。

## 开发环境

建议准备以下工具：

- Rust stable 工具链。
- 支持 BPF target 的 LLVM clang。
- Android NDK，用于 Android ARM64 Release 构建。

macOS 自带的 Apple clang 通常不能编译 eBPF，建议安装 Homebrew LLVM：

```bash
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang
```

Android 构建需给当前 Rust 工具链安装目标标准库，并指向实际安装的 NDK：

```bash
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/android-sdk/ndk/<version>
```

如果同时安装了 Homebrew Rust 和 rustup，确认 `rustc` 使用的是安装了 Android
目标的工具链；必要时设置 `RUSTC="$(rustup which rustc)"`。不要仅凭 NDK 不在默认
位置就认定未安装，先检查 Android SDK 下的 `ndk/` 目录。

## 提交前检查

提交改动前建议执行：

```bash
cargo fmt --check
cargo test --locked
sh build_android.sh
```

Android Release 可执行文件会生成在：

```text
target/aarch64-linux-android/release/eBPFDexDumper
```

如果只改了文档，也至少确认 Markdown 内容准确，不要写超过当前实现能力的功能描述。

主机测试不会执行所有 Android 专用代码。修改采集缓存、BPF 事件或退出流程时，
还应在 ARM64 Android 上运行测试二进制及自建 APK 的端到端测试；步骤和本轮结果见
[防御性修复验证](docs/DEFENSIVE_VALIDATION.md)。测试日志应记录 API/ABI、内核、
探针模式、APK 哈希、手动偏移和退出码，不要只以“文件已生成”判断成功。

## 打包

CI 和发布工作流仅使用 `run` 步骤，不依赖外部仓库的 Action，兼容仅允许
仓库所有者名下 Action 的策略。GitHub 托管的 Ubuntu runner 需提供 Git、rustup、
Android SDK 的 sdkmanager 和 GitHub CLI；NDK 固定为 `27.2.12479018`（r27c）。
检出按事件的 `GITHUB_SHA` 固定，PR 测试使用事件对应的合并提交。

推送 `v*` 标签会构建并发布 Android 产物；也可对该标签手动触发 Release 工作流。
发布步骤通过 `GITHUB_TOKEN` 的 `contents: write` 权限创建 Release 和上传产物，
普通 CI 仅授予 `contents: read`。工作流变更可用 `actionlint` 检查。
修复发布工作流后应创建新版本标签，避免移动已发布的旧标签。

本地复现 GitHub Release 产物：

```bash
./scripts/package-release.sh
```

生成文件位于 `dist/`。

## 代码要求

- 保持 `dump`、`fix`、`offsets` 的命令行为稳定。
- 优先使用已有模块和数据结构，不做无关重构。
- 涉及 eBPF、ART 偏移、DEX 修复逻辑的改动，需要尽量补充或更新测试。
- 不提交 `target/`、`dist/`、`.DS_Store` 等本地生成文件。

## 安全边界

请不要提交用于绕过授权、攻击第三方设备或泄露敏感数据的示例。项目只面向授权的
Android 逆向分析和安全研究场景。

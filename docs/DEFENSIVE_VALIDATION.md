# 防御性修复验证

## 环境与范围

2026-09-06 在本机只读 AVD `Pixel_7_API_35_arm64` 上验证，Android 15 / API 35、
`arm64-v8a`、root、内核 `6.6.30-android15-8-gdd9c02ccfe27-ab11987101-4k`，具备内核 BTF。
使用自建 `dev.dexdefensive.fixture` APK，不使用第三方应用数据。
采集参数为 `--probe-mode lifecycle --no-clean-oat --no-maps-scan`。
测试结束后关闭了本轮启动的模拟器。

## 结果

| 检查 | 观察结果 |
| --- | --- |
| 主机单元测试 | 80 通过 |
| Android 单元测试 | 91 通过，含进程隔离和冲突测试 |
| Android ARM64 release | 构建成功，并在模拟器实际运行 |
| 双进程同地址 | 两个进程的 `0x73b0785000` DEX 分别保留 |
| 普通采集文件 | 原始 4 个、11544 字节；去重修复后 2 个、5772 字节 |
| 文件校验 | 上述 6 个文件的 magic、file_size、SHA-1、Adler-32、apkanalyzer 均通过 |
| APK 对照 | 内容分别匹配 APK 的 classes.dex 和 assets/payload.dex，无新增运行时独有字节内容 |
| JNI 退出积压 | 基线 / 修改版 / 回滚版捕获 0 / 1300 / 0 条测试注册记录 |
| 无效 DEX | 基线 / 修改版 / 回滚版退出码 0 / 1 / 0；仅修改版不生成输出文件 |
| 源码回滚 | 独立副本的 5 个原改动文件逐字节恢复，原有 68 项测试通过 |

普通双进程 APK SHA-256：
`4d1be20c6d99069377d50c572eb2549f377bd038c0358c0313e9bfa437e8240c`。
JNI 积压版 APK SHA-256：
`5d72c1ac05f72db9bb3ec9d06c33e23b88012aacadd4e110b8bd8369872e8b53`。
796 字节的 payload 是刻意构造的完整小 DEX，并经 ART 执行确认，不是截断片段。

## ART 实测发现

从捕获的 payload 中清除构造方法的 code_off，提供原始构造方法指令记录，保留
compute 方法的 try/catch，测试缺失方法重建。初次输出虽通过 apkanalyzer，ART 仍报告：

```text
Non-zero padding 3 before section of type 8195 at offset 0xfc
```

原因是迁移结构后旧区段仍含非零字节。修复现已清零废弃的 code_item、class_data
区段和旧 map，并增加保留相邻调试数据的回归断言。再次用 InMemoryDexClassLoader
加载、构造实例并调用正常路径与异常路径，输出：

```text
ART_LOAD_OK constructor=dev.dexdefensive.payload.Payload normal=841 catch=0
```

退出码为 0。此前失败来自 Java 加载异常，app_process 退出码为 137，不是 native SIGSEGV。

## 复测步骤

以下是测试流程，不是开箱即用的 APK 测试套件；本轮生成的 APK、设备日志和本机
路径不纳入源码仓库。复测需另行准备包含双进程、内存 DEX 加载和 JNI 注册的测试 APK。

1. 执行 `cargo fmt --check`、`cargo test --locked` 和 `sh build_android.sh`。
2. 设置 NDK 的 `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER` 后运行
   `cargo test --locked --target aarch64-linux-android --no-run`，将打印出的测试可执行文件
   推到设备，赋予执行权限后运行 `--test-threads=1`。将 `TMPDIR` 指向设备可写目录。
3. 安装测试 APK，以 root 和上述 lifecycle 参数启动采集，使用新的输出目录，再启动 APK。
   检查不同 PID 的相同 begin 是否生成独立文件；用不同内容样本及单元测试覆盖串流风险。
4. 为验证退出排空，暂停采集进程（SIGSTOP），让测试 APK 注册超过 1024 个不同 JNI
   方法，确认注册结束，再向采集进程发送 SIGINT 和 SIGCONT。核对输出中的唯一方法名集合，
   而不只看汇总数量。本轮使用 1300 个方法，另有 10 条预先捕获的记录。
5. 对每个 DEX 检查头部大小、SHA-1、Adler-32，运行 `apkanalyzer dex packages`，再与 APK
   中所有 DEX 条目作 SHA-256 对照。重建方法还需由实际 ART 加载并执行相关路径。
6. 对无效输入、输出写入失败分别检查退出码和文件状态。使用独立源码副本作基线与回滚
   对照，不覆盖正在使用的修改版工作区。

## 已知边界

- 本轮 API 35 的 RegisterNatives 自动定位选择 `0x5fb26c`，挂载后未捕获 JNI 记录。
  测试 APK 通过实际 JNIEnv 函数指针及 dladdr 核实为当前 libart 的 `0x885724`，随后用
  `--register-natives-offset 0x885724` 完成测试。自动定位问题尚未修复，此数值不可跨构建套用。
- 未验证 full 模式或其他 Android/ART 版本；同内容双进程实测本身也不证明所有地址复用
  情况均已覆盖。地址、头部和 CodeItem 标识不变的原地改写仍可能漏采。
- 结构校验不是完整字节码验证；只有指令的缺失方法记录不能恢复原始异常表、调试信息，
  寄存器窗口仍依赖推断。
- `cargo clippy --locked --lib -- -D warnings` 通过；all-targets 检查存在未改动的
  `src/art.rs` 测试中的 `identity_op`，未把无关清理混入本次修改。

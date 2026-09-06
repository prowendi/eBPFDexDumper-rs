# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

[English](docs/README_EN.md) | 中文

从已 root 的 Android ARM64 设备上抓取 DEX 文件，并回填执行过的方法字节码。也支持 native .so dump 和 JNI 动态注册名恢复。

## 快速开始

```bash
# 构建 Android ARM64 二进制
sh build_android.sh

# 推到设备并运行
adb push target/aarch64-linux-android/release/eBPFDexDumper /data/local/tmp/
adb shell su -c '/data/local/tmp/eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

默认 `full` 模式，退出时自动修复 DEX，输出在 `repair/` 目录；单独运行 `fix` 的汇总输出仍在 `final/`。

## 数据完整性

- 新抓取文件使用 `dex_<pid>_<begin>_<size>.dex`，字段均为十六进制；离线修复兼容旧的 `dex_<begin>_<size>.dex`。
- 采集缓存按进程隔离。观察到同一进程、同一地址的大小或内容冲突后，该地址的字节码关联会被停用；后续完整快照以带内容哈希的文件名保留，不覆盖首次快照。建议每次抓取使用新的输出目录。
- BPF 缓存同时考虑 DEX 头特征或 CodeItem 地址/长度。这是地址复用的防御措施，不是完整的映射生命周期跟踪；地址、头特征和 CodeItem 标识均未变化的原地改写仍可能漏采。
- `repair` 重定位所有活动的 code_item/class_data 时同步更新 map 条目，清零已废弃的原区段和旧 map，满足 ART 对区段间零填充的要求；已有方法完整的异常处理尾部保持不变。仅凭捕获指令重建的方法仍缺少原始异常表和调试信息，寄存器窗口也依赖推断。
- 修复结果执行头/索引表边界、活动 code_item/class_data 与 map 的一致性、异常尾部边界、SHA-1 和 Adler-32 检查。这不等同于完整 DEX 验证或 ART 字节码语义验证。
- map 不可读、结构检查失败、捕获记录无效或输出失败会使 `repair` 返回非零状态；成功文件单独计数并原子替换输出，原始输入保留。缺少捕获的方法仍会单独报告。
- 去重只跳过 DEX 内容与配套捕获记录均相同的输入，不按大小合并，也不删除原文件。
- 正常停止时先卸载探针，再排空包括 JNI 在内的事件队列，最后写出符号文件；再次发送停止信号可中止排空，届时不保证记录完整。

## 验证与兼容性

已在 Android 15 / API 35 ARM64 本地 root 模拟器上，用自建双进程 APK 验证进程隔离、退出队列排空、修复失败状态，以及修复 DEX 的 ART 加载和执行。验证使用 `lifecycle --no-clean-oat --no-maps-scan`，不代表 `full` 模式或所有 ART 版本均已验证。

该模拟器的 JNI `RegisterNatives` 自动定位存在偏移不准确的问题；探针挂载成功不等于事件已捕获。可通过 `--register-natives-offset` 指定针对当前 `libart.so` 核实的偏移，不要跨系统版本复用偏移值。

详细结果、边界和复测步骤见[防御性修复验证](docs/DEFENSIVE_VALIDATION.md)；构建环境见[贡献指南](CONTRIBUTING.md)。

## 子命令

| 命令 | 用途 |
|------|------|
| `dump` | 抓取 DEX + 方法字节码 |
| `fix` | 回填字节码到 DEX |
| `repair` | 修复头/格式/缺失 code_item |
| `dumpso` | 抓取 native .so |
| `fixso` | 修复 .so 段偏移 |
| `offsets` | 检查 ART 布局 |

## 探针模式

| 模式 | 探针 | 性能影响 |
|------|------|---------|
| `full`（默认） | 解释器 + 生命周期 + libc | 有卡顿 |
| `lifecycle` | 仅生命周期 | 无影响 |
| `maps-only` | 无 uprobe | 无影响 |

## 项目 Skill

一键运行：

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

## 许可证

GPL-3.0-or-later

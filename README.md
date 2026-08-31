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

默认 `full` 模式，退出时自动修复并校验 DEX。输出在 `final/` 目录。

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

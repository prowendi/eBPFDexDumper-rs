# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

[中文](../README.md) | English

Capture real DEX files from rooted Android ARM64 devices, restore executed method bytecode into dumped files. Also supports native .so memory dumps and JNI name recovery.

## Quick start

```bash
# Build Android ARM64 binary
sh build_android.sh

# Push to device and run
adb push target/aarch64-linux-android/release/eBPFDexDumper /data/local/tmp/
adb shell su -c '/data/local/tmp/eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

Default `full` mode auto-repairs and validates DEX on exit. Output goes to `final/`.

## Subcommands

| Command | Purpose |
|---------|---------|
| `dump` | Capture DEX + method bytecode |
| `fix` | Restore bytecode into DEX |
| `repair` | Fix header/format/missing code_items |
| `dumpso` | Capture native .so from memory |
| `fixso` | Repair .so segment offsets |
| `offsets` | Inspect ART layout |

## Probe modes

| Mode | Probes | Performance |
|------|--------|-------------|
| `full` (default) | Interpreter + lifecycle + libc | UI lag |
| `lifecycle` | Lifecycle only | No impact |
| `maps-only` | No uprobes | No impact |

## Project skill

One-click run:

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

## License

GPL-3.0-or-later

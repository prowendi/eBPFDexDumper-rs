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

The default `full` mode auto-repairs DEX on exit into `repair/`. The standalone `fix` command still writes its combined output into `final/`.

## Data integrity

- New captures use `dex_<pid>_<begin>_<size>.dex`, with hexadecimal fields. Offline repair also accepts the older `dex_<begin>_<size>.dex` names.
- Capture caches isolate processes. Conflicting sizes or contents at the same process/address disable bytecode association for that address; later complete snapshots retain content-hash filenames instead of overwriting the first capture. Use a fresh output directory for each session.
- BPF deduplication includes DEX header features or CodeItem address/length. This is not complete mapping lifecycle tracking: in-place changes with unchanged identities can still be missed.
- Repair relocates live code_items/class_data, updates map counts/offsets, and clears retired sections and the old map for ART zero-padding requirements. Existing exception tails are preserved. Synthesized methods still lack original exception/debug metadata and use inferred register windows.
- Output checks cover header/index bounds, live-item/map consistency, exception-tail bounds, SHA-1 and Adler-32. They are not a complete DEX or ART bytecode verifier.
- Invalid maps, structural failures, invalid capture records and output failures cause a nonzero `repair` status. Successful files are counted separately and written atomically; original inputs remain intact. Deduplication compares both DEX content and capture records, never size alone.
- Normal shutdown detaches probes and drains all event queues, including JNI, before writing symbols. A second stop signal can interrupt draining and leave records incomplete.

## Validation and compatibility

Android 15 / API 35 ARM64 emulator testing with a local two-process fixture covered process isolation, shutdown draining, repair error status, and actual ART loading/execution. Testing used `lifecycle --no-clean-oat --no-maps-scan`, not `full` mode.

Automatic JNI `RegisterNatives` discovery selected an incorrect offset on this emulator. A successful attachment does not prove event capture. Use `--register-natives-offset` only with an offset verified against the current `libart.so`; offsets are not portable across builds.

See the [validation record and retest procedure](DEFENSIVE_VALIDATION.md) (Chinese) and [contributor guide](../CONTRIBUTING.md).

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

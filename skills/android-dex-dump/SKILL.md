---
name: android-dex-dump
description: From a Windows, macOS, or Linux PC, dump and validate runtime DEX files from an authorized local APK on a rooted ARM64 Android emulator/device using eBPFDexDumper-rs. Use for local APK runtime capture, APK-vs-runtime DEX comparison, and optional JADX decompilation.
---

# Android runtime DEX dump from PC

Use only for APKs and devices the user is authorized to test. The PC is the host that runs this workflow; the live target remains a rooted ARM64 Android emulator/device.

## Host support

- Windows 10/11: PowerShell + Python 3.9+ with `run_dump.ps1`.
- macOS/Linux: Python 3.9+ with `run_dump.sh`.
- All hosts need: `adb`, a rooted ARM64 Android target, and `apkanalyzer` or `aapt`.

From repository root:

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

```powershell
.\skills\android-dex-dump\scripts\run_dump.ps1 C:\path\to\app.apk
```

Both wrappers call `run_dump.py`. It tries `full → lifecycle → maps-only` in order, pulls results, and writes `report.txt`.

## Workflow

1. Build: `sh build_android.sh` (macOS/Linux) or `cargo ndk -t arm64-v8a build --release` (Windows).
2. Push binary and run: `su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'`.
3. Default `full` mode auto-repairs DEX on exit — fixes header bounds, map list, format fields, and missing code_items. All repaired DEX pass post-fix validation.
4. Output in `repair/` subdirectory (not `final/`).
5. Validate: `dex\n` magic, header `file_size`, SHA-1, Adler32.

## Probe modes

| Mode | Probes | Auto-fix output | When to use |
|------|--------|----------------|-------------|
| `full` (default) | Interpreter + lifecycle + libc native | `repair/` with bytecode | Best coverage, may cause UI lag |
| `lifecycle` | Lifecycle only | `repair/`, no bytecode | App crashes in full mode |
| `maps-only` | None | `repair/`, no bytecode | App detects uprobes |

## Auto-repair features (v0.2.6+)

- **Header bounds**: fix `file_size`/`data_off`/`data_size`
- **Map list**: rebuild if out of order or not at end of file
- **Format fields**: zero out-of-bounds `debug_info_off`/`tries_size`/`interfaces_off`/`annotations_off`/`static_values_off`
- **Bytecode restore**: write captured method bodies back into code_items
- **Missing code_items**: synthesize new ones for methods the packer stripped
- **Post-fix validation**: `DexParser::new` check after repair, reports `validation OK/FAILED`
- **Parallel repair**: multiple DEX files repaired concurrently

## Subcommands

| Command | Purpose |
|---------|---------|
| `dump` | Capture DEX + method bytecode (auto-repair on exit) |
| `fix` | Restore bytecode into DEX using `_code.json` |
| `repair` | Full repair: header, format, missing code_items |
| `dumpso` | Capture native .so from memory |
| `fixso` | Repair .so segment offsets, inject JNI symbols |
| `offsets` | Inspect ART hook targets and layout |

## Output

```
<output>/<package>/
├── dex_*.dex               # raw DEX
├── dex_*_code.json         # method bytecode records
├── repair/                 # auto-repaired DEX (recommended)
├── native_elf/             # anonymous ELF (optional)
└── jni_symbols_*.txt       # JNI names (optional)
```

## Failure handling

- If no DEX produced: check `pidof`, `logcat`, whether the launcher crashed.
- For native `SIGSEGV`: record signal, fault address, API level.
- For ART differences: retry another AVD, report API level and detected layout.
- Never overwrite APK or original dump. Use `--no-clean-oat` unless user requests oat cleanup.

## Reporting

Always include: package, API/ABI, probe mode, valid DEX count and total size, output path, APK hash comparison, and crash/fragment evidence.

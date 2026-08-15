<div align="center">

  <h1>🎮 <code>ps3ida9</code> 🕹️</h1>

  <p>
    <strong>A modern, all-in-one PlayStation 3 reverse engineering plugin & tool suite for IDA Pro 9.</strong>
  </p>

  <p>
    <a href="#license"><img src="https://img.shields.io/badge/license-GPLv3-blue?style=flat-square" alt="License"></a>
    <a href="https://hex-rays.com/ida-pro/"><img src="https://img.shields.io/badge/IDA%20Pro-9%2B-green?style=flat-square" alt="IDA Version"></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.x-yellow?style=flat-square" alt="Python 3"></a>
  </p>

</div>

`ps3ida9` is a unified, production-ready reverse engineering toolkit for analyzing PlayStation 3 executables (`.self`, `.sprx`, `.elf`, PRX libraries, and LV2 kernel/hypervisor dumps) in **IDA Pro 9**.

It combines and modernizes the best features from legacy **`ps3ida`** (which only worked on IDA 6.x) and **`Ps3GhidraScripts`** (Ghidra extension), updated to take full advantage of IDA Pro 9's native 64-bit PowerPC architecture, modern IDAPython 3.x APIs, and the IDA 9 C++ SDK.

---

## 🌟 Authors

- [@zeph](https://github.com/ZephyrCodesStuff) (that's me!)

## 💛 Acknowledgements

This project builds upon foundational reverse engineering work done by the PS3 scene over many years, and the amazing reverse-engineering tools by Hex-Rays:

- **[@kakaroto](https://github.com/kakaroto)** for the original `ps3ida` toolkit.
- **[@clienthax](https://github.com/clienthax)** and **[the Ps3GhidraScripts contributors](https://github.com/clienthax/Ps3GhidraScripts/graphs/contributors)** for the extensive Ghidra NID and syscall databases.
- [Hex-Rays](https://hex-rays.com/) for IDA and [the open IDA SDK](https://github.com/HexRaysSA/ida-sdk).

As well as Gemini 3.7 Flash for doing 90% of the work here.

## 🌠 Features

- **9,386+ Unified NID Database**: Merged symbol datasets from Ghidra scripts, `ps3.xml`, and `fnids.idh` to automatically resolve 32-bit SHA-1 hashes into clean function names (`cellAudioInit`, `cellGcmSetDisplayBuffer`, `sys_net_initialize`, etc.).
- **PRX Header & Stub Parsing**: Scans `.sys_proc_param`, `sys_process_prx_info_t`, and `_scemoduleinfo_ppu32` tables to build import stubs, export entries, and library associations.
- **OPD & TOC (`r2`) Discovery**: Parses OPD (`.opd`) files, generates functions at target code addresses, types descriptors as `opd32_t`/`opd64_t`, and establishes the global `TOC_BASE` pointer.
- **Smart RTOC (`r2`) Register Propagation Fixer**: Emulates PowerPC register arithmetic (`li`, `lis`, `addi`, `addis`, `ori`, `mr`) to resolve TOC-relative memory operations (`lwz`, `ld`, `lhz`, `lbz`, `lfs`, `lfd`, `stw`, `std`) into readable cross-referenced global variables and strings.
- **Full Syscall & Hypercall Resolution**: Detects `sc 2` (LV2 system calls) and `sc 1` (LV1 hypercalls), backtracks `r11` constants, and resolves them against **664 LV2 syscalls** and **128 LV1 hypercalls**.
- **Local Types & Decompiler Structs**: Injects standard PS3 runtime structures into IDA's Local Types for clean, structured Hex-Rays decompilation.
- **LV2 Kernel & Hypervisor Dump Analyzer**: Automatically locates kernel dispatch tables and labels all 1,024 kernel syscall handlers.

## 🧰 Installation & Usage

### 🐍 Option 1: IDAPython Plugin (Recommended)

1. Copy the `ps3ida9` folder and `plugins/ps3ida9_plugin.py` into your IDA Pro `plugins` directory:
   - **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\` or `<IDA_INSTALL_DIR>\plugins\`
   - **Linux / macOS**: `~/.idapro/plugins/` or `<IDA_INSTALL_DIR>/plugins/`
2. Open your PS3 binary in IDA Pro 9.
3. Press **`Ctrl-Alt-P`** or navigate to **Edit -> PS3 IDA 9 Tools -> 1. Run Full PS3 Analysis (Auto All)**.

### 📜 Option 2: Standalone Script Execution

You can run `ps3ida9_standalone.py` directly without installing:
1. Open your PS3 binary in IDA Pro 9.
2. Go to **File -> Script file...** (`Alt+F7`).
3. Select `ps3ida9_standalone.py`.

> [!IMPORTANT]
> Make sure that the `ps3ida9_standalone.py` script is located right next to the `ps3ida9` main folder. It's just a wrapper!

### ⚡ Option 3: C++ SDK Plugin (`ida-sdk`)

For maximum performance on massive 100+ MB retail binaries:
```bash
cd ida-sdk/src
cmake -B build -G Ninja
cmake --build build --target ps3ida9
```
Outputs `ida-sdk/bin/plugins/ps3ida9.dll` (or `.so` / `.dylib`), which you can place in your IDA `plugins/` directory.

## 🎛️ Action List & Hotkeys

All tools are accessible under the **Edit -> PS3 IDA 9 Tools** menu:

| Menu Action | Hotkey | Description |
|---|---|---|
| **1. Run Full PS3 Analysis (Auto All)** | `Ctrl-Alt-P` | Executes complete pipeline (Types $\to$ OPD/TOC $\to$ Imports/Exports $\to$ Syscalls $\to$ RTOC Fixer) |
| **2. Parse OPD Section & Set TOC (r2)** | — | Discovers OPD procedure descriptors and establishes `TOC_BASE` |
| **3. Resolve PRX Imports/Exports & NIDs** | — | Scans stub tables and names library imports and exports |
| **4. Resolve PS3 Syscalls & Hypercalls** | — | Resolves `sc 2` / `sc 1` instructions via `r11` constant tracing |
| **5. Run RTOC (r2) Cross-Reference Fixer** | `Ctrl-F11` | Propagates `r2` to fix TOC-relative memory cross references |
| **6. Define PS3 Data Structures in Local Types** | — | Imports C header structures into IDA Local Types |
| **7. Analyze LV2 Kernel Dump** | — | Locates kernel syscall dispatch table and marks all LV2 routines |

## 🚀 Python vs. C++ Performance Note

On small to medium-sized homebrew or PRX modules, IDAPython runs in just a few seconds. 

However, retail PS3 games often contain **100,000+ functions and millions of instructions**. Because IDAPython creates temporary Python wrapper objects for every decoded instruction across the SWIG boundary, full-binary RTOC register propagation in Python can take a couple of minutes. 

> [!TIP]
> If you are regularly reversing large commercial games, compile the native C++ plugin (`ida-sdk/src/plugins/ps3ida9`), which executes instruction decoding directly in CPU registers with zero allocation overhead (~20× to 100× faster).

## 📝 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

- ✅ **You can** use, share, and modify this tool suite freely.
- 🛑 **If you distribute** modified versions, you **must** provide the source code under AGPL-3.0 as well.
- 🛑 **If you use modified versions** of this in an API service, you **must** provide the source code under AGPL-3.0 as well.

See [LICENSE](LICENSE) for more details.

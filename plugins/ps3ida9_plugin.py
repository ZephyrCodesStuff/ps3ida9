"""
ps3ida9_plugin.py - Main IDA Pro 9.3+ Plugin Entry Point for PS3 Reverse Engineering Tools
"""

import sys
import os

# Ensure package directory is on sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
_pkg_parent = os.path.abspath(os.path.join(_current_dir, ".."))
if _pkg_parent not in sys.path:
    sys.path.insert(0, _pkg_parent)

try:
    import ida_idaapi
    import ida_kernwin
    import ida_idp
    import ida_auto
except ImportError:
    pass

from ps3ida9.ps3_analyzer import run_full_analysis
from ps3ida9.ps3_structures import register_ps3_types
from ps3ida9.ps3_opd_toc import process_opd
from ps3ida9.ps3_nids_imports import scan_and_process_prx
from ps3ida9.ps3_syscalls import process_syscalls
from ps3ida9.ps3_rtoc_fixer import run_rtoc_fixer
from ps3ida9.ps3_lv2_dump import analyze_lv2_kernel_dump

class PS3ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, action_func):
        super().__init__()
        self.action_func = action_func

    def activate(self, ctx):
        self.action_func()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class PS3IdaPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "PS3 IDA Pro 9.3+ Reverse Engineering Tools"
    help = "Automated PS3 binary analysis, NID resolution, TOC/OPD handling, syscall resolution, and RTOC fixer"
    wanted_name = "PS3 IDA Pro 9 Tools"
    wanted_hotkey = "Ctrl-Alt-P"

    def __init__(self):
        super().__init__()
        self.registered_actions = []

    def _register_action(self, name, label, callback, hotkey=""):
        action_desc = ida_kernwin.action_desc_t(
            name,
            label,
            PS3ActionHandler(callback),
            hotkey,
            f"PS3: {label}",
            -1
        )
        if ida_kernwin.register_action(action_desc):
            self.registered_actions.append(name)
            ida_kernwin.attach_action_to_menu(
                f"Edit/PS3 IDA 9 Tools/{label}",
                name,
                ida_kernwin.SETMENU_APP
            )

    def init(self):
        print("\n" + "=" * 60)
        print("[PS3IDA9] Initializing PS3 IDA Pro 9.3+ Plugin Suite...")
        print("[PS3IDA9] Supported architectures: PowerPC 32/64 (Cell PPU / SPU / LV1 / LV2)")
        print("=" * 60)

        # Register individual action items in Edit -> PS3 IDA 9 Tools menu
        self._register_action(
            "ps3ida9:analyze_all",
            "1. Run Full PS3 Analysis (Auto All)",
            run_full_analysis,
            "Ctrl-Alt-P"
        )
        self._register_action(
            "ps3ida9:opd_toc",
            "2. Parse OPD Section & Set TOC (r2)",
            process_opd
        )
        self._register_action(
            "ps3ida9:nids_imports",
            "3. Resolve PRX Imports/Exports & NIDs",
            scan_and_process_prx
        )
        self._register_action(
            "ps3ida9:syscalls",
            "4. Resolve PS3 Syscalls & Hypercalls",
            process_syscalls
        )
        self._register_action(
            "ps3ida9:rtoc_fixer",
            "5. Run RTOC (r2) Cross-Reference Fixer",
            run_rtoc_fixer,
            "Ctrl-F11"
        )
        self._register_action(
            "ps3ida9:def_structs",
            "6. Define PS3 Data Structures in Local Types",
            register_ps3_types
        )
        self._register_action(
            "ps3ida9:lv2_dump",
            "7. Analyze LV2 Kernel Dump",
            analyze_lv2_kernel_dump
        )

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        run_full_analysis()

    def term(self):
        for act in self.registered_actions:
            ida_kernwin.unregister_action(act)
        self.registered_actions.clear()
        print("[PS3IDA9] Plugin unloaded.")

def PLUGIN_ENTRY():
    return PS3IdaPlugin()

if __name__ == "__main__":
    run_full_analysis()

"""
ps3_analyzer.py - Master Orchestrator for PS3 IDA Pro 9.3+ Analysis
"""

import time

try:
    import ida_auto
    import ida_idaapi
except ImportError:
    pass

from .ps3_structures import register_ps3_types
from .ps3_opd_toc import process_opd, find_opd_segment
from .ps3_nids_imports import scan_and_process_prx
from .ps3_syscalls import process_syscalls
from .ps3_rtoc_fixer import run_rtoc_fixer
from .ps3_lv2_dump import analyze_lv2_kernel_dump

def run_full_analysis():
    """
    Runs the complete PS3 automated analysis pipeline.
    """
    print("=" * 60)
    print("[PS3IDA9] Starting Full PS3 Binary Analysis for IDA Pro 9.3+...")
    print("=" * 60)
    
    t0 = time.time()

    # Step 1: Register PS3 structures
    print("\n[Step 1/5] Registering PS3 C-structures in Local Types...")
    register_ps3_types()

    # Step 2: OPD and TOC Analysis
    print("\n[Step 2/5] Parsing OPD section and establishing TOC (r2)...")
    toc = process_opd()

    # Step 3: PRX Imports / Exports and NID Resolution
    print("\n[Step 3/5] Parsing PRX / ELF Import & Export tables and resolving NIDs...")
    imports_count, exports_count = scan_and_process_prx()

    # Step 4: Syscall / Hypercall Resolution
    print("\n[Step 4/5] Scanning and resolving PS3 Syscalls & Hypercalls...")
    total_sc, resolved_sc = process_syscalls()

    # Step 5: RTOC (r2) Register Propagation Fixer
    print("\n[Step 5/5] Running RTOC (r2) Register Propagation & Cross-Reference Fixer...")
    xrefs_fixed = run_rtoc_fixer(toc)

    # Trigger IDA auto-analysis refresh
    try:
        ida_auto.auto_wait()
    except Exception:
        pass

    elapsed = time.time() - t0
    print("\n" + "=" * 60)
    print(f"[PS3IDA9] Full Analysis Finished in {elapsed:.2f}s!")
    print(f" - TOC Base Address: {('0x%08X' % toc) if toc else 'N/A'}")
    print(f" - PRX Imports Resolved: {imports_count}")
    print(f" - PRX Exports Resolved: {exports_count}")
    print(f" - Syscalls Resolved: {resolved_sc}/{total_sc}")
    print(f" - RTOC Xrefs Created: {xrefs_fixed}")
    print("=" * 60)

    return True

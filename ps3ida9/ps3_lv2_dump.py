"""
ps3_lv2_dump.py - PS3 LV2 Kernel Dump and Hypervisor Dump Analyzer for IDA Pro 9.3+
"""

try:
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment
    import ida_idaapi
    import idautils
    import idc
except ImportError:
    pass

from .ps3_syscalls import SyscallDatabase

def find_lv2_syscall_table():
    """
    Scans an LV2 kernel dump to identify the syscall dispatch table.
    """
    db = SyscallDatabase.get_instance()
    # Typical LV2 syscall tables contain pointers/OPD entries for syscalls 1..1024
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        
        start = seg.start_ea
        end = seg.end_ea

        ea = start
        while ea < end - (100 * 8):
            # Check for candidate table of valid pointers
            valid_ptrs = 0
            for j in range(1, 30):
                ptr = ida_bytes.get_dword(ea + j * 8)
                if ptr != 0 and ida_segment.getseg(ptr):
                    valid_ptrs += 1
            
            if valid_ptrs >= 20:
                print(f"[PS3IDA9] Identified candidate LV2 syscall table at 0x{ea:08X}")
                return ea
            ea += 8

    return None

def analyze_lv2_kernel_dump(table_ea=None):
    """
    Analyzes an LV2 kernel dump, marking the syscall table, naming syscall functions,
    and resolving hypercalls made by the kernel.
    """
    db = SyscallDatabase.get_instance()

    if table_ea is None:
        table_ea = find_lv2_syscall_table()

    if not table_ea:
        print("[PS3IDA9] LV2 Kernel Dump: Syscall table not automatically detected.")
        return False

    ida_name.set_name(table_ea, "LV2_Syscall_Table", ida_name.SN_NOWARN)
    print(f"[PS3IDA9] Analyzing LV2 syscall table at 0x{table_ea:08X}...")

    resolved = 0
    for num in range(1, 1024):
        entry_ea = table_ea + num * 8
        func_ptr = ida_bytes.get_dword(entry_ea)
        toc_ptr = ida_bytes.get_dword(entry_ea + 4)

        if func_ptr != 0 and func_ptr != ida_idaapi.BADADDR and ida_segment.getseg(func_ptr):
            sys_name = db.get_lv2_name(num)
            ida_funcs.add_func(func_ptr, ida_idaapi.BADADDR)
            ida_name.set_name(entry_ea, f"opd_sys_{num}_{sys_name}", ida_name.SN_NOWARN)
            ida_name.set_name(func_ptr, f"sys_{sys_name}", ida_name.SN_NOWARN)
            ida_bytes.set_cmt(func_ptr, f"LV2 Syscall #{num} ({sys_name})", True)
            resolved += 1

    print(f"[PS3IDA9] LV2 Kernel Dump analysis complete. Named {resolved} syscall functions.")
    return True

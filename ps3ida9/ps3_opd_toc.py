"""
ps3_opd_toc.py - Official Procedure Descriptor (OPD) and TOC (r2) analysis for IDA Pro 9.3+
"""

import os

try:
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment
    import ida_idaapi
    import ida_idp
    import ida_segregs
    import idautils
    import idc
except ImportError:
    pass

from .ps3_structures import apply_struct_to_ea, register_ps3_types

def find_opd_segment():
    """
    Finds the OPD segment by name or by heuristic scan.
    """
    # 1. Try finding by standard segment names
    for name in [".opd", "opd", "OPD", ".OPD"]:
        seg = ida_segment.get_segm_by_name(name)
        if seg:
            return seg

    # 2. Heuristic search: look for consecutive identical TOC pointers
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        start = seg.start_ea
        end = min(seg.end_ea, start + 0x1000)
        if end - start < 16:
            continue
        
        found = True
        toc = ida_bytes.get_dword(start + 4)
        if toc == 0 or toc == 0xFFFFFFFF:
            continue
            
        for ea in range(start, end - 8, 8):
            cur_toc = ida_bytes.get_dword(ea + 4)
            if cur_toc != toc:
                found = False
                break
        if found:
            ida_segment.set_segm_name(seg, ".opd")
            print(f"[PS3IDA9] Identified OPD segment by heuristic at 0x{seg.start_ea:X} - 0x{seg.end_ea:X}")
            return seg

    return None

def set_toc_register(toc_ea):
    """
    Sets the default r2 (TOC) value across all segments and creates the TOC label.
    """
    if toc_ea == 0 or toc_ea == ida_idaapi.BADADDR:
        return False
        
    ida_name.set_name(toc_ea, "TOC_BASE", ida_name.SN_NOWARN)
    print(f"[PS3IDA9] Setting TOC / r2 to 0x{toc_ea:08X}")
    
    # Try setting r2 reg value for PowerPC
    try:
        r2_idx = ida_idp.str2reg("r2")
        if r2_idx != -1:
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg:
                    # IDA 9.x: set_default_sreg_value_ea or idc.set_sreg_value
                    if hasattr(ida_segregs, "set_default_sreg_value_ea"):
                        ida_segregs.set_default_sreg_value_ea(seg.start_ea, r2_idx, toc_ea)
                    elif hasattr(ida_segregs, "set_default_sreg_value"):
                        ida_segregs.set_default_sreg_value(seg, r2_idx, toc_ea)
                    
                    try:
                        idc.set_sreg_value(seg.start_ea, "r2", toc_ea)
                    except Exception:
                        pass
    except Exception as e:
        print(f"[PS3IDA9] Note on setting register r2: {e}")
        
    return True

def process_opd(opd_seg=None):
    """
    Parses OPD descriptors, creates functions at target code addresses,
    and returns the identified TOC address.
    """
    register_ps3_types()
    
    if not opd_seg:
        opd_seg = find_opd_segment()
        
    if not opd_seg:
        print("[PS3IDA9] Could not locate .opd segment.")
        return None

    start_ea = opd_seg.start_ea
    end_ea = opd_seg.end_ea
    size = end_ea - start_ea

    print(f"[PS3IDA9] Processing OPD section: 0x{start_ea:X} to 0x{end_ea:X} ({size} bytes)")

    primary_toc = None
    func_count = 0

    ea = start_ea
    while ea < end_ea:
        func_ea = ida_bytes.get_dword(ea)
        toc_ea = ida_bytes.get_dword(ea + 4)

        if primary_toc is None and toc_ea != 0 and toc_ea != 0xFFFFFFFF:
            primary_toc = toc_ea

        # Define as opd32_t structure or dword pointers
        apply_struct_to_ea(ea, "opd32_t")

        # If valid func_ea in code segment, create function
        if func_ea != 0 and func_ea != ida_idaapi.BADADDR:
            seg = ida_segment.getseg(func_ea)
            if seg:
                pfn = ida_funcs.get_func(func_ea)
                if not pfn:
                    if ida_funcs.add_func(func_ea, ida_idaapi.BADADDR):
                        func_count += 1
                else:
                    func_count += 1

        ea += 8

    if primary_toc:
        set_toc_register(primary_toc)
        print(f"[PS3IDA9] Successfully parsed OPD. Created/verified {func_count} functions. TOC: 0x{primary_toc:08X}")
    else:
        print(f"[PS3IDA9] Parsed OPD with {func_count} functions, but no valid TOC base found.")

    return primary_toc

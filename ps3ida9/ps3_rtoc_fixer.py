"""
ps3_rtoc_fixer.py - Modernized RTOC (r2) Register Propagation & Cross-Reference Fixer for IDA Pro 9.3+
"""

try:
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment
    import ida_xref
    import ida_ua
    import ida_idaapi
    import ida_idp
    import idautils
    import idc
except ImportError:
    pass

from .ps3_opd_toc import find_opd_segment

def get_mnemonic(ea):
    return (ida_ua.ua_mnem(ea) or "").lower()

def fix_function_rtoc(func_ea, default_toc_ea):
    """
    Simulates register flow through a single function to resolve r2/TOC relative memory accesses.
    """
    pfn = ida_funcs.get_func(func_ea)
    if not pfn:
        return 0

    g_gpr = [0] * 32
    g_act = [False] * 32

    # Initialize r2 (TOC)
    g_gpr[2] = default_toc_ea
    g_act[2] = True

    xrefs_added = 0
    insn = ida_ua.insn_t()

    ea = pfn.start_ea
    while ea < pfn.end_ea:
        if ida_ua.decode_insn(insn, ea) <= 0:
            ea = ida_bytes.next_head(ea, pfn.end_ea)
            if ea == ida_idaapi.BADADDR or ea <= 0:
                break
            continue

        mnem = get_mnemonic(ea)
        if not mnem:
            ea = insn.size + ea
            continue

        op1 = insn.Op1
        op2 = insn.Op2
        op3 = insn.Op3

        # 1. Register Moves and Immediates
        if mnem == "mr" and op1.type == ida_ua.o_reg and op2.type == ida_ua.o_reg:
            rD, rA = op1.reg, op2.reg
            if 0 <= rD < 32 and 0 <= rA < 32:
                if g_act[rA]:
                    g_gpr[rD] = g_gpr[rA]
                    g_act[rD] = True
                else:
                    g_act[rD] = False

        elif mnem in ["li"] and op1.type == ida_ua.o_reg:
            rD = op1.reg
            if 0 <= rD < 32:
                g_gpr[rD] = op2.value
                g_act[rD] = True

        elif mnem in ["lis"] and op1.type == ida_ua.o_reg:
            rD = op1.reg
            if 0 <= rD < 32:
                g_gpr[rD] = (op2.value & 0xFFFF) << 16
                g_act[rD] = True

        elif mnem in ["addi"] and op1.type == ida_ua.o_reg:
            rD = op1.reg
            if 0 <= rD < 32:
                if op2.type == ida_ua.o_reg and 0 <= op2.reg < 32 and g_act[op2.reg]:
                    val = (g_gpr[op2.reg] + op3.value) & 0xFFFFFFFFFFFFFFFF
                    g_gpr[rD] = val
                    g_act[rD] = True
                elif op2.type == ida_ua.o_imm:
                    g_gpr[rD] = op2.value
                    g_act[rD] = True
                else:
                    g_act[rD] = False

        elif mnem in ["addis"] and op1.type == ida_ua.o_reg:
            rD = op1.reg
            if 0 <= rD < 32:
                if op2.type == ida_ua.o_reg and 0 <= op2.reg < 32 and g_act[op2.reg]:
                    val = (g_gpr[op2.reg] + ((op3.value & 0xFFFF) << 16)) & 0xFFFFFFFFFFFFFFFF
                    g_gpr[rD] = val
                    g_act[rD] = True
                else:
                    g_act[rD] = False

        elif mnem in ["ori"] and op1.type == ida_ua.o_reg and op2.type == ida_ua.o_reg:
            rD, rA = op1.reg, op2.reg
            if 0 <= rD < 32 and 0 <= rA < 32 and g_act[rA]:
                g_gpr[rD] = g_gpr[rA] | (op3.value & 0xFFFF)
                g_act[rD] = True

        # 2. Memory Loads (lwz, ld, lhz, lbz, lfs, lfd, etc.)
        elif mnem in ["lwz", "ld", "lhz", "lbz", "lfs", "lfd", "lwzx", "ldx", "lha", "lwa"]:
            # Check displacement addressing mode: displ(rA)
            # In IDA: Op2 is o_displ or o_phrase
            rD = op1.reg if op1.type == ida_ua.o_reg else -1
            rA = op2.reg if (op2.type in [ida_ua.o_displ, ida_ua.o_phrase]) else -1
            displ = op2.addr if op2.type == ida_ua.o_displ else 0

            # Displacement is a signed 16-bit int in PPC
            if displ >= 0x8000:
                displ -= 0x10000

            if 0 <= rA < 32 and g_act[rA]:
                target_ea = (g_gpr[rA] + displ) & 0xFFFFFFFF
                
                # Verify target_ea is inside valid database segment
                if ida_segment.getseg(target_ea):
                    ida_xref.add_dref(ea, target_ea, ida_xref.dr_R)
                    xrefs_added += 1

                    # Read value into rD if destination is a general register
                    if 0 <= rD < 32 and rD != 2:
                        if mnem in ["lwz", "lwa"]:
                            g_gpr[rD] = ida_bytes.get_dword(target_ea)
                            g_act[rD] = True
                        elif mnem == "ld":
                            g_gpr[rD] = ida_bytes.get_qword(target_ea)
                            g_act[rD] = True
                        elif mnem in ["lhz", "lha"]:
                            g_gpr[rD] = ida_bytes.get_word(target_ea)
                            g_act[rD] = True
                        elif mnem == "lbz":
                            g_gpr[rD] = ida_bytes.get_byte(target_ea)
                            g_act[rD] = True
                        else:
                            g_act[rD] = False
                else:
                    if 0 <= rD < 32 and rD != 2:
                        g_act[rD] = False
            else:
                if 0 <= rD < 32 and rD != 2:
                    g_act[rD] = False

        # 3. Memory Stores (stw, std, sth, stb, stfs, stfd)
        elif mnem in ["stw", "std", "sth", "stb", "stfs", "stfd"]:
            rA = op2.reg if (op2.type in [ida_ua.o_displ, ida_ua.o_phrase]) else -1
            displ = op2.addr if op2.type == ida_ua.o_displ else 0
            if displ >= 0x8000:
                displ -= 0x10000

            if 0 <= rA < 32 and g_act[rA]:
                target_ea = (g_gpr[rA] + displ) & 0xFFFFFFFF
                if ida_segment.getseg(target_ea):
                    ida_xref.add_dref(ea, target_ea, ida_xref.dr_W)
                    xrefs_added += 1

        # 4. Other destination writes
        elif op1.type == ida_ua.o_reg:
            rD = op1.reg
            # Do not clear r2 (TOC) unless explicitly overwritten with ld r2, ...
            if 0 <= rD < 32 and rD != 2 and rD != 30:
                g_act[rD] = False

        # Maintain r2
        if not g_act[2]:
            g_gpr[2] = default_toc_ea
            g_act[2] = True

        ea = ida_bytes.next_head(ea, pfn.end_ea)
        if ea == ida_idaapi.BADADDR or ea <= 0:
            break

    return xrefs_added


def run_rtoc_fixer(default_toc=None):
    """
    Runs RTOC propagation across all functions in the database.
    """
    opd_seg = find_opd_segment()
    if default_toc is None and opd_seg:
        default_toc = ida_bytes.get_dword(opd_seg.start_ea + 4)

    if default_toc is None or default_toc == 0 or default_toc == ida_idaapi.BADADDR:
        print("[PS3IDA9] RTOC Fixer: Could not determine valid TOC address.")
        return 0

    print(f"[PS3IDA9] Running RTOC Fixer using TOC base 0x{default_toc:08X}...")

    total_xrefs = 0
    func_count = 0

    for func_ea in idautils.Functions():
        xrefs = fix_function_rtoc(func_ea, default_toc)
        total_xrefs += xrefs
        func_count += 1

    print(f"[PS3IDA9] RTOC Fixer complete: processed {func_count} functions, added {total_xrefs} cross-references.")
    return total_xrefs

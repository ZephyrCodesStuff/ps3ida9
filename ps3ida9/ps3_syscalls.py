"""
ps3_syscalls.py - PS3 LV2 Syscall & LV1 Hypercall analyzer and resolver for IDA Pro 9.3+
"""

import os
import json

try:
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment
    import ida_idaapi
    import ida_ua
    import ida_idp
    import idautils
    import idc
except ImportError:
    pass

class SyscallDatabase:
    _instance = None

    def __init__(self):
        self.lv2 = {}
        self.lv1 = {}
        self._load()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load(self):
        data_path = os.path.join(os.path.dirname(__file__), "..", "data", "ps3_syscalls.json")
        if os.path.exists(data_path):
            try:
                with open(data_path, "r", encoding="utf-8") as f:
                    db = json.load(f)
                    self.lv2 = db.get("lv2", {})
                    self.lv1 = db.get("lv1", {})
                print(f"[PS3IDA9] Loaded {len(self.lv2)} LV2 syscalls and {len(self.lv1)} LV1 hypercalls.")
            except Exception as e:
                print(f"[PS3IDA9] Failed to load syscall database: {e}")
        else:
            print(f"[PS3IDA9] Warning: Syscall database not found at {data_path}")

    def get_lv2_name(self, num):
        return self.lv2.get(str(num), f"sys_unknown_{num}")

    def get_lv1_name(self, num):
        return self.lv1.get(str(num), f"hv_unknown_{num}")


def trace_r11_constant(sc_ea, max_backtrack=16):
    """
    Backtracks before an 'sc' instruction to determine the constant value loaded into r11.
    Handles 'li r11, val', 'lis r11, val_hi', 'ori r11, r11, val_lo', 'addi r11, 0, val'.
    """
    pfn = ida_funcs.get_func(sc_ea)
    func_start = pfn.start_ea if pfn else sc_ea - 0x100

    r11_val = None
    r11_hi = 0

    insn = ida_ua.insn_t()
    
    # Backtrack up to max_backtrack instructions
    curr_ea = sc_ea
    for _ in range(max_backtrack):
        curr_ea = ida_bytes.prev_head(curr_ea, func_start)
        if curr_ea == ida_idaapi.BADADDR or curr_ea < func_start:
            break

        if ida_ua.decode_insn(insn, curr_ea) <= 0:
            break

        # Check if instruction modifies r11
        # In PowerPC:
        # Op1 is destination register (r11 = 11)
        if insn.Op1.type == ida_ua.o_reg and insn.Op1.reg == 11:
            mnem = ida_ua.ua_mnem(curr_ea)
            if not mnem:
                continue
            mnem = mnem.lower()

            if mnem in ["li", "addi"]:
                # li r11, imm or addi r11, 0, imm (where rA == 0)
                if insn.Op2.type == ida_ua.o_imm:
                    imm = insn.Op2.value
                    return (r11_hi | (imm & 0xFFFF))
                elif insn.Op3.type == ida_ua.o_imm and (insn.Op2.type == ida_ua.o_reg and insn.Op2.reg == 0):
                    imm = insn.Op3.value
                    return (r11_hi | (imm & 0xFFFF))
            elif mnem in ["lis", "addis"]:
                if insn.Op2.type == ida_ua.o_imm:
                    r11_hi = (insn.Op2.value & 0xFFFF) << 16
                    if r11_val is not None:
                        return r11_hi | (r11_val & 0xFFFF)
                    return r11_hi
            elif mnem == "ori":
                if insn.Op3.type == ida_ua.o_imm:
                    r11_val = insn.Op3.value & 0xFFFF
            else:
                # Some other write to r11 (e.g. mr r11, rX)
                break

    return r11_val


def process_syscalls():
    """
    Scans binary for PowerPC system calls (sc 2) and hypercalls (sc 1),
    resolves r11 constants, adds comments and renames stub wrapper functions.
    """
    db = SyscallDatabase.get_instance()
    
    total_found = 0
    resolved_count = 0

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        
        # Only check executable segments
        if not (seg.perm & ida_segment.SEGPERM_EXEC):
            continue

        ea = seg.start_ea
        end_ea = seg.end_ea

        while ea < end_ea:
            # Check 4-byte instruction:
            # 0x44000002 -> sc 2 (LV2)
            # 0x44000001 -> sc 1 (LV1)
            # 0x44000000 -> sc 0
            val = ida_bytes.get_dword(ea)
            if (val & 0xFFFFFFFC) == 0x44000000:
                sc_type = val & 0x3
                total_found += 1

                sys_num = trace_r11_constant(ea)
                if sys_num is not None:
                    if sc_type == 2 or sc_type == 0:
                        sys_name = db.get_lv2_name(sys_num)
                        comment = f"PS3 LV2 Syscall: {sys_name} (0x{sys_num:X} / #{sys_num})"
                    elif sc_type == 1:
                        sys_name = db.get_lv1_name(sys_num)
                        comment = f"PS3 LV1 Hypercall: {sys_name} (0x{sys_num:X} / #{sys_num})"
                    else:
                        sys_name = f"syscall_{sys_num}"
                        comment = f"PS3 Syscall {sc_type}: 0x{sys_num:X}"

                    ida_bytes.set_cmt(ea, comment, False)

                    # Check if enclosed in a small stub function
                    pfn = ida_funcs.get_func(ea)
                    if pfn and (pfn.end_ea - pfn.start_ea) <= 32:
                        cur_name = ida_name.get_name(pfn.start_ea)
                        if cur_name.startswith("sub_") or cur_name.startswith("loc_"):
                            stub_func_name = f"{sys_name}" if not sys_name.startswith("sys_") else sys_name
                            ida_name.set_name(pfn.start_ea, stub_func_name, ida_name.SN_NOWARN)
                            ida_bytes.set_cmt(pfn.start_ea, f"Wrapper for {comment}", True)

                    resolved_count += 1
                else:
                    ida_bytes.set_cmt(ea, f"PS3 System Call (sc {sc_type})", False)

            ea += 4

    print(f"[PS3IDA9] Syscall analysis complete: Found {total_found} syscall instructions, resolved {resolved_count} numbers.")
    return total_found, resolved_count

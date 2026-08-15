"""
ps3_nids_imports.py - PS3 NID resolution, PRX imports and exports parsing for IDA Pro 9.3+
"""

import os
import json

try:
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment
    import ida_entry
    import ida_idaapi
    import ida_lines
    import idautils
    import idc
except ImportError:
    pass

from .ps3_structures import apply_struct_to_ea

class NidDatabase:
    _instance = None

    def __init__(self):
        self.modules = {}
        self.by_nid = {}
        self._load()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load(self):
        data_path = os.path.join(os.path.dirname(__file__), "..", "data", "ps3_nids.json")
        if os.path.exists(data_path):
            try:
                with open(data_path, "r", encoding="utf-8") as f:
                    db = json.load(f)
                    self.modules = db.get("modules", {})
                    self.by_nid = db.get("by_nid", {})
                print(f"[PS3IDA9] Loaded NID database with {len(self.by_nid)} symbols across {len(self.modules)} modules.")
            except Exception as e:
                print(f"[PS3IDA9] Failed to load NID database: {e}")
        else:
            print(f"[PS3IDA9] Warning: NID database file not found at {data_path}")

    def resolve(self, module_name, nid_int):
        nid_hex = f"0x{nid_int:08X}"
        # Check module specific
        if module_name and module_name in self.modules:
            if nid_hex in self.modules[module_name]:
                return self.modules[module_name][nid_hex]
        # Fallback to global by_nid
        if nid_hex in self.by_nid:
            return self.by_nid[nid_hex]
        return f"nid_{nid_int:08X}"

def get_string_at(ea, max_len=64):
    """
    Reads a null-terminated C string from IDA database at address ea.
    """
    if ea == 0 or ea == ida_idaapi.BADADDR:
        return ""
    chars = []
    for i in range(max_len):
        b = ida_bytes.get_byte(ea + i)
        if b == 0:
            break
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            break
    return "".join(chars)

def process_import_stubs(start_ea, count=0):
    """
    Processes an array of _scelibstub_ppu32 import structures.
    """
    nids = NidDatabase.get_instance()
    ea = start_ea
    idx = 0
    resolved_count = 0

    while True:
        if count > 0 and idx >= count:
            break
            
        struct_size = ida_bytes.get_byte(ea)
        if struct_size != 0x2C:
            if count == 0:
                break

        apply_struct_to_ea(ea, "_scelibstub_ppu32")

        num_func = ida_bytes.get_word(ea + 0x06)
        num_var = ida_bytes.get_word(ea + 0x08)
        num_tlsvar = ida_bytes.get_word(ea + 0x0A)

        libname_ptr = ida_bytes.get_dword(ea + 0x10)
        func_nid_ptr = ida_bytes.get_dword(ea + 0x14)
        func_tbl_ptr = ida_bytes.get_dword(ea + 0x18)
        var_nid_ptr = ida_bytes.get_dword(ea + 0x1C)
        var_tbl_ptr = ida_bytes.get_dword(ea + 0x20)

        libname = get_string_at(libname_ptr) if libname_ptr != 0 else "NONAME"

        print(f"[PS3IDA9] Import stub [{idx}]: Library '{libname}', {num_func} funcs, {num_var} vars")

        # Set label for library name string
        if libname_ptr != 0:
            ida_name.set_name(libname_ptr, f"str_lib_{libname}", ida_name.SN_NOWARN)

        # Process functions
        if num_func > 0 and func_nid_ptr != 0 and func_tbl_ptr != 0:
            ida_name.set_name(func_nid_ptr, f"FNIDTable_{libname}", ida_name.SN_NOWARN)
            ida_name.set_name(func_tbl_ptr, f"StubTable_{libname}", ida_name.SN_NOWARN)

            for j in range(num_func):
                nid_ea = func_nid_ptr + j * 4
                stub_ref_ea = func_tbl_ptr + j * 4

                ida_bytes.create_dword(nid_ea, 4)
                ida_bytes.create_dword(stub_ref_ea, 4)

                fnid = ida_bytes.get_dword(nid_ea)
                func_name = nids.resolve(libname, fnid)

                ida_name.set_name(nid_ea, f"NID_{func_name}", ida_name.SN_NOWARN)
                ida_bytes.set_cmt(nid_ea, f"Import from {libname}: 0x{fnid:08X} -> {func_name}", False)

                stub_target = ida_bytes.get_dword(stub_ref_ea)
                if stub_target != 0 and stub_target != ida_idaapi.BADADDR:
                    # Create function at stub target
                    ida_funcs.add_func(stub_target, ida_idaapi.BADADDR)
                    full_func_name = f"_{libname}_{func_name}" if not func_name.startswith("nid_") else f"_import_{libname}_{fnid:08X}"
                    ida_name.set_name(stub_target, full_func_name, ida_name.SN_NOWARN)
                    ida_bytes.set_cmt(stub_target, f"Import stub for {libname}::{func_name} (NID: 0x{fnid:08X})", True)
                    resolved_count += 1

        # Process variables
        if num_var > 0 and var_nid_ptr != 0 and var_tbl_ptr != 0:
            ida_name.set_name(var_nid_ptr, f"VarNIDTable_{libname}", ida_name.SN_NOWARN)
            ida_name.set_name(var_tbl_ptr, f"VarTable_{libname}", ida_name.SN_NOWARN)

            for j in range(num_var):
                nid_ea = var_nid_ptr + j * 4
                var_ref_ea = var_tbl_ptr + j * 4

                ida_bytes.create_dword(nid_ea, 4)
                ida_bytes.create_dword(var_ref_ea, 4)

                vnid = ida_bytes.get_dword(nid_ea)
                var_name = nids.resolve(libname, vnid)

                ida_name.set_name(nid_ea, f"NID_var_{var_name}", ida_name.SN_NOWARN)
                var_target = ida_bytes.get_dword(var_ref_ea)
                if var_target != 0 and var_target != ida_idaapi.BADADDR:
                    ida_name.set_name(var_target, f"{libname}_{var_name}", ida_name.SN_NOWARN)

        ea += 0x2C
        idx += 1

    print(f"[PS3IDA9] Completed import stubs processing. Resolved {resolved_count} imported functions.")
    return resolved_count

def process_export_entries(start_ea, count=0):
    """
    Processes an array of _scelibent_ppu32 export structures.
    """
    nids = NidDatabase.get_instance()
    ea = start_ea
    idx = 0
    resolved_count = 0

    while True:
        if count > 0 and idx >= count:
            break
            
        struct_size = ida_bytes.get_byte(ea)
        if struct_size != 0x1C:
            if count == 0:
                break

        apply_struct_to_ea(ea, "_scelibent_ppu32")

        num_func = ida_bytes.get_word(ea + 0x06)
        num_var = ida_bytes.get_word(ea + 0x08)
        num_tlsvar = ida_bytes.get_word(ea + 0x0A)
        total_nids = num_func + num_var + num_tlsvar

        libname_ptr = ida_bytes.get_dword(ea + 0x10)
        nid_tbl_ptr = ida_bytes.get_dword(ea + 0x14)
        add_tbl_ptr = ida_bytes.get_dword(ea + 0x18)

        libname = get_string_at(libname_ptr) if libname_ptr != 0 else "MAIN"

        print(f"[PS3IDA9] Export entry [{idx}]: Library '{libname}', {num_func} funcs, {num_var} vars")

        if libname_ptr != 0:
            ida_name.set_name(libname_ptr, f"str_export_lib_{libname}", ida_name.SN_NOWARN)

        if total_nids > 0 and nid_tbl_ptr != 0 and add_tbl_ptr != 0:
            ida_name.set_name(nid_tbl_ptr, f"ExportNIDTable_{libname}", ida_name.SN_NOWARN)
            ida_name.set_name(add_tbl_ptr, f"ExportAddTable_{libname}", ida_name.SN_NOWARN)

            for j in range(total_nids):
                nid_ea = nid_tbl_ptr + j * 4
                add_ea = add_tbl_ptr + j * 4

                ida_bytes.create_dword(nid_ea, 4)
                ida_bytes.create_dword(add_ea, 4)

                fnid = ida_bytes.get_dword(nid_ea)
                func_name = nids.resolve(libname, fnid)

                ida_name.set_name(nid_ea, f"FNID_{func_name}", ida_name.SN_NOWARN)
                target_ea = ida_bytes.get_dword(add_ea)

                if target_ea != 0 and target_ea != ida_idaapi.BADADDR:
                    if j < num_func:
                        # On PS3, exported function tables typically point to an OPD entry
                        opd_func_ea = ida_bytes.get_dword(target_ea)
                        if opd_func_ea != 0 and opd_func_ea != ida_idaapi.BADADDR and ida_segment.getseg(opd_func_ea):
                            ida_funcs.add_func(opd_func_ea, ida_idaapi.BADADDR)
                            ida_name.set_name(target_ea, f"OPD_{func_name}", ida_name.SN_NOWARN)
                            ida_name.set_name(opd_func_ea, func_name, ida_name.SN_NOWARN)
                            ida_entry.add_entry(target_ea, opd_func_ea, func_name, 1)
                        else:
                            ida_funcs.add_func(target_ea, ida_idaapi.BADADDR)
                            ida_name.set_name(target_ea, func_name, ida_name.SN_NOWARN)
                            ida_entry.add_entry(target_ea, target_ea, func_name, 1)
                        resolved_count += 1
                    else:
                        ida_name.set_name(target_ea, f"Export_{libname}_{func_name}", ida_name.SN_NOWARN)

        ea += 0x1C
        idx += 1

    print(f"[PS3IDA9] Completed export entries processing. Resolved {resolved_count} exported functions.")
    return resolved_count

def scan_and_process_prx():
    """
    Scans entire binary memory for PRX / ELF import and export tables.
    """
    total_imports = 0
    total_exports = 0

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        
        seg_name = (ida_segment.get_segm_name(seg) or "").lower()
        start = seg.start_ea
        end = seg.end_ea

        # Check by section name or scan
        if "stub" in seg_name or "import" in seg_name or seg_name == ".lib.stub":
            total_imports += process_import_stubs(start, (end - start) // 0x2C)
        elif "ent" in seg_name or "export" in seg_name or seg_name == ".lib.ent":
            total_exports += process_export_entries(start, (end - start) // 0x1C)
        else:
            # Check if start of segment matches structsize == 0x2C or 0x1C
            size = end - start
            if size >= 0x2C and (size % 0x2C == 0):
                if ida_bytes.get_byte(start) == 0x2C and (size < 0x58 or ida_bytes.get_byte(start + 0x2C) == 0x2C):
                    total_imports += process_import_stubs(start, size // 0x2C)
            if size >= 0x1C and (size % 0x1C == 0):
                if ida_bytes.get_byte(start) == 0x1C and (size < 0x38 or ida_bytes.get_byte(start + 0x1C) == 0x1C):
                    total_exports += process_export_entries(start, size // 0x1C)

    return total_imports, total_exports

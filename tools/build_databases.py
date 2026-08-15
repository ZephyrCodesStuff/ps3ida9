#!/usr/bin/env python3
"""
build_databases.py - Combines NIDs, FNIDs, and Syscalls from Ps3GhidraScripts and ps3ida
into unified ps3_nids.json and ps3_syscalls.json files.
"""

import os
import re
import json
import xml.etree.ElementTree as ET

def normalize_hex(val):
    if isinstance(val, int):
        return f"0x{val:08X}"
    val_str = str(val).strip()
    if val_str.startswith("0x") or val_str.startswith("0X"):
        val_int = int(val_str, 16)
    else:
        val_int = int(val_str, 16) if all(c in '0123456789abcdefABCDEF' for c in val_str) else int(val_str)
    return f"0x{val_int:08X}"

def parse_ghidra_nids(nids_file):
    nids = {}
    if not os.path.exists(nids_file):
        print(f"Warning: {nids_file} not found")
        return nids
    with open(nids_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                nid_hex = normalize_hex(parts[0])
                name = parts[1].strip()
                nids[nid_hex] = name
    print(f"Parsed {len(nids)} NIDs from Ghidra nids.txt")
    return nids

def parse_ps3_xml(xml_file):
    modules = {}
    by_nid = {}
    if not os.path.exists(xml_file):
        print(f"Warning: {xml_file} not found")
        return modules, by_nid
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for group in root.findall("Group"):
        mod_name = group.get("name", "GLOBAL")
        if mod_name not in modules:
            modules[mod_name] = {}
        for entry in group.findall("Entry"):
            nid_str = entry.get("id")
            func_name = entry.get("name")
            if nid_str and func_name:
                nid_hex = normalize_hex(nid_str)
                modules[mod_name][nid_hex] = func_name
                by_nid[nid_hex] = func_name
    print(f"Parsed {len(modules)} modules and {len(by_nid)} NIDs from ps3.xml")
    return modules, by_nid

def parse_fnids_idh(idh_file):
    by_nid = {}
    if not os.path.exists(idh_file):
        print(f"Warning: {idh_file} not found")
        return by_nid
    pattern = re.compile(r'fnid\s*==\s*(0x[0-9a-fA-F]+)\s*\)\s*\{\s*return\s*"([^"]+)"')
    with open(idh_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        for m in pattern.finditer(content):
            nid_hex = normalize_hex(m.group(1))
            name = m.group(2)
            by_nid[nid_hex] = name
    print(f"Parsed {len(by_nid)} NIDs from fnids.idh")
    return by_nid

def parse_ghidra_syscalls(syscall_file):
    syscalls = {}
    if not os.path.exists(syscall_file):
        print(f"Warning: {syscall_file} not found")
        return syscalls
    with open(syscall_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                try:
                    num = int(parts[0])
                    name = parts[1].strip()
                    if not name.startswith("syscall_"):
                        syscalls[str(num)] = name
                except ValueError:
                    pass
    print(f"Parsed {len(syscalls)} syscalls from Ghidra syscall.txt")
    return syscalls

def parse_syscall_names_idh(idh_file):
    lv1 = {}
    lv2 = {}
    if not os.path.exists(idh_file):
        print(f"Warning: {idh_file} not found")
        return lv1, lv2
    with open(idh_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    # Extract get_hvcall_rawname
    hv_match = re.search(r'static\s+get_hvcall_rawname\s*\([^)]*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', content)
    if hv_match:
        hv_body = hv_match.group(1)
        for m in re.finditer(r'num\s*==\s*(\d+)\s*\)\s*return\s*"([^"]+)"', hv_body):
            num = int(m.group(1))
            name = m.group(2)
            lv1[str(num)] = name
            
    # Extract get_lv2_rawname
    lv2_match = re.search(r'static\s+get_lv2_rawname\s*\([^)]*\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}', content)
    if lv2_match:
        lv2_body = lv2_match.group(1)
        for m in re.finditer(r'num\s*==\s*(\d+)\s*\)\s*return\s*"([^"]+)"', lv2_body):
            num = int(m.group(1))
            name = m.group(2)
            if name != "not_implemented":
                lv2[str(num)] = name

    print(f"Parsed {len(lv1)} hypercalls (LV1) and {len(lv2)} syscalls (LV2) from syscall_names.idh")
    return lv1, lv2

def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    ghidra_dir = os.path.join(base_dir, "Ps3GhidraScripts")
    ps3ida_dir = os.path.join(base_dir, "ps3ida")
    out_dir = os.path.join(base_dir, "ps3ida9", "data")
    os.makedirs(out_dir, exist_ok=True)

    # 1. NIDs
    ghidra_nids = parse_ghidra_nids(os.path.join(ghidra_dir, "data", "nids.txt"))
    xml_modules, xml_nids = parse_ps3_xml(os.path.join(ps3ida_dir, "ps3.xml"))
    idh_nids = parse_fnids_idh(os.path.join(ps3ida_dir, "fnids.idh"))

    merged_by_nid = {}
    merged_by_nid.update(idh_nids)
    merged_by_nid.update(xml_nids)
    merged_by_nid.update(ghidra_nids)

    nids_db = {
        "modules": xml_modules,
        "by_nid": merged_by_nid
    }

    nids_path = os.path.join(out_dir, "ps3_nids.json")
    with open(nids_path, "w", encoding="utf-8") as f:
        json.dump(nids_db, f, indent=2)
    print(f"Saved {len(merged_by_nid)} total unique NIDs to {nids_path}")

    # 2. Syscalls
    ghidra_sys = parse_ghidra_syscalls(os.path.join(ghidra_dir, "data", "syscall.txt"))
    lv1, lv2_idh = parse_syscall_names_idh(os.path.join(ps3ida_dir, "syscall_names.idh"))

    merged_lv2 = {}
    merged_lv2.update(lv2_idh)
    merged_lv2.update(ghidra_sys)

    syscalls_db = {
        "lv2": merged_lv2,
        "lv1": lv1
    }

    syscalls_path = os.path.join(out_dir, "ps3_syscalls.json")
    with open(syscalls_path, "w", encoding="utf-8") as f:
        json.dump(syscalls_db, f, indent=2)
    print(f"Saved {len(merged_lv2)} LV2 syscalls and {len(lv1)} LV1 hypercalls to {syscalls_path}")

if __name__ == "__main__":
    main()

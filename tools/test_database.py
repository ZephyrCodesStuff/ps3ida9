#!/usr/bin/env python3
"""
test_database.py - Verification tests for ps3_nids.json and ps3_syscalls.json
"""

import sys
import os

# Add package directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ps3ida9.ps3_nids_imports import NidDatabase
from ps3ida9.ps3_syscalls import SyscallDatabase

def test_nids():
    db = NidDatabase.get_instance()
    assert len(db.by_nid) > 9000, f"Expected >9000 NIDs, got {len(db.by_nid)}"
    
    # Test specific well-known NIDs
    # sys_process_getpid: 0x1970CD7E (sys_libc)
    # cellAudioInit: 0x0B168F92
    assert db.resolve("cellAudio", 0x0B168F92) == "cellAudioInit", f"Failed to resolve cellAudioInit: {db.resolve('cellAudio', 0x0B168F92)}"
    assert db.resolve("sys_libc", 0x1970CD7E) == "getpid", f"Failed to resolve getpid: {db.resolve('sys_libc', 0x1970CD7E)}"
    assert db.resolve("", 0x1970CD7E) == "getpid", f"Failed global resolve getpid: {db.resolve('', 0x1970CD7E)}"
    
    print(f"[TEST PASS] NID Database: {len(db.by_nid)} NIDs, sample lookups verified.")

def test_syscalls():
    db = SyscallDatabase.get_instance()
    assert len(db.lv2) >= 600, f"Expected >=600 LV2 syscalls, got {len(db.lv2)}"
    assert len(db.lv1) >= 100, f"Expected >=100 LV1 hypercalls, got {len(db.lv1)}"
    
    # Test well-known syscalls:
    # 1: sys_process_getpid
    # 3: sys_process_exit
    assert db.get_lv2_name(1) == "sys_process_getpid", f"Failed LV2 syscall 1: {db.get_lv2_name(1)}"
    assert db.get_lv2_name(3) == "sys_process_exit", f"Failed LV2 syscall 3: {db.get_lv2_name(3)}"
    
    # Test hypercall:
    # 0: allocate_memory
    # 255: panic
    assert db.get_lv1_name(0) == "allocate_memory", f"Failed LV1 hypercall 0: {db.get_lv1_name(0)}"
    assert db.get_lv1_name(255) == "panic", f"Failed LV1 hypercall 255: {db.get_lv1_name(255)}"
    
    print(f"[TEST PASS] Syscall Database: {len(db.lv2)} LV2 syscalls, {len(db.lv1)} LV1 hypercalls verified.")

if __name__ == "__main__":
    test_nids()
    test_syscalls()
    print("\nAll database tests passed successfully!")

"""
ps3ida9_standalone.py - Standalone Script for IDA Pro 9.3+ (Run via File -> Script file... / Alt+F7)
"""

import sys
import os

_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from ps3ida9.ps3_analyzer import run_full_analysis

if __name__ == "__main__":
    run_full_analysis()

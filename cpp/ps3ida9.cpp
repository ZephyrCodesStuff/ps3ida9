/*
 * ps3ida9.cpp - High-Performance PS3 Reverse Engineering C++ Plugin for IDA
 * Pro 9.3+
 *
 * Combines OPD parsing, TOC (r2) establishment, fast RTOC instruction
 * propagation, and PowerPC LV2/LV1 system call analysis using the IDA 9 C++
 * SDK.
 *
 * Author: zeph, Gemini 3.7 Flash & the PS3 Reverse Engineering Community
 * License: GNU General Public License v3.0 (GPL-3.0)
 */

#include <allins.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <pro.h>
#include <segment.hpp>
#include <segregs.hpp>
#include <ua.hpp>
#include <xref.hpp>

#define GPR_COUNT 32

//--------------------------------------------------------------------------
// Plugin Context (IDA 9.x plugmod_t architecture)
//--------------------------------------------------------------------------
struct ps3_plugin_ctx_t : public plugmod_t {
  virtual bool idaapi run(size_t arg) override;

  ea_t process_opd();
  size_t run_rtoc_fixer(ea_t toc_ea);
  size_t scan_and_resolve_syscalls();
  size_t fix_function_rtoc(func_t *pfn, ea_t toc_ea);
  uint32 backtrack_r11(ea_t sc_ea, int max_backtrack = 16);
};

//--------------------------------------------------------------------------
// Parse .opd segment, create functions, establish TOC_BASE
//--------------------------------------------------------------------------
ea_t ps3_plugin_ctx_t::process_opd() {
  segment_t *p_seg = get_segm_by_name(".opd");
  if (p_seg == nullptr)
    p_seg = get_segm_by_name("OPD");

  // Heuristic search if segment not named explicitly
  if (p_seg == nullptr) {
    for (int i = 0; i < get_segm_qty(); ++i) {
      segment_t *s = getnseg(i);
      if (s == nullptr)
        continue;

      ea_t start = s->start_ea;
      ea_t end = qmin(s->end_ea, start + 0x1000);
      if (end - start < 16)
        continue;

      uint32 first_toc = get_dword(start + 4);
      if (first_toc == 0 || first_toc == 0xFFFFFFFF)
        continue;

      bool consistent = true;
      for (ea_t ea = start; ea < end - 8; ea += 8) {
        if (get_dword(ea + 4) != first_toc) {
          consistent = false;
          break;
        }
      }

      if (consistent) {
        p_seg = s;
        set_segm_name(s, ".opd");
        msg("[PS3IDA9 C++] Identified .opd segment by heuristic at 0x%a - "
            "0x%a\n",
            s->start_ea, s->end_ea);
        break;
      }
    }
  }

  if (p_seg == nullptr) {
    msg("[PS3IDA9 C++] Could not locate .opd segment.\n");
    return BADADDR;
  }

  ea_t start_ea = p_seg->start_ea;
  ea_t end_ea = p_seg->end_ea;
  ea_t primary_toc = BADADDR;
  size_t func_count = 0;

  msg("[PS3IDA9 C++] Processing OPD segment: 0x%a - 0x%a (%" FMT_Z " bytes)\n",
      start_ea, end_ea, (size_t)(end_ea - start_ea));

  for (ea_t ea = start_ea; ea < end_ea; ea += 8) {
    ea_t func_ea = get_dword(ea);
    ea_t toc_ea = get_dword(ea + 4);

    if (primary_toc == BADADDR && toc_ea != 0 && toc_ea != BADADDR)
      primary_toc = toc_ea;

    // Type descriptor
    create_dword(ea, 4);
    create_dword(ea + 4, 4);

    if (func_ea != 0 && func_ea != BADADDR) {
      segment_t *fseg = getseg(func_ea);
      if (fseg != nullptr) {
        func_t *pfn = get_func(func_ea);
        if (pfn == nullptr) {
          if (add_func(func_ea, BADADDR))
            func_count++;
        } else {
          func_count++;
        }
      }
    }
  }

  if (primary_toc != BADADDR) {
    set_name(primary_toc, "TOC_BASE", SN_NOWARN);
    msg("[PS3IDA9 C++] Established primary TOC at 0x%a. Defined %" FMT_Z
        " functions.\n",
        primary_toc, func_count);

    // Set r2 register default for all database segments
    int r2_idx = str2reg("r2");
    if (r2_idx != -1) {
      for (int i = 0; i < get_segm_qty(); ++i) {
        segment_t *s = getnseg(i);
        if (s != nullptr) {
          set_default_sreg_value_ea(s->start_ea, r2_idx, primary_toc);
          split_sreg_range(s->start_ea, r2_idx, primary_toc, SR_user, true);
        }
      }
    }
  }

  return primary_toc;
}

//--------------------------------------------------------------------------
// RTOC Fixer for a single function (In-memory register emulation)
//--------------------------------------------------------------------------
size_t ps3_plugin_ctx_t::fix_function_rtoc(func_t *pfn, ea_t toc_ea) {
  if (pfn == nullptr)
    return 0;

  uint64 g_gpr[GPR_COUNT];
  bool g_act[GPR_COUNT];

  memset(g_gpr, 0, sizeof(g_gpr));
  memset(g_act, 0, sizeof(g_act));

  // Initialize r2 (TOC)
  g_gpr[2] = toc_ea;
  g_act[2] = true;

  size_t xrefs_added = 0;
  insn_t insn;

  for (ea_t ea = pfn->start_ea; ea < pfn->end_ea; ea = get_item_end(ea)) {
    if (decode_insn(&insn, ea) <= 0)
      continue;

    const op_t &op1 = insn.ops[0];
    const op_t &op2 = insn.ops[1];
    const op_t &op3 = insn.ops[2];

    // 1. Register moves
    if (insn.itype == PPC_mr && op1.type == o_reg && op2.type == o_reg) {
      if (op1.reg < GPR_COUNT && op2.reg < GPR_COUNT) {
        if (g_act[op2.reg]) {
          g_gpr[op1.reg] = g_gpr[op2.reg];
          g_act[op1.reg] = true;
        } else {
          g_act[op1.reg] = false;
        }
      }
    }
    // 2. Load immediate
    else if (insn.itype == PPC_li && op1.type == o_reg) {
      if (op1.reg < GPR_COUNT) {
        g_gpr[op1.reg] = op2.value;
        g_act[op1.reg] = true;
      }
    }
    // 3. Load immediate shifted
    else if (insn.itype == PPC_lis && op1.type == o_reg) {
      if (op1.reg < GPR_COUNT) {
        g_gpr[op1.reg] = (op2.value & 0xFFFF) << 16;
        g_act[op1.reg] = true;
      }
    }
    // 4. Add immediate
    else if (insn.itype == PPC_addi && op1.type == o_reg) {
      if (op1.reg < GPR_COUNT) {
        if (op2.type == o_reg && op2.reg < GPR_COUNT && g_act[op2.reg]) {
          g_gpr[op1.reg] = g_gpr[op2.reg] + op3.value;
          g_act[op1.reg] = true;
        } else if (op2.type == o_imm) {
          g_gpr[op1.reg] = op2.value;
          g_act[op1.reg] = true;
        } else {
          g_act[op1.reg] = false;
        }
      }
    }
    // 5. Add immediate shifted
    else if (insn.itype == PPC_addis && op1.type == o_reg) {
      if (op1.reg < GPR_COUNT) {
        if (op2.type == o_reg && op2.reg < GPR_COUNT && g_act[op2.reg]) {
          g_gpr[op1.reg] = g_gpr[op2.reg] + ((op3.value & 0xFFFF) << 16);
          g_act[op1.reg] = true;
        } else {
          g_act[op1.reg] = false;
        }
      }
    }
    // 6. Bitwise OR immediate
    else if (insn.itype == PPC_ori && op1.type == o_reg && op2.type == o_reg) {
      if (op1.reg < GPR_COUNT && op2.reg < GPR_COUNT && g_act[op2.reg]) {
        g_gpr[op1.reg] = g_gpr[op2.reg] | (op3.value & 0xFFFF);
        g_act[op1.reg] = true;
      }
    }
    // 7. Memory Loads (lwz, ld, lhz, lbz, lfs, lfd, etc.)
    else if ((insn.itype == PPC_lwz || insn.itype == PPC_ld ||
              insn.itype == PPC_lhz || insn.itype == PPC_lbz ||
              insn.itype == PPC_lfs || insn.itype == PPC_lfd) &&
             (op2.type == o_displ || op2.type == o_phrase)) {
      int rD = (op1.type == o_reg && op1.reg < GPR_COUNT) ? op1.reg : -1;
      int rA = (op2.reg < GPR_COUNT) ? op2.reg : -1;
      sval_t displ = (sval_t)op2.addr;

      if (rA >= 0 && g_act[rA]) {
        ea_t target_ea = (ea_t)(g_gpr[rA] + displ);
        if (getseg(target_ea) != nullptr) {
          add_dref(ea, target_ea, dr_R);
          xrefs_added++;

          if (rD >= 0 && rD != 2) {
            if (insn.itype == PPC_lwz) {
              g_gpr[rD] = get_dword(target_ea);
              g_act[rD] = true;
            } else if (insn.itype == PPC_ld) {
              g_gpr[rD] = get_qword(target_ea);
              g_act[rD] = true;
            } else {
              g_act[rD] = false;
            }
          }
        } else {
          if (rD >= 0 && rD != 2)
            g_act[rD] = false;
        }
      } else {
        if (rD >= 0 && rD != 2)
          g_act[rD] = false;
      }
    }
    // 8. Memory Stores (stw, std, sth, stb)
    else if ((insn.itype == PPC_stw || insn.itype == PPC_std ||
              insn.itype == PPC_sth || insn.itype == PPC_stb) &&
             (op2.type == o_displ || op2.type == o_phrase)) {
      int rA = (op2.reg < GPR_COUNT) ? op2.reg : -1;
      sval_t displ = (sval_t)op2.addr;

      if (rA >= 0 && g_act[rA]) {
        ea_t target_ea = (ea_t)(g_gpr[rA] + displ);
        if (getseg(target_ea) != nullptr) {
          add_dref(ea, target_ea, dr_W);
          xrefs_added++;
        }
      }
    }
    // 9. Other writes to general registers (invalidate tracking except r2/r30)
    else if (op1.type == o_reg && op1.reg < GPR_COUNT && op1.reg != 2 &&
             op1.reg != 30) {
      g_act[op1.reg] = false;
    }

    // Maintain r2
    if (!g_act[2]) {
      g_gpr[2] = toc_ea;
      g_act[2] = true;
    }
  }

  return xrefs_added;
}

//--------------------------------------------------------------------------
// Full binary RTOC Propagation Fixer
//--------------------------------------------------------------------------
size_t ps3_plugin_ctx_t::run_rtoc_fixer(ea_t toc_ea) {
  msg("[PS3IDA9 C++] Running high-speed RTOC Fixer with TOC=0x%a...\n", toc_ea);
  size_t total_funcs = get_func_qty();
  size_t total_xrefs = 0;

  for (size_t i = 0; i < total_funcs; ++i) {
    func_t *pfn = getn_func(i);
    if (pfn != nullptr)
      total_xrefs += fix_function_rtoc(pfn, toc_ea);
  }

  msg("[PS3IDA9 C++] RTOC Fixer complete: Processed %" FMT_Z
      " functions, created %" FMT_Z " cross-references.\n",
      total_funcs, total_xrefs);
  return total_xrefs;
}

//--------------------------------------------------------------------------
// Backtrack r11 register value before an 'sc' instruction
//--------------------------------------------------------------------------
uint32 ps3_plugin_ctx_t::backtrack_r11(ea_t sc_ea, int max_backtrack) {
  func_t *pfn = get_func(sc_ea);
  ea_t func_start = pfn ? pfn->start_ea : (sc_ea - 0x100);

  insn_t insn;
  ea_t curr = sc_ea;

  for (int i = 0; i < max_backtrack; ++i) {
    curr = prev_head(curr, func_start);
    if (curr == BADADDR || curr < func_start)
      break;

    if (decode_insn(&insn, curr) <= 0)
      break;

    if (insn.ops[0].type == o_reg && insn.ops[0].reg == 11) {
      if (insn.itype == PPC_li || insn.itype == PPC_addi) {
        if (insn.ops[1].type == o_imm)
          return (uint32)insn.ops[1].value;
        else if (insn.ops[2].type == o_imm && insn.ops[1].type == o_reg &&
                 insn.ops[1].reg == 0)
          return (uint32)insn.ops[2].value;
      }
      break;
    }
  }

  return 0xFFFFFFFF;
}

//--------------------------------------------------------------------------
// Scan and annotate PowerPC system calls
//--------------------------------------------------------------------------
size_t ps3_plugin_ctx_t::scan_and_resolve_syscalls() {
  size_t sc_count = 0;
  size_t resolved = 0;

  for (int i = 0; i < get_segm_qty(); ++i) {
    segment_t *s = getnseg(i);
    if (s == nullptr || !(s->perm & SEGPERM_EXEC))
      continue;

    for (ea_t ea = s->start_ea; ea < s->end_ea; ea += 4) {
      uint32 val = get_dword(ea);
      if ((val & 0xFFFFFFFC) == 0x44000000) {
        uint32 sc_type = val & 0x3;
        sc_count++;

        uint32 num = backtrack_r11(ea);
        if (num != 0xFFFFFFFF) {
          qstring cmt;
          if (sc_type == 2 || sc_type == 0)
            cmt.sprnt("PS3 LV2 Syscall #%u (0x%X)", num, num);
          else if (sc_type == 1)
            cmt.sprnt("PS3 LV1 Hypercall #%u (0x%X)", num, num);

          set_cmt(ea, cmt.c_str(), false);

          func_t *pfn = get_func(ea);
          if (pfn && (pfn->end_ea - pfn->start_ea) <= 32) {
            qstring fname;
            get_func_name(&fname, pfn->start_ea);
            if (fname.empty() || fname.find("sub_") == 0 ||
                fname.find("loc_") == 0) {
              fname.sprnt("sys_%u", num);
              set_name(pfn->start_ea, fname.c_str(), SN_NOWARN);
            }
          }
          resolved++;
        } else {
          set_cmt(ea,
                  sc_type == 1 ? "PS3 LV1 Hypercall (sc 1)"
                               : "PS3 LV2 Syscall (sc 2)",
                  false);
        }
      }
    }
  }

  msg("[PS3IDA9 C++] Syscall analysis complete: Found %" FMT_Z
      " syscall sites, resolved %" FMT_Z ".\n",
      sc_count, resolved);
  return resolved;
}

//--------------------------------------------------------------------------
// Plugin Entry (Invoked when triggered from IDA UI / Hotkey)
//--------------------------------------------------------------------------
bool idaapi ps3_plugin_ctx_t::run(size_t) {
  msg("\n=========================================================\n");
  msg("[PS3IDA9 C++] Starting PS3 Binary Analysis for IDA 9.3+...\n");
  msg("=========================================================\n");

  ea_t toc = process_opd();
  if (toc != BADADDR)
    run_rtoc_fixer(toc);

  scan_and_resolve_syscalls();

  msg("\n[PS3IDA9 C++] Full analysis completed successfully!\n");
  return true;
}

//--------------------------------------------------------------------------
// Plugin Initialization
//--------------------------------------------------------------------------
static plugmod_t *idaapi init() {
  if (PH.id != PLFM_PPC) {
    // Return nullptr if not PowerPC
    return nullptr;
  }
  return new ps3_plugin_ctx_t;
}

//--------------------------------------------------------------------------
// PLUGIN Descriptor
//--------------------------------------------------------------------------
plugin_t PLUGIN = {IDP_INTERFACE_VERSION,
                   PLUGIN_MULTI,
                   init,
                   nullptr,
                   nullptr,
                   "PS3 IDA Pro 9.3+ Native Tools (C++)",
                   "High-performance PS3 binary analyzer for IDA Pro 9.3+",
                   "PS3 IDA Pro 9 Tools (C++)",
                   "Ctrl-Alt-P"};

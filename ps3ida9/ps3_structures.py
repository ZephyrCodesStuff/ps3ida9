"""
ps3_structures.py - PS3 C-structures registration and application for IDA Pro 9.3+
"""

try:
    import ida_typeinf
    import ida_bytes
    import ida_name
    import ida_idaapi
except ImportError:
    pass

PS3_C_DECLARATIONS = """
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef int int32_t;

typedef struct opd32_t {
    uint32_t sub;
    uint32_t toc;
} opd32_t;

typedef struct opd64_t {
    uint64_t sub;
    uint64_t toc;
    uint32_t opd32_sub;
    uint32_t opd32_toc;
} opd64_t;

typedef struct sys_process_param_t {
    uint32_t size;
    uint32_t magic;
    uint32_t version;
    uint32_t sdk_version;
    int32_t  primary_prio;
    uint32_t primary_stacksize;
    uint32_t malloc_pagesize;
    uint32_t ppc_seg;
    uint32_t crash_dump_param_addr;
} sys_process_param_t;

typedef struct sys_process_prx_info_t {
    uint32_t size;
    uint32_t magic;
    uint32_t version;
    uint32_t sdk_version;
    uint32_t libent_start;
    uint32_t libent_end;
    uint32_t libstub_start;
    uint32_t libstub_end;
    uint8_t  major_version;
    uint8_t  minor_version;
    uint8_t  reserved[6];
} sys_process_prx_info_t;

typedef struct _scemoduleinfo_common {
    uint16_t module_attribute;
    uint8_t  module_version[2];
    char     module_name[27];
    uint8_t  infover;
} _scemoduleinfo_common;

typedef struct _scemoduleinfo_ppu32 {
    _scemoduleinfo_common c;
    uint32_t gp_value;
    uint32_t ent_top;
    uint32_t ent_end;
    uint32_t stub_top;
    uint32_t stub_end;
} _scemoduleinfo_ppu32;

typedef struct _scemoduleinfo_ppu64 {
    _scemoduleinfo_common c;
    uint64_t gp_value;
    uint64_t ent_top;
    uint64_t ent_end;
    uint64_t stub_top;
    uint64_t stub_end;
} _scemoduleinfo_ppu64;

typedef struct _scelibstub_common {
    uint8_t  structsize;
    uint8_t  reserved1;
    uint16_t version;
    uint16_t attribute;
    uint16_t num_func;
    uint16_t num_var;
    uint16_t num_tlsvar;
    uint8_t  reserved2[4];
} _scelibstub_common;

typedef struct _scelibstub_ppu32 {
    _scelibstub_common c;
    uint32_t libname;
    uint32_t func_nidtable;
    uint32_t func_table;
    uint32_t var_nidtable;
    uint32_t var_table;
    uint32_t tls_nidtable;
    uint32_t tls_table;
} _scelibstub_ppu32;

typedef struct _scelibstub_ppu64 {
    _scelibstub_common c;
    uint64_t libname;
    uint64_t func_nidtable;
    uint64_t func_table;
    uint64_t var_nidtable;
    uint64_t var_table;
    uint64_t tls_nidtable;
    uint64_t tls_table;
} _scelibstub_ppu64;

typedef struct _scelibent_common {
    uint8_t  structsize;
    uint8_t  auxattribute;
    uint16_t version;
    uint16_t attribute;
    uint16_t num_func;
    uint16_t num_var;
    uint16_t num_tlsvar;
    uint8_t  hashinfo;
    uint8_t  hashinfotls;
    uint8_t  reserved2[1];
    uint8_t  nidaltsets;
} _scelibent_common;

typedef struct _scelibent_ppu32 {
    _scelibent_common c;
    uint32_t libname;
    uint32_t nidtable;
    uint32_t addtable;
} _scelibent_ppu32;

typedef struct _scelibent_ppu64 {
    _scelibent_common c;
    uint64_t libname;
    uint64_t nidtable;
    uint64_t addtable;
} _scelibent_ppu64;
"""

def register_ps3_types():
    """
    Parses and adds PS3 C-structure types to IDA Pro's Local Types.
    """
    try:
        idati = ida_typeinf.get_idati()
        errors = ida_typeinf.parse_decls(idati, PS3_C_DECLARATIONS, None, ida_typeinf.HTI_DCL)
        if errors == 0:
            print("[PS3IDA9] Successfully imported PS3 data types into Local Types.")
            return True
        else:
            print(f"[PS3IDA9] parse_decls returned {errors} errors while importing types.")
            return False
    except Exception as e:
        print(f"[PS3IDA9] Error registering PS3 types: {e}")
        return False

def apply_struct_to_ea(ea, struct_name):
    """
    Applies a named C-struct type at a specific effective address in IDA.
    """
    try:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(ida_typeinf.get_idati(), struct_name):
            register_ps3_types()
            if not tif.get_named_type(ida_typeinf.get_idati(), struct_name):
                return False
        
        size = tif.get_size()
        if size > 0:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
            return ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
    except Exception as e:
        print(f"[PS3IDA9] Failed to apply struct {struct_name} at 0x{ea:X}: {e}")
    return False

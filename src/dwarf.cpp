/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <stdlib.h>
#include <sys/utsname.h>
#include "dwarf.h"
#include "log.h"


enum {
    DW_CFA_nop                     = 0x0,
    DW_CFA_set_loc                 = 0x1,
    DW_CFA_advance_loc1            = 0x2,
    DW_CFA_advance_loc2            = 0x3,
    DW_CFA_advance_loc4            = 0x4,
    DW_CFA_offset_extended         = 0x5,
    DW_CFA_restore_extended        = 0x6,
    DW_CFA_undefined               = 0x7,
    DW_CFA_same_value              = 0x8,
    DW_CFA_register                = 0x9,
    DW_CFA_remember_state          = 0xa,
    DW_CFA_restore_state           = 0xb,
    DW_CFA_def_cfa                 = 0xc,
    DW_CFA_def_cfa_register        = 0xd,
    DW_CFA_def_cfa_offset          = 0xe,
    DW_CFA_def_cfa_expression      = 0xf,
    DW_CFA_expression              = 0x10,
    DW_CFA_offset_extended_sf      = 0x11,
    DW_CFA_def_cfa_sf              = 0x12,
    DW_CFA_def_cfa_offset_sf       = 0x13,
    DW_CFA_val_offset              = 0x14,
    DW_CFA_val_offset_sf           = 0x15,
    DW_CFA_val_expression          = 0x16,
    DW_CFA_AARCH64_negate_ra_state = 0x2d,
    DW_CFA_GNU_args_size           = 0x2e,

    DW_CFA_advance_loc             = 0x1,
    DW_CFA_offset                  = 0x2,
    DW_CFA_restore                 = 0x3,
};

enum {
    DW_OP_breg_pc = 0x70 + DW_REG_PC,
    DW_OP_const1u = 0x08,
    DW_OP_const1s = 0x09,
    DW_OP_const2u = 0x0a,
    DW_OP_const2s = 0x0b,
    DW_OP_const4u = 0x0c,
    DW_OP_const4s = 0x0d,
    DW_OP_constu  = 0x10,
    DW_OP_consts  = 0x11,
    DW_OP_minus   = 0x1c,
    DW_OP_plus    = 0x22,
};


FrameDesc FrameDesc::empty_frame = {0, DW_REG_SP | EMPTY_FRAME_SIZE << 8, DW_SAME_FP, -EMPTY_FRAME_SIZE};
FrameDesc FrameDesc::default_frame = {0, DW_REG_FP | LINKED_FRAME_SIZE << 8, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT};


DwarfParser::DwarfParser(const char* name, const char* image_base) {
    _name = name;
    _image_base = image_base;

    _capacity = 128;
    _count = 0;
    _table = (FrameDesc*)malloc(_capacity * sizeof(FrameDesc));
    _prev = NULL;

    _code_align = sizeof(instruction_t);
    _data_align = -(int)sizeof(void*);
}

void DwarfParser::parseUnwindOpcode(u64 location, u32 opcode, const char* eh_frame) {
    static int arch = 0;

    if (arch == 0) {
        utsname sysinfo;
        if (uname(&sysinfo) == 0) {
            if (strstr(sysinfo.machine, "x86")) {
                arch = 1;
            } else {
                arch = 2;
            }
        }
    }

    u32 opcode_kind = opcode & 0x0f000000;
    u32 opcode_data = opcode & 0x00ffffff;

    if (arch == 1) {
        if (opcode_kind == 2) {
            addRecord(location - (u64)_image_base, DW_REG_SP, opcode_data * 16, DW_SAME_FP, 0);// TODO: This is wrong, Dwarf is a big asshole on RA
        } else if (opcode_kind == 3) { // Dwarf
            _ptr = eh_frame + opcode_data;
            parseFde();
        } else if (opcode_kind == 4) { // Frame pointer
            addRecord(location - (u64)_image_base, DW_REG_FP, LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT);
        }
    } else {
        if (opcode_kind == 1) { // Frame pointer
            addRecord(location - (u64)_image_base, DW_REG_FP, LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT);
        } else if (opcode_kind == 2) { // Frameless (Stack-Immediate)
            addRecord(location - (u64)_image_base, DW_REG_SP, opcode_data * sizeof(void*), DW_SAME_FP, -1 * (int)sizeof(void*));
        } else if (opcode_kind == 3) { // TODO: Find actual example on this & check byte code
            /* u32 instruction_offset = (opcode_data & 0x00f00000) >> 20;
             u32 stack_adjust = (opcode_data & 0x000E0000) >> 17;
             addRecord(location - (u64)_image_base, DW_REG_SP, + (stack_adjust * sizeof(void*)), DW_SAME_FP, -1 * sizeof(void*));
             */
        } else if (opcode_kind == 4) { // Dwarf
            _ptr = eh_frame + opcode_data;
            parseFde();
        }
    }
}

void DwarfParser::parseUnwindPage(const char* page, u32 address, const char* eh_frame, u32* global_opcodes, u32 global_opcodes_len) {
    _ptr = page;

    u32 kind = get32();
    if (kind != 2 && kind != 3) { // can happen on last page
        return;
    }

    u16 entries_offset = get16();
    u16 entries_len = get16();

    if (kind == 2) {
        _ptr = page + entries_offset;
        for (u16 i = 0; i < entries_len; i++) {
            u32 location = get32();
            u32 opcode = get32();

            const char* ptr = _ptr;
            parseUnwindOpcode(location, opcode, eh_frame);
            _ptr = ptr;
        }
    }

    if (kind == 3) {
        u16 local_opcodes_offset = get16();
        get16(); // local opcode length
        u32* local_opcodes = (u32*)(page + local_opcodes_offset);

        _ptr = page + entries_offset;
        for (int i = 0; i < entries_len; ++i) {
            u32 data = get32();
            u32 opcode_index = (0xf0000000 & data) > 24;
            u64 location = (0x0fffffff & data) + address + (u64)_image_base;
            u32 opcode = opcode_index < global_opcodes_len ? global_opcodes[opcode_index] : local_opcodes[opcode_index - global_opcodes_len];

            const char* ptr = _ptr;
            parseUnwindOpcode(location, opcode, eh_frame);
            _ptr = ptr;
        }
    }
}

void DwarfParser::parseUnwindInfo(const char* unwind_info, const char* eh_frame, const char* stubs_address) {
    _ptr = unwind_info;

    u32 version = get32();
    if (version != 1) { // only version 1 is supported
        return;
    }

    u32 global_opcodes_offset = get32();
    u32 global_opcodes_len = get32();
    u32* global_opcodes = (u32*)(unwind_info + global_opcodes_offset);

    // personalities_offset & personalities_Len
    get32();
    get32();

    u32 pages_offset = get32();
    u32 pages_len = get32();

    // prepare to parse the pages
    _ptr = unwind_info + pages_offset;

    for (int i = 0; i < pages_len; ++i) {
        u32 first_address = get32();
        u32 second_level_page_offset = get32();

        // lsda_index_offset
        get32();

        const char* ptr = _ptr;
        parseUnwindPage(unwind_info + second_level_page_offset, first_address, eh_frame, global_opcodes, global_opcodes_len);
        _ptr = ptr;
    }

    if (stubs_address) {
        addRecord(stubs_address - _image_base, DW_REG_SP, EMPTY_FRAME_SIZE << 8, DW_SAME_FP, -EMPTY_FRAME_SIZE);
    }

    std::sort(_table, _table + _count, [](const FrameDesc& a, const FrameDesc& b) {
        return a.loc < b.loc;
    });
}

void DwarfParser::parseEhFrameHdr(const char* eh_frame_hdr) {
    u8 version = eh_frame_hdr[0];
    u8 eh_frame_ptr_enc = eh_frame_hdr[1];
    u8 fde_count_enc = eh_frame_hdr[2];
    u8 table_enc = eh_frame_hdr[3];

    if (version != 1 || (eh_frame_ptr_enc & 0x7) != 0x3 || (fde_count_enc & 0x7) != 0x3 || (table_enc & 0xf7) != 0x33) {
        Log::warn("Unsupported .eh_frame_hdr [%02x%02x%02x%02x] in %s",
                  version, eh_frame_ptr_enc, fde_count_enc, table_enc, _name);
        return;
    }

    int fde_count = *(int*)(eh_frame_hdr + 8);
    int* table =  (int*)(eh_frame_hdr + 16);
    for (int i = 0; i < fde_count; i++) {
        _ptr = eh_frame_hdr + table[i * 2];
        parseFde();
    }
}

void DwarfParser::parseCie() {
    u32 cie_len = get32();
    if (cie_len == 0 || cie_len == 0xffffffff) {
        return;
    }

    const char* cie_start = _ptr;
    _ptr += 5;
    while (*_ptr++) {}
    _code_align = getLeb();
    _data_align = getSLeb();
    _ptr = cie_start + cie_len;
}

void DwarfParser::parseFde() {
    u32 fde_len = get32();
    if (fde_len == 0 || fde_len == 0xffffffff) {
        return;
    }

    const char* fde_start = _ptr;
    u32 cie_offset = get32();
    if (_count == 0) {
        _ptr = fde_start - cie_offset;
        parseCie();
        _ptr = fde_start + 4;
    }

    u32 range_start = getPtr() - _image_base;
    u32 range_len = get32();
    _ptr += getLeb();
    parseInstructions(range_start, fde_start + fde_len);
    addRecord(range_start + range_len, DW_REG_FP, LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE, -LINKED_FRAME_SIZE + DW_STACK_SLOT);
}

void DwarfParser::parseInstructions(u32 loc, const char* end) {
    const u32 code_align = _code_align;
    const int data_align = _data_align;

    u32 cfa_reg = DW_REG_SP;
    int cfa_off = EMPTY_FRAME_SIZE;
    int fp_off = DW_SAME_FP;
    int pc_off = -EMPTY_FRAME_SIZE;

    u32 rem_cfa_reg = DW_REG_SP;
    int rem_cfa_off = EMPTY_FRAME_SIZE;
    int rem_fp_off = DW_SAME_FP;
    int rem_pc_off = -EMPTY_FRAME_SIZE;

    while (_ptr < end) {
        u8 op = get8();
        switch (op >> 6) {
            case 0:
                switch (op) {
                    case DW_CFA_nop:
                    case DW_CFA_set_loc:
                        _ptr = end;
                        break;
                    case DW_CFA_advance_loc1:
                        addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                        loc += get8() * code_align;
                        break;
                    case DW_CFA_advance_loc2:
                        addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                        loc += get16() * code_align;
                        break;
                    case DW_CFA_advance_loc4:
                        addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                        loc += get32() * code_align;
                        break;
                    case DW_CFA_offset_extended:
                        switch (getLeb()) {
                            case DW_REG_FP: fp_off = getLeb() * data_align; break;
                            case DW_REG_PC: pc_off = getLeb() * data_align; break;
                            default: skipLeb();
                        }
                        break;
                    case DW_CFA_restore_extended:
                    case DW_CFA_undefined:
                    case DW_CFA_same_value:
                        if (getLeb() == DW_REG_FP) {
                            fp_off = DW_SAME_FP;
                        }
                        break;
                    case DW_CFA_register:
                        skipLeb();
                        skipLeb();
                        break;
                    case DW_CFA_remember_state:
                        rem_cfa_reg = cfa_reg;
                        rem_cfa_off = cfa_off;
                        rem_fp_off = fp_off;
                        rem_pc_off = pc_off;
                        break;
                    case DW_CFA_restore_state:
                        cfa_reg = rem_cfa_reg;
                        cfa_off = rem_cfa_off;
                        fp_off = rem_fp_off;
                        pc_off = rem_pc_off;
                        break;
                    case DW_CFA_def_cfa:
                        cfa_reg = getLeb();
                        cfa_off = getLeb();
                        break;
                    case DW_CFA_def_cfa_register:
                        cfa_reg = getLeb();
                        break;
                    case DW_CFA_def_cfa_offset:
                        cfa_off = getLeb();
                        break;
                    case DW_CFA_def_cfa_expression: {
                        u32 len = getLeb();
                        cfa_reg = len == 11 ? DW_REG_PLT : DW_REG_INVALID;
                        cfa_off = DW_STACK_SLOT;
                        _ptr += len;
                        break;
                    }
                    case DW_CFA_expression:
                        skipLeb();
                        _ptr += getLeb();
                        break;
                    case DW_CFA_offset_extended_sf:
                        switch (getLeb()) {
                            case DW_REG_FP: fp_off = getSLeb() * data_align; break;
                            case DW_REG_PC: pc_off = getSLeb() * data_align; break;
                            default: skipLeb();
                        }
                        break;
                    case DW_CFA_def_cfa_sf:
                        cfa_reg = getLeb();
                        cfa_off = getSLeb() * data_align;
                        break;
                    case DW_CFA_def_cfa_offset_sf:
                        cfa_off = getSLeb() * data_align;
                        break;
                    case DW_CFA_val_offset:
                    case DW_CFA_val_offset_sf:
                        skipLeb();
                        skipLeb();
                        break;
                    case DW_CFA_val_expression:
                        if (getLeb() == DW_REG_PC) {
                            int pc_off = parseExpression();
                            if (pc_off != 0) {
                                fp_off = DW_PC_OFFSET | (pc_off << 1);
                            }
                        } else {
                            _ptr += getLeb();
                        }
                        break;
#ifdef __aarch64__
                    case DW_CFA_AARCH64_negate_ra_state:
                        break;
#endif
                    case DW_CFA_GNU_args_size:
                        skipLeb();
                        break;
                    default:
                        Log::warn("Unknown DWARF instruction 0x%x in %s", op, _name);
                        return;
                }
                break;
            case DW_CFA_advance_loc:
                addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
                loc += (op & 0x3f) * code_align;
                break;
            case DW_CFA_offset:
                switch (op & 0x3f) {
                    case DW_REG_FP: fp_off = getLeb() * data_align; break;
                    case DW_REG_PC: pc_off = getLeb() * data_align; break;
                    default: skipLeb();
                }
                break;
            case DW_CFA_restore:
                if ((op & 0x3f) == DW_REG_FP) {
                    fp_off = DW_SAME_FP;
                }
                break;
        }
    }

    addRecord(loc, cfa_reg, cfa_off, fp_off, pc_off);
}

// Parse a limited subset of DWARF expressions, which is used in DW_CFA_val_expression
// to point to the previous PC relative to the current PC.
// Returns the offset of the previous PC from the current PC.
int DwarfParser::parseExpression() {
    int pc_off = 0;
    int tos = 0;

    u32 len = getLeb();
    const char* end = _ptr + len;

    while (_ptr < end) {
        u8 op = get8();
        switch (op) {
            case DW_OP_breg_pc:
                pc_off = getSLeb();
                break;
            case DW_OP_const1u:
                tos = get8();
                break;
            case DW_OP_const1s:
                tos = (signed char)get8();
                break;
            case DW_OP_const2u:
                tos = get16();
                break;
            case DW_OP_const2s:
                tos = (short)get16();
                break;
            case DW_OP_const4u:
            case DW_OP_const4s:
                tos = get32();
                break;
            case DW_OP_constu:
                tos = getLeb();
                break;
            case DW_OP_consts:
                tos = getSLeb();
                break;
            case DW_OP_minus:
                pc_off -= tos;
                break;
            case DW_OP_plus:
                pc_off += tos;
                break;
            default:
                Log::warn("Unknown DWARF opcode 0x%x in %s", op, _name);
                _ptr = end;
                return 0;
        }
    }

    return pc_off;
}

void DwarfParser::addRecord(u32 loc, u32 cfa_reg, int cfa_off, int fp_off, int pc_off) {
    int cfa = cfa_reg | cfa_off << 8;
    if (_prev == NULL || (_prev->loc == loc && --_count >= 0) ||
            _prev->cfa != cfa || _prev->fp_off != fp_off || _prev->pc_off != pc_off) {
        _prev = addRecordRaw(loc, cfa, fp_off, pc_off);
    }
}

FrameDesc* DwarfParser::addRecordRaw(u32 loc, int cfa, int fp_off, int pc_off) {
    if (_count >= _capacity) {
        _capacity *= 2;
        _table = (FrameDesc*)realloc(_table, _capacity * sizeof(FrameDesc));
    }

    FrameDesc* f = &_table[_count++];
    f->loc = loc;
    f->cfa = cfa;
    f->fp_off = fp_off;
    f->pc_off = pc_off;
    return f;
}

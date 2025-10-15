/*
 * Copyright The async-profiler authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __APPLE__

#include <unordered_set>
#include <dlfcn.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include "dwarf.h"
#include "symbols.h"
#include "log.h"

UnloadProtection::UnloadProtection(const CodeCache *cc) {
    // Protect library from unloading while parsing in-memory ELF program headers.
    // Also, dlopen() ensures the library is fully loaded.
    _lib_handle = dlopen(cc->name(), RTLD_LAZY | RTLD_NOLOAD);
    _valid = _lib_handle != NULL;
}

UnloadProtection::~UnloadProtection() {
    if (_lib_handle != NULL) {
        dlclose(_lib_handle);
    }
}

class MachOParser {
  private:
    CodeCache* _cc;
    const mach_header* _image_base;
    const char* _vmaddr_slide;

    static const char* add(const void* base, uint64_t offset) {
        return (const char*)base + offset;
    }

    void findSymbolPtrSection(const segment_command_64* sc, const section_64** section_ptr) {
        const section_64* section = (const section_64*)add(sc, sizeof(segment_command_64));
        for (uint32_t i = 0; i < sc->nsects; i++) {
            uint32_t section_type = section->flags & SECTION_TYPE;
            if (section_type == S_NON_LAZY_SYMBOL_POINTERS) {
                section_ptr[0] = section;
            } else if (section_type == S_LAZY_SYMBOL_POINTERS) {
                section_ptr[1] = section;
            }
            section++;
        }
    }

    const section_64* findSection(const segment_command_64* sc, const char* section_name) {
        const section_64* section = (const section_64*)add(sc, sizeof(segment_command_64));
        for (uint32_t i = 0; i < sc->nsects; i++) {
            if (strcmp(section->sectname, section_name) == 0) {
                return section;
            }
            section++;
        }
        return NULL;
    }

    void loadSymbols(const symtab_command* symtab, const char* link_base) {
        const nlist_64* sym = (const nlist_64*)add(link_base, symtab->symoff);
        const char* str_table = add(link_base, symtab->stroff);
        bool debug_symbols = false;

        for (uint32_t i = 0; i < symtab->nsyms; i++) {
            if ((sym->n_type & 0xee) == 0x0e && sym->n_value != 0) {
                const char* addr = _vmaddr_slide + sym->n_value;
                const char* name = str_table + sym->n_un.n_strx;
                if (name[0] == '_') name++;
                _cc->add(addr, 0, name);
                if (strstr(_cc->name(), "libsystem_m.dylib") || strstr(_cc->name(), "libjninativestacks.dylib")) {
                    fprintf(stderr, "%s ==> %s => %p\n", _cc->name(), name, (void*)sym->n_value);
                }
                debug_symbols = true;
            }
            sym++;
        }

        _cc->setDebugSymbols(debug_symbols);
    }

    void loadStubSymbols(const symtab_command* symtab, const dysymtab_command* dysymtab,
                         const section_64* stubs_section, const char* link_base) {
        const nlist_64* sym = (const nlist_64*)add(link_base, symtab->symoff);
        const char* str_table = add(link_base, symtab->stroff);

        const uint32_t* isym = (const uint32_t*)add(link_base, dysymtab->indirectsymoff) + stubs_section->reserved1;
        uint32_t isym_count = stubs_section->size / stubs_section->reserved2;
        const char* stubs_start = _vmaddr_slide + stubs_section->addr;

        for (uint32_t i = 0; i < isym_count; i++) {
            if ((isym[i] & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) == 0) {
                const char* name = str_table + sym[isym[i]].n_un.n_strx;
                if (name[0] == '_') name++;

                char stub_name[256];
                snprintf(stub_name, sizeof(stub_name), "stub:%s", name);
                _cc->add(stubs_start + i * stubs_section->reserved2, stubs_section->reserved2, stub_name);

                if (strstr(_cc->name(), "libsystem_m.dylib") || strstr(_cc->name(), "libjninativestacks.dylib")) {
                    fprintf(stderr, "%s(stubs) ==> %s => %p\n", _cc->name(), name, (void*)(stubs_section->addr + i * stubs_section->reserved2));
                }
            }
        }

        _cc->setPlt(stubs_section->addr, isym_count * stubs_section->reserved2);
    }

    void loadImports(const symtab_command* symtab, const dysymtab_command* dysymtab,
                     const section_64* symbol_ptr_section, const char* link_base) {
        const nlist_64* sym = (const nlist_64*)add(link_base, symtab->symoff);
        const char* str_table = add(link_base, symtab->stroff);

        const uint32_t* isym = (const uint32_t*)add(link_base, dysymtab->indirectsymoff) + symbol_ptr_section->reserved1;
        uint32_t isym_count = symbol_ptr_section->size / sizeof(void*);
        void** slot = (void**)(_vmaddr_slide + symbol_ptr_section->addr);

        for (uint32_t i = 0; i < isym_count; i++) {
            if ((isym[i] & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) == 0) {
                const char* name = str_table + sym[isym[i]].n_un.n_strx;
                if (name[0] == '_') name++;
                _cc->addImport(&slot[i], name);
            }
        }
    }

    void fillBasicUnwindInfo(const section_64* unwind_section) {
        u32* unwind_info = (u32*)(_vmaddr_slide + unwind_section->addr);

        if (!strstr(_cc->name(), "libsystem_m.dylib") && !strstr(_cc->name(), "libjninativestacks.dylib")) {
            return;
        }

        u32 version = *(unwind_info++);
        u32 global_opcodes_offset = *(unwind_info++);
        u32 global_opcodes_len = *(unwind_info++);
        u32 personalities_offset = *(unwind_info++);
        u32 personalities_len = *(unwind_info++);
        u32 pages_offset = *(unwind_info++);
        u32 pages_len = *(unwind_info++);

        u32* pages = (u32*)(_vmaddr_slide + unwind_section->addr + pages_offset);
        u32 table_size = pages_len;

        fprintf(stderr, "======================================================================\n");
        fprintf(stderr, "Unwind info for %s\n", _cc->name());
        fprintf(stderr, "Version: %u\n", version);

        u32* global_opcodes = (u32*)(global_opcodes_offset + _vmaddr_slide + unwind_section->addr);
        for (u32 i = 0; i < global_opcodes_len; i++) {
            u32 global_opcode = global_opcodes[i];
            u32 opcode_kind = (global_opcode & 0x0f000000) >> 24;
            fprintf(stderr, "Global opcode %u: %u 0x%x\n", i, opcode_kind, global_opcode);
        }

        for (u32 i = 0; i < pages_len; i++) {
            u32* page_root = pages;

            u32 first_address = *(pages++);
            u32 second_level_page_offset = *(pages++);
            u32 lsda_index_offset = *(pages++);

            fprintf(stderr, "Page %u: 0x%x\n", i, first_address);

            u32* second_level_page = (u32*)(second_level_page_offset + _vmaddr_slide + unwind_section->addr);
            u32 second_page_kind = *second_level_page;

            fprintf(stderr, "Second level page kind: %d\n", second_page_kind);


            if (second_page_kind == 3) { // compressed page
                u16* data = (u16*)(second_level_page + 1);

                u16 entries_offset = *data++;
                u16 entries_len = *data++;

                u16 local_opcodes_offset = *data++;
                u16 local_opcodes_len = *data++;
                u32* local_opcodes = (u32*)(local_opcodes_offset + (const char*)second_level_page);

                fprintf(stderr, "Local Opcode Length = %u\n", local_opcodes_len);

                for (u32 j = 0; j < local_opcodes_len; j++) {
                    u32 local_opcode = local_opcodes[j];
                    u32 local_opcode_kind = (local_opcode & 0x0f000000) >> 24;
                    fprintf(stderr, "Local opcode %u: %u\n", j, local_opcode_kind);
                }

                u32* local_entries = (u32*)(entries_offset + (const char*)second_level_page);
                for (u32 j = 0; j < entries_len; j++) {
                    u32 entry = local_entries[j];
                    u8 opcode_index = (entry & 0xff000000) >> 24;
                    u32 instruction = entry & 0x00ffffff;

                    fprintf(stderr, "Instruction 0x%x, Opcode %u\n", instruction + first_address, opcode_index);
                }
            }
        }

        fprintf(stderr, "======================================================================\n");
    }

  public:
    MachOParser(CodeCache* cc, const mach_header* image_base, const char* vmaddr_slide) :
        _cc(cc), _image_base(image_base), _vmaddr_slide(vmaddr_slide) {}

    bool parse() {
        if (_image_base->magic != MH_MAGIC_64) {
            return false;
        }

        const mach_header_64* header = (const mach_header_64*)_image_base;
        const load_command* lc = (const load_command*)(header + 1);

        const char* link_base = NULL;
        const section_64* symbol_ptr[2] = {NULL, NULL};
        const symtab_command* symtab = NULL;
        const dysymtab_command* dysymtab = NULL;
        const section_64* stubs_section = NULL;
        const section_64* unwind_info_section = NULL;

        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const segment_command_64* sc = (const segment_command_64*)lc;
                if (strcmp(sc->segname, "__TEXT") == 0) {
                    _cc->updateBounds(_image_base, add(_image_base, sc->vmsize));
                    stubs_section = findSection(sc, "__stubs");
                    unwind_info_section = findSection(sc, "__unwind_info");
                } else if (strcmp(sc->segname, "__LINKEDIT") == 0) {
                    link_base = _vmaddr_slide + sc->vmaddr - sc->fileoff;
                } else if (strcmp(sc->segname, "__DATA") == 0 || strcmp(sc->segname, "__DATA_CONST") == 0) {
                    findSymbolPtrSection(sc, symbol_ptr);
                }

                if (strstr(_cc->name(), "libsystem_m.dylib") || strstr(_cc->name(), "libjninativestacks.dylib")) {
                    fprintf(stderr, "Segment: %s\n", sc->segname);

                    const section_64* section = (const section_64*)add(sc, sizeof(segment_command_64));
                    for (uint32_t j = 0; j < sc->nsects; j++) {
                        fprintf(stderr, "section: %s\n", section->sectname);
                        section++;
                    }
                }
            } else if (lc->cmd == LC_SYMTAB) {
                symtab = (const symtab_command*)lc;
            } else if (lc->cmd == LC_DYSYMTAB) {
                dysymtab = (const dysymtab_command*)lc;
            }
            lc = (const load_command*)add(lc, lc->cmdsize);
        }

        if (unwind_info_section) {
            fillBasicUnwindInfo(unwind_info_section);
        }

        if (symtab != NULL && link_base != NULL) {
            loadSymbols(symtab, link_base);

            if (dysymtab != NULL) {
                if (symbol_ptr[0] != NULL) loadImports(symtab, dysymtab, symbol_ptr[0], link_base);
                if (symbol_ptr[1] != NULL) loadImports(symtab, dysymtab, symbol_ptr[1], link_base);
                if (stubs_section != NULL) loadStubSymbols(symtab, dysymtab, stubs_section, link_base);
            }
        }

        return true;
    }
};


Mutex Symbols::_parse_lock;
bool Symbols::_have_kernel_symbols = false;
bool Symbols::_libs_limit_reported = false;
static std::unordered_set<const void*> _parsed_libraries;

void Symbols::parseKernelSymbols(CodeCache* cc) {
}

void Symbols::parseLibraries(CodeCacheArray* array, bool kernel_symbols) {
    MutexLocker ml(_parse_lock);
    uint32_t images = _dyld_image_count();

    for (uint32_t i = 0; i < images; i++) {
        const mach_header* image_base = _dyld_get_image_header(i);
        if (image_base == NULL || !_parsed_libraries.insert(image_base).second) {
            continue;  // the library was already parsed
        }

        int count = array->count();
        if (count >= MAX_NATIVE_LIBS) {
            if (!_libs_limit_reported) {
                Log::warn("Number of parsed libraries reached the limit of %d", MAX_NATIVE_LIBS);
                _libs_limit_reported = true;
            }
            break;
        }

        const char* path = _dyld_get_image_name(i);
        const char* vmaddr_slide = (const char*)_dyld_get_image_vmaddr_slide(i);

        CodeCache* cc = new CodeCache(path, count);
        cc->setTextBase((const char*)image_base);

        if (strstr(path, "libsystem_m.dylib") || strstr(path, "libjninativestacks.dylib")){
            fprintf(stderr, "SLIDE (%s) = %p, BASE = %p\n", path, (void*)vmaddr_slide, (void*)image_base);
        }

        UnloadProtection handle(cc);
        if (handle.isValid()) {
            MachOParser parser(cc, image_base, vmaddr_slide);
            if (!parser.parse()) {
                Log::warn("Could not parse symbols from %s", path);
            }
            cc->sort();
            array->add(cc);
        } else {
            delete cc;
        }
    }
}

#endif // __APPLE__

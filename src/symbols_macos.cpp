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
                debug_symbols = true;

                if (strstr(_cc->name(), "libsystem_m.dylib") || strstr(_cc->name(), "main.o")) {
                    fprintf(stderr, "# %s = %p\n", name, addr);
                }
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

                if (strstr(_cc->name(), "libsystem_m.dylib") || strstr(_cc->name(), "main.o")) {
                    fprintf(stderr, "# %s = %p\n", name, stubs_start + i * stubs_section->reserved2);
                }
            }
        }
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

        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const segment_command_64* sc = (const segment_command_64*)lc;
                if (strcmp(sc->segname, "__TEXT") == 0) {
                    _cc->updateBounds(_image_base, add(_image_base, sc->vmsize));
                    stubs_section = findSection(sc, "__stubs");

                    if (strstr(_cc->name(), "libsystem_m.dylib") || strstr(_cc->name(), "main.o")) {
                        const section_64* section = findSection(sc, "__unwind_info");
                        u32* data = (u32*)(_vmaddr_slide + section->addr);

                        u32 version = *(data++);
                        u32 global_opcodes_offset = *(data++);
                        u32 global_opcodes_len = *(data++);

                        u32 personalities_offset = *(data++);
                        u32 personalities_len = *(data++);

                        u32 pages_offset = *(data++);
                        u32 pages_len = *(data++);

                        fprintf(stderr, "===================================\n");
                        fprintf(stderr, "version = %u\n", version);
                        fprintf(stderr, "global_opcodes_offset = %u\n", global_opcodes_offset);
                        fprintf(stderr, "global_opcodes_len = %u\n", global_opcodes_len);
                        fprintf(stderr, "personalities_offset = %u\n", personalities_offset);
                        fprintf(stderr, "personalities_len = %u\n", personalities_len);
                        fprintf(stderr, "pages_offset = %u\n", pages_offset);
                        fprintf(stderr, "pages_len = %u\n", pages_len);

                        u32* global_opcodes = (u32*)((u64)_vmaddr_slide + section->addr + global_opcodes_offset);
                        for (int j = 0; j < global_opcodes_len; j++) {
                            u8 opcode_kind = (global_opcodes[j] & 0x0f000000) >> 24;
                            fprintf(stderr, "global_opcodes @ %d = %x, Kind %d\n", j, global_opcodes[j], opcode_kind);
                        }

                        fprintf(stderr, "===================================\n");

                        u32* pages = (u32*)(((u64)_vmaddr_slide + section->addr) + pages_offset);

                        for (int j = 0; j < pages_len; j++) {
                            u32 first_address = *(pages++);
                            u32 second_level_page_offset = *(pages++);
                            u32 lsda_index_offset = *(pages++);

                            fprintf(stderr, "first_address = 0x%llx\n", (u64)_vmaddr_slide + section->addr + first_address);
                            fprintf(stderr, "second_level_page_offset = %u\n", second_level_page_offset);
                            fprintf(stderr, "lsda_index_offset = %u\n", lsda_index_offset);

                            u32* second_page = (u32*)(((u64)_vmaddr_slide + section->addr) + second_level_page_offset);
                            u32 kind = *(second_page++);
                            fprintf(stderr, "kind = %u\n", kind);

                            if (kind == 3) {
                                u16* compressed_second_level_page = (u16*)second_page;

                                u16 entries_offset = *(compressed_second_level_page++);
                                u16 entries_len = *(compressed_second_level_page++);

                                u16 local_opcodes_offset = *(compressed_second_level_page++);
                                u16 local_opcodes_len = *(compressed_second_level_page++);

                                fprintf(stderr, "entries_offset = %u\n", entries_offset);
                                fprintf(stderr, "entries_len = %u\n", entries_len);
                                fprintf(stderr, "local_opcodes_offset = %u\n", local_opcodes_offset);
                                fprintf(stderr, "local_opcodes_len = %u\n", local_opcodes_len);

                                u32* second_page_entries = (u32*)((u64)_vmaddr_slide + section->addr + second_level_page_offset + entries_offset);
                                for (int k = 0; k < entries_len; k++) {
                                    u32 entry = second_page_entries[k];
                                    u8 entry_opcode_index = entry >> 24;
                                    u32 entry_address = entry & 0x00ffffff; // 0x19f624f80

                                    fprintf(stderr, "==> entry_opcode_index = %d\n", entry_opcode_index);
                                    fprintf(stderr, "==> entry_address = 0x%llx\n", (u64)_vmaddr_slide + section->addr + first_address + entry_address);
                                }

                                u32* second_page_opcodes = (u32*)((u64)_vmaddr_slide + section->addr + second_level_page_offset + local_opcodes_offset);
                                for (int k = 0; k < local_opcodes_len; k++) {
                                    u8 opcode_kind = (second_page_opcodes[k] & 0x0f000000) >> 24;
                                    fprintf(stderr, "==> local_opcodes @ %d = %x, Kind %d\n", k, second_page_opcodes[k], opcode_kind);
                                }
                            }

                            if (kind == 2) {
                                u16* regular_second_level_page = (u16*)second_page;
                                u16 entries_offset = *(regular_second_level_page++);
                                u16 entries_len = *(regular_second_level_page++);

                                u32* second_page_entries = (u32*)((u64)_vmaddr_slide + section->addr + second_level_page_offset + entries_offset);
                                for (int k = 0; k < entries_len; k++) {
                                    u32 instruction_address = *(second_page_entries++);
                                    u32 opcode = *(second_page_entries++);
                                    u8 opcode_kind = (opcode & 0x0f000000) >> 24;

                                    fprintf(stderr, "opcode = %x, Kind %d => Address 0x%x\n", opcode, opcode_kind, instruction_address);
                                }
                            }


                            fprintf(stderr, "===================================\n");
                        }
                    }

                } else if (strcmp(sc->segname, "__LINKEDIT") == 0) {
                    link_base = _vmaddr_slide + sc->vmaddr - sc->fileoff;
                } else if (strcmp(sc->segname, "__DATA") == 0 || strcmp(sc->segname, "__DATA_CONST") == 0) {
                    findSymbolPtrSection(sc, symbol_ptr);
                }
            } else if (lc->cmd == LC_SYMTAB) {
                symtab = (const symtab_command*)lc;
            } else if (lc->cmd == LC_DYSYMTAB) {
                dysymtab = (const dysymtab_command*)lc;
            }
            lc = (const load_command*)add(lc, lc->cmdsize);
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
        cc->setTextBase(vmaddr_slide);

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

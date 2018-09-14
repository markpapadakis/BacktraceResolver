// http://www.dwarfstd.org/doc/DWARF5.pdf
// objdump --dump=info a.out
#include "stacktraces.h"
#ifdef SWITCH_PHAISTOS
//#define DBG_ST 1
#include <text.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utility>
#include <linux/limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <algorithm>
#include <cstdio>
#endif
#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <elf.h>
#include <link.h>
#include <libdwarf/dwarf.h> // apt-get install -y libdwarf-dev

static constexpr size_t K_max_compilation_units              = 512;
static constexpr size_t K_max_compilation_units_tracked_refs = 512;
static constexpr size_t K_max_tracked_frames                 = 512;
static constexpr size_t K_max_dso_frames                     = 512;
static constexpr size_t K_max_abbrev_spec_attrs              = 128;
static constexpr size_t K_abbr_map_size                      = 128;
static constexpr size_t K_max_compilation_unit_files         = 512;
static constexpr size_t K_max_tracked_dsos                   = 128;
static constexpr size_t K_max_tracked_refs                   = 128;


static uint64_t decode_LEB128(const uint8_t *&data) {
        const auto *p = data;
        uint8_t     shift{0}, byte;
        int64_t     result{0};

        do {
                byte = *p++;
                result |= ((unsigned long int)(byte & 0x7f)) << shift;
                shift += 7;
        } while (byte & 0x80);

        data = p;
        return result;
}

static int64_t decode_signed_LEB128(const uint8_t *&data) {
        const auto *p = data;
        uint8_t     shift{0}, byte;
        int64_t     result{0};

        do {
                byte = *p++;

                result |= ((unsigned long int)(byte & 0x7f)) << shift;
                shift += 7;
        } while (byte & 0x80);

        data = p;
        if ((shift < 8 * sizeof(result)) && (byte & 0x40))
                result |= -1L << shift;

        return result;
}

#ifndef DW_FORM_implicit_const
#define DW_FORM_implicit_const 0x21
#endif

#ifndef DW_LNS_extended_op
#define DW_LNS_extended_op 0
#endif

union attr_val final {
        uint64_t   u64;
        str_view32 _str;

        attr_val()
            : _str{} {
        }

	auto str() { 
		if (_str.p && !_str.len) _str.len = strlen(_str.p);
		return _str;
	}
};

struct attr_spec final {
        uint64_t name;
        uint64_t form;
        uint64_t const_value;
};

struct abbrev_spec final {
        uint64_t     entry;
        uint64_t     tag;
        uint8_t      children;
        size_t       attrs_cnt;
        abbrev_spec *next;
        attr_spec    attrs[0];
};

static bool parse_attr_value(const uint64_t form, const uint8_t version,
                             const uint8_t *const debug_str_base,
                             const uint8_t offset_size, const uint8_t addr_size,
                             const uint8_t *&p, attr_val *const out) {
        out->_str.reset();

        switch (form) {
                case DW_FORM_ref_addr:
                        if (version == 3 || version == 4) {
                                out->u64 = offset_size == sizeof(uint32_t) ? decode_pod<uint32_t>(p) : decode_pod<uint64_t>(p);
                                break;
                        }
                        [[fallthrough]];
                case DW_FORM_addr:
                        // clang-format off
                        out->u64 = addr_size == sizeof(uint64_t) ? decode_pod<uint64_t>(p) 
					: (addr_size == sizeof(uint32_t) ? decode_pod<uint32_t>(p) 
					: (addr_size == sizeof(uint16_t) ? decode_pod<uint16_t>(p) : 0));
                        // clang-format on
                        break;

                case DW_FORM_GNU_ref_alt:
                        [[fallthrough]];
                case DW_FORM_sec_offset:
                        out->u64 = offset_size == sizeof(uint32_t) ? decode_pod<uint32_t>(p) : decode_pod<uint64_t>(p);
                        break;

                case DW_FORM_block2:
                        p += (*reinterpret_cast<const uint16_t *>(p)) + sizeof(uint16_t);
                        break;

                case DW_FORM_block4:
                        p += (*reinterpret_cast<const uint32_t *>(p)) + sizeof(uint32_t);
                        break;

                case DW_FORM_data2:
                        out->u64 = decode_pod<uint16_t>(p);
                        break;

                case DW_FORM_data4:
                        out->u64 = decode_pod<uint32_t>(p);
                        break;

                case DW_FORM_data8:
                        out->u64 = decode_pod<uint64_t>(p);
                        break;

                case DW_FORM_string:
                        out->_str.p   = reinterpret_cast<const char *>(p);
                        out->_str.len = strlen(out->_str.p);
                        p += out->_str.len + 1;
                        break;

                case DW_FORM_strp: {
                        const auto o = offset_size == sizeof(uint64_t) ? decode_pod<uint64_t>(p) : decode_pod<uint32_t>(p);

                        // deferred
                        out->_str.p   = reinterpret_cast<const char *>(debug_str_base + o);
                        out->_str.len = 0;
                } break;

                case DW_FORM_GNU_strp_alt:
                        p += offset_size;
                        break;

                case DW_FORM_exprloc:
                        [[fallthrough]];
                case DW_FORM_block:
                        p += decode_LEB128(p);
                        break;

                case DW_FORM_block1:
                        p += (*p) + sizeof(uint8_t);
                        break;

                case DW_FORM_data1:
                        out->u64 = *p++;
                        break;

                case DW_FORM_flag:
                        ++p;
                        break;

                case DW_FORM_flag_present:
                        break;

                case DW_FORM_sdata:
                        decode_signed_LEB128(p);
                        break;

                case DW_FORM_udata:
                        decode_LEB128(p);
                        break;

                case DW_FORM_ref1:
                        out->u64 = decode_pod<uint8_t>(p);
                        break;

                case DW_FORM_ref2:
                        out->u64 = decode_pod<uint16_t>(p);
                        break;

                case DW_FORM_ref4:
                        out->u64 = decode_pod<uint32_t>(p);
                        break;

                case DW_FORM_ref8:
                        out->u64 = decode_pod<uint64_t>(p);
                        break;

                case DW_FORM_ref_udata:
                        decode_LEB128(p);
                        break;

                case DW_FORM_indirect: {
                        const auto f = decode_LEB128(p);
                        attr_val   other;

                        if (!parse_attr_value(f, version, debug_str_base, offset_size, addr_size, p, &other)) {
                                return false;
                        }
                } break;

                default:
                        return false;
        }

        return true;
}

static bool locate_abstract_instance_name(const uint8_t *unit_hdr, const uint8_t *const debug_str_base, const abbrev_spec **dict,
                                          const uint8_t version, const uint8_t offset_size, const uint8_t addr_size,
                                          const uint64_t form, const uint64_t ref, str_view32 *const __restrict res) {
        if (form == DW_FORM_ref_addr || form == DW_FORM_GNU_ref_alt) {
                return false;
        }

        const auto *p    = unit_hdr + ref;
        const auto  code = decode_LEB128(p);

        if (!code) {
                return true;
        }

        const abbrev_spec *abbr;

        for (abbr = dict[code & (K_abbr_map_size - 1)]; abbr && abbr->entry != code; abbr = abbr->next) {
                continue;
        }

        if (!abbr) {
                return false;
        }

        attr_val value;

	for (const auto *at = abbr->attrs, *const at_end = at + abbr->attrs_cnt; at < at_end; ++at) {
                if (!parse_attr_value(at->form, version, debug_str_base, offset_size, addr_size, p, &value)) {
                        return false;
                }

                switch (at->name) {
                        case DW_AT_name:
                                if (!res->p) {
                                        // linkage name has precendance over name
                                        *res = value._str;
                                }
                                break;

                        case DW_AT_specification:
                                if (!locate_abstract_instance_name(unit_hdr, debug_str_base, dict, version, offset_size, addr_size, at->form, value.u64, res)) {
                                        return false;
                                }
                                break;

                        case DW_AT_linkage_name:
                                [[fallthrough]];
                        case DW_AT_MIPS_linkage_name:
                                if (value._str.p)
                                        *res = value._str;
                                break;

                        default:
                                break;
                }
        }

        return true;
}

int Switch::stacktrace(void **frames, const size_t depth, stack_frame *out, const size_t stack_frames_capacity, uint8_t *storage, size_t storage_size) {
        // XXX: backtrace() will allocate memory(why?)
        // we can't safely allocate memory in the signal handler
        // we should look for an alternative way to obtain that backtrace.
        //
        // Also, note that backtrace() will store RETURN ADDRESSES in frames[], which
        // means we need to determine the callsite of the function instead of
        // the callsite of whatever the called function returns to.
        if (!stack_frames_capacity || storage_size < 256) {
#ifdef DBG_ST
		SLog("Out Of Memory\n");
#endif
                return -StackResolverErrors::OutOfMemory;
	}

        struct match final {
                uintptr_t                          base_addr; // so that we can use this as a key
                const int8_t *                     q;
                Elf64_Phdr                         phdr;
                char                               path[PATH_MAX];
                range_base<const int8_t *, size_t> loadable_progseg_range;
        } frame_match;
        struct tracked_dso final {
                uintptr_t key;
                char *    path;
                uint8_t   path_len;

                struct {
                        const uint8_t *addr;
                        size_t         size;
                } vma;

                struct {
                        range_base<const uint8_t *, size_t> debug_info, debug_line,
                            debug_abbrev, debug_ranges, debug_str, dynstr;
                } sections;

                str_view32 path_s8() const noexcept {
                        if (!path)
                                return {};
                        else
                                return {path, path_len};
                }

        } tracked_dsos[K_max_tracked_dsos];
        struct tracked_ref final {
                uint32_t                      frame_index;
                uint32_t                      index;
                uint32_t                      tracked_dsos_index;
                str_view32                    func_name;
                range_base<uintptr_t, size_t> addr_range;
                uint32_t                      cunit;

                struct {
                        str_view32 dir;
                        str_view32  filename;
                        uint32_t   line;
                        uint32_t   column;
                        uintptr_t  line_addr;
                        uint32_t   call_line;
                } src_ref;

                struct {
                        uint32_t  line;
                        uint32_t  column;
                        uint32_t  file_id;
                        str_view32 filename;
                } inline_ctx;

        } tracked_refs[K_max_tracked_refs];
        size_t                         tracked_dsos_cnt{0}, tracked_refs_cnt{0};
        std::pair<uint32_t, uint32_t>  frame_dso[K_max_tracked_frames];
        std::pair<uintptr_t, uint32_t> dso_frames[K_max_dso_frames];
        attr_spec                      abbreviation_spec_attrs[K_max_abbrev_spec_attrs];
        size_t                         frame_dso_size{0};
        str_view32                     comp_unit_files[K_max_compilation_unit_files];
        const auto                     tear_down = [&]() {
                for (size_t i{0}; i < tracked_dsos_cnt; ++i) {
                        if (auto addr = tracked_dsos[i].vma.addr) {
                                munmap(reinterpret_cast<void *>(const_cast<uint8_t *>(addr)), tracked_dsos[i].vma.size);
                        }
                }
        };

        for (size_t i{0}; i < depth && tracked_dsos_cnt < K_max_tracked_dsos; ++i) {
                const auto return_addr = reinterpret_cast<const int8_t *>(frames[i]); // the return address from the corresponding frame

                frame_match.q = return_addr;
                if (!dl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) {
                            auto *const frame_match = reinterpret_cast<match *>(data);
                            const auto  base_addr{info->dlpi_addr};

			    (void)size;

                            // consider all loadable program segments
                            for (size_t i{0}; i < info->dlpi_phnum; ++i) {
                                    const auto &phdr = info->dlpi_phdr[i];

                                    if (phdr.p_type == PT_LOAD) {
                                            const auto b = reinterpret_cast<int8_t *>(phdr.p_vaddr + base_addr);
                                            const auto e = b + phdr.p_memsz;

                                            if (frame_match->q >= b && frame_match->q < e) {
                                                    frame_match->loadable_progseg_range.set(b, phdr.p_memsz);              // not needed, but track it anyway
                                                    strcpy(frame_match->path, info->dlpi_name);                            // only needed because we need to mmap() it
                                                    memcpy(&frame_match->phdr, &phdr, sizeof(phdr));                       // don't need that either?
                                                    frame_match->base_addr = reinterpret_cast<uintptr_t>(info->dlpi_addr); // for tracking distinct DSOs
                                                    return 1;
                                            }
                                    }
                            }

                            return 0;
                    },
                                     &frame_match)) {

                        // this doesn't make any sense
#ifdef DBG_ST
			SLog("Unable to match with dl_iterate_phdr()\n");
#endif
			tear_down();
                        return -StackResolverErrors::NoSupport;
                }


                size_t       dso_i{0};
                tracked_dso *dso;

                while (dso_i < tracked_dsos_cnt && (dso = tracked_dsos + dso_i)->key != frame_match.base_addr) {
                        ++dso_i;
                }

                if (dso_i == tracked_dsos_cnt) {
                        // First-seen DSO
                        dso = &tracked_dsos[tracked_dsos_cnt];
                        if (!frame_match.path[0]) {
                                dso->path = nullptr;
				dso->path_len = 0;
                        } else {
                                const auto len = strlen(frame_match.path);

                                if (len + 1 > storage_size) {
                                        goto l200;
                                }

                                dso->path     = reinterpret_cast<char *>(storage);
                                dso->path_len = len;
                                memcpy(storage, frame_match.path, len);
                                storage[len] = '\0';
                                storage += len + 1;
                                storage_size -= len + 1;
                        }
                        ++tracked_dsos_cnt;

                        dso->key      = frame_match.base_addr;
                        dso->vma.addr = nullptr;
                }

                frame_dso[frame_dso_size++] = {i, dso_i};
                if (frame_dso_size == K_max_tracked_frames) {
                        // sanity
                        break;
                }
        }

l200:
        // Group by DSO
        std::sort(frame_dso, frame_dso + frame_dso_size, [](const auto &a, const auto &b) noexcept { return a.second < b.second; });

        for (size_t tri{0}; tri < frame_dso_size; ++tri) {
                const auto dso_i = frame_dso[tri].second;
                auto       dso   = tracked_dsos + dso_i;
                int        fd    = open(dso->path ?: "/proc/self/exe", O_RDONLY | O_LARGEFILE);

                if (-1 == fd) {
			tear_down();
#if DBG_ST 
			SLog("open(): ", strerror(errno), "\n");
#endif
                        return -StackResolverErrors::Sys;
		}

                const auto file_size = lseek(fd, 0, SEEK_END);

                if (file_size < static_cast<off_t>(sizeof(Elf64_Ehdr))) {
                        close(fd);
			tear_down();
#if DBG_ST 
			SLog("file_size = ", file_size, "\n");
#endif
                        return -StackResolverErrors::Sys;
                }

                auto vma_base = mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);

                close(fd);
                if (vma_base == MAP_FAILED) {
			tear_down();
#ifdef DBG_ST
			SLog("mmap(): ", strerror(errno), "\n");
#endif
                        return -StackResolverErrors::Sys;
                }

                dso->vma.addr = reinterpret_cast<const uint8_t *>(vma_base);
                dso->vma.size = file_size;

                const auto  addr    = dso->vma.addr;
                const auto  elf_hdr = reinterpret_cast<const Elf64_Ehdr *>(addr);
                const auto  sh      = reinterpret_cast<const Elf64_Shdr *>(addr + elf_hdr->e_shoff);
                const auto &snsth   = sh[elf_hdr->e_shstrndx]; // section header table index of the entry associated with the section name string table (could be SHN_UNDEF)

                memset(&dso->sections, 0, sizeof(dso->sections));
                for (size_t i{0}; i < elf_hdr->e_shnum; ++i) {
                        const auto &    s = sh[i];
                        const str_view32 name(reinterpret_cast<const char *>(addr + snsth.sh_offset + s.sh_name));

                        switch (s.sh_type) {
                                case SHT_SYMTAB:
                                case SHT_DYNSYM:
                                        break;

                                case 3:
                                        if (name.Eq(_S(".dynstr")))
                                                dso->sections.dynstr.set(addr + s.sh_offset, s.sh_size);
                                        break;

                                case 1:
                                        if (name.Eq(_S(".debug_info")))
                                                dso->sections.debug_info.set(addr + s.sh_offset, s.sh_size);
                                        else if (name.Eq(_S(".debug_line")))
                                                dso->sections.debug_line.set(addr + s.sh_offset, s.sh_size);
                                        else if (name.Eq(_S(".debug_abbrev")))
                                                dso->sections.debug_abbrev.set(addr + s.sh_offset, s.sh_size);
                                        else if (name.Eq(_S(".debug_ranges")))
                                                dso->sections.debug_ranges.set(addr + s.sh_offset, s.sh_size);
                                        else if (name.Eq(_S(".debug_str")))
                                                dso->sections.debug_str.set(addr + s.sh_offset, s.sh_size);
                                        break;

                                default:
                                        break;
                        }
                }

                if (!dso->sections.debug_info || !dso->sections.debug_line || !dso->sections.debug_abbrev || !dso->sections.debug_ranges || !dso->sections.debug_str) {
                        // debug info missing; compile with -g3
                        continue;
                }

                auto       dso_tracked_ref_base = tracked_refs_cnt;
                const auto abbrev_base          = dso->sections.debug_abbrev.offset;
                [[maybe_unused]] const auto abbrev_end           = abbrev_base + dso->sections.debug_abbrev.size();
                size_t     dso_frames_size{0};

                do {
                        const auto frame_index = frame_dso[tri].first;
                        const auto ptr         = reinterpret_cast<uintptr_t>(frames[frame_index]);

                        dso_frames[dso_frames_size++] = {ptr, frame_index};
                        if (dso_frames_size == K_max_dso_frames) {
                                // sanity
#ifdef DBG_ST
				SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                break;
                        }
                } while (++tri < frame_dso_size && frame_dso[tri].second == dso_i);

#ifdef DBG_ST
                SLog(ansifmt::color_red, "FOR NEW module ", dso_frames_size, ansifmt::reset, "\n");
#endif

                const auto *p = dso->sections.debug_info.offset, *const e = p + dso->sections.debug_info.size();
                abbrev_spec *abbreviations_map[K_abbr_map_size] = {nullptr};
                size_t       compilation_unit{0};
                uint64_t     interesting_cus_bm[K_max_compilation_units / 64 + 1] = {0}; // track all compilation units we are interested in

                // http://www.dwarfstd.org/doc/DWARF5.pdf  7.5
                while (p < e) {
                        // 7.5.1.1: Full or Partial Compilation Unit Headers
                        const auto unit_hdr = p;
                        [[maybe_unused]] size_t     offset_size, initial_len_size;
                        uint64_t   compilation_unit_len = decode_pod<uint32_t>(p);
                        auto       local_storage_next   = storage;
                        const auto local_storage_end    = storage + storage_size;

                        if (compilation_unit_len == 0xffffffff) {
                                // DWARF3 way of indicating we use 64-bit offsets, instead of 32-bit offsets
                                compilation_unit_len = decode_pod<uint64_t>(p);
                                offset_size          = sizeof(uint64_t);
                        } else if (compilation_unit_len == 0) {
                                // IRIX way of indicating 64-bit offsets, mostly
                                compilation_unit_len = decode_pod<uint64_t>(p);
                                offset_size          = sizeof(uint64_t);
                        } else {
                                offset_size = sizeof(uint32_t);
                        }

                        const auto compilation_unit_end = p + compilation_unit_len;

                        // We are only really doing this in order to determine the
                        // function name and the address range of the function
                        // we are going to get the filename from the .debug_line section, and
                        // we need the range of the function first in order to match the address
                        // computed while running the line program against the it
                        if (compilation_unit_len > 0) {
                                const auto     version       = decode_pod<uint16_t>(p);
                                const auto     unit_type     = version >= 5 ? decode_pod<uint8_t>(p) : 0;
                                const uint64_t abbrev_offset = offset_size == sizeof(uint64_t) ? decode_pod<uint64_t>(p) : decode_pod<uint32_t>(p);
                                const auto     addr_size     = decode_pod<uint8_t>(p);
                                [[maybe_unused]] const auto     dwo_id        = (unit_type == 0x04 || unit_type == 0x05) ? decode_pod<uint64_t>(p) : 0;

                                if (unit_type == 0x2) {
                                        [[maybe_unused]] const auto     type_signature = decode_pod<uint64_t>(p);
                                        [[maybe_unused]] const uint64_t type_offset    = offset_size == sizeof(uint64_t) ? decode_pod<uint64_t>(p) : decode_pod<uint32_t>(p);
                                }

                                if (version < 2 || version > 5) {
					tear_down();
#ifdef DBG_ST
					SLog("Version ", version, "\n");
#endif

                                        return -StackResolverErrors::NoSupport;
                                }

                                switch (addr_size) {
                                        case sizeof(uint16_t):
                                                [[fallthrough]];
                                        case sizeof(uint32_t):
                                                [[fallthrough]];
                                        case sizeof(uint64_t):
                                                break;

                                        default:
						tear_down();
#ifdef DBG_ST
						SLog("No Support\n");
#endif
                                                return -StackResolverErrors::NoSupport;
                                }

                                const auto *first_entry = p;

                                // Dwarf 7.5.3
                                // Multiple compilation units may share the same abbrevation table.
                                // The abbreviations table for a single compilation unit consists of a series of abbreviation declarations.
                                //
                                // Each abbreviation specifies the TAG and ATTRIBUTES for a particular FORM of debugging information entry.
                                // Each declaration begins with LEB128 number representing the abbreviation code itself.
                                // It is this code that appears in the beginning of debuging information entry in the .debug_info section.
                                // It is followed by another unsigned LEB128 that encode the entry's tag.
                                //
                                // Following the tag encoding is a 1-byte value that determines ether the debugging information entry using this
                                // abbreviation has child entries or not. If it is == DW_CHILDREN_yes, the next physically succeeding entry of
                                // any debugging information entry using this abbreviation is the first child of that entry, otherwise if if it is
                                // == DW_CHILDREN_no it is a sibling of that entry.
                                // Finally, the child encoding is followed by a series of attributes specifications.
                                // Each consists of two parts. The first represnets the name, and the second the form
                                // The series of attribute specifications ends with an entry containing 0 for name and 0 for form
                                //
                                // We are going to parse the abbreviationt able associated with this compilation unit before
                                // we iterate the debugging information entries of the compilation unit
                                p = abbrev_base + abbrev_offset;

                                // Parse successive abbreviation declarations from the abbreviation table
                                // TODO: multiple compilation units can be associated with the same abbr.table, so maybe
                                // we should cache this information if already decoded
                                while (const auto code = decode_LEB128(p)) {
                                        // tag for this abbreviation declaration
                                        const auto tag      = decode_LEB128(p); // e.g DW_TAG_compile_unit, DW_TAG_subprogram, ..
                                        const auto children = decode_pod<uint8_t>(p);
                                        size_t     abbreviation_spec_attrs_cnt{0};

                                        // attributes
                                        for (;;) {
                                                const auto attr = decode_LEB128(p); // e.g DW_AT_producer, DW_AT_name, ...
                                                const auto form = decode_LEB128(p);

                                                if (!attr && !form) {
                                                        break;
                                                }

                                                if (abbreviation_spec_attrs_cnt < K_max_abbrev_spec_attrs) {
                                                        if (form == DW_FORM_implicit_const) {
                                                                abbreviation_spec_attrs[abbreviation_spec_attrs_cnt] = {.name = attr, .form = form, .const_value = decode_LEB128(p)};
                                                        } else {
                                                                abbreviation_spec_attrs[abbreviation_spec_attrs_cnt] = {.name = attr, .form = form};
                                                        }
                                                        ++abbreviation_spec_attrs_cnt;
                                                } else {
#ifdef DBG_ST
                                                        SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                                }

                                        }

                                        const size_t required = sizeof(abbrev_spec) + sizeof(attr_spec) * abbreviation_spec_attrs_cnt;
                                        auto         ent      = reinterpret_cast<abbrev_spec *>(local_storage_next);
                                        const auto   index    = code & (sizeof_array(abbreviations_map) - 1);

                                        local_storage_next += required;
                                        if (local_storage_next > local_storage_end) {
						tear_down();
#ifdef DBG_ST
						SLog("Out of Memory\n");
#endif
                                                return -StackResolverErrors::OutOfMemory;
                                        }

                                        ent->attrs_cnt = abbreviation_spec_attrs_cnt;
                                        ent->tag       = tag;
                                        ent->entry     = code;
                                        ent->children  = children;
                                        memcpy(ent->attrs, abbreviation_spec_attrs, abbreviation_spec_attrs_cnt * sizeof(attr_spec));
                                        ent->next = abbreviations_map[index];

                                        abbreviations_map[index] = ent;
                                }

                                int32_t      level{1};
                                str_view32   compilation_unit_name;
                                attr_val     value;
                                abbrev_spec *abbrev_info;

                                // Process CU abbrevations
                                for (p = first_entry; p < compilation_unit_end;) {
                                        // Dwarf3: 7.5.2
                                        const auto abbrev_num = decode_LEB128(p);

                                        if (!abbrev_num) {
                                                --level;
                                                continue;
                                        }

                                        for (abbrev_info = abbreviations_map[abbrev_num & (sizeof_array(abbreviations_map) - 1)];
                                             abbrev_info && abbrev_info->entry != abbrev_num;
                                             abbrev_info = abbrev_info->next) {
                                                continue;
                                        }

                                        if (!abbrev_info) {
						tear_down();
#ifdef DBG_ST
						SLog("Unexpected Structure\n");
#endif
                                                return -StackResolverErrors::UnexpectedStruct;
                                        }

                                        str_view32 func_name;
                                        uint64_t   low_pc{0}, high_pc{0}, base_range_addr{0}, call_line{0}, call_column{0};
                                        uint32_t   decl_line{0};
                                        bool       high_pc_relative{false}, in_func;
                                        range64_t  func_range;
                                        uint32_t   call_file{0};

                                        // Process abbreviation
                                        switch (abbrev_info->tag) {
                                                case DW_TAG_inlined_subroutine:
                                                        // See 3.3.8.2
                                                        // Each inline subroutine entry may have either a DW_AT_low_pc and a DW_AT_high_pc attributes, or
                                                        // DW_AT_ranges attribute, whose values encode the contiguous or non-contiguous address ranges, respectively, of
                                                        // the machine instructions generated for the inline subroutine.
                                                        // An inlined subroutine may also contain a DW_AT_entry_pc attribute, representing the first
                                                        // executable instruction of the inline expansion
                                                        //
                                                        // An inline subroutine may also have DW_AT_call_file, DW_AT_call_line, and DW_AT_call_column attributes
                                                        // The locate the statement or expression that caused the inline expansion.
                                                        [[fallthrough]];
                                                case DW_TAG_subprogram:
                                                        [[fallthrough]];
                                                case DW_TAG_entry_point:
                                                        // this abbreviation is specific to a function or program
                                                        in_func = true;
                                                        break;

                                                default:
                                                        in_func = false;
                                                        break;
                                        }

                                        // Process abbreviation attributes
					for (const auto *it = abbrev_info->attrs, *const it_end = it + abbrev_info->attrs_cnt; it < it_end; ++it) {
                                                if (!parse_attr_value(it->form, version, dso->sections.debug_str.offset, offset_size, addr_size, p, &value)) {
							tear_down();
#ifdef DBG_ST
							SLog("Unexpected Structure\n");
#endif
                                                        return -StackResolverErrors::UnexpectedStruct;
                                                }


                                                if (in_func) {
                                                        // See 3.3.1.3: Call Site-Related Attributes
                                                        switch (it->name) {
                                                                // An inline subroutine may also have DW_AT_call_file, DW_AT/_call_line, and DW_AT_call_column attributes
                                                                // They represent the source file, source line number, and source column number, repsectively, of
                                                                // the first character of the statement or expression that caused the inline expansion.
                                                                // See http://www.dwarfstd.org/doc/DWARF4.pdf#page=130&zoom=100,0,152 for how they are specified
                                                                case DW_AT_call_file:
                                                                        // corresponds to a file number form the line number information table for
                                                                        // the compilation unit containing the debugging information entry and respresents the source file
                                                                        // in which the declaration appeared. The value 0 indicates taht no source file has been specified
                                                                        call_file = value.u64;
                                                                        break;

                                                                case DW_AT_call_line:
                                                                        call_line = value.u64;
                                                                        break;

                                                                case DW_AT_call_column:
                                                                        call_column = value.u64;
                                                                        break;

                                                                case DW_AT_entry_pc:
                                                                        // The first executable instruction of the inline expansion
                                                                        break;

                                                                case DW_AT_name:
                                                                        if (!func_name.p) {
                                                                                // we prefer DW_AT_linkage_name over DW_AT_name
                                                                                func_name = value._str;
                                                                        }
                                                                        break;

                                                                case DW_AT_abstract_origin:
                                                                        [[fallthrough]];
                                                                case DW_AT_specification:
                                                                        if (!func_name.p) {
                                                                                if (!locate_abstract_instance_name(unit_hdr, dso->sections.debug_str.offset,
                                                                                                                   const_cast<const abbrev_spec **>(abbreviations_map),
                                                                                                                   version, offset_size, addr_size,
                                                                                                                   it->form, value.u64,
                                                                                                                   &func_name)) {
											tear_down();
#ifdef DBG_ST
											SLog("Unexpected Structure\n");
#endif
                                                                                        return -StackResolverErrors::UnexpectedStruct;
                                                                                }
                                                                        }
                                                                        break;

                                                                case DW_AT_linkage_name:
                                                                        [[fallthrough]];
                                                                case DW_AT_MIPS_linkage_name:
                                                                        if (value._str.p)
                                                                                func_name = value._str;
                                                                        break;

                                                                case DW_AT_low_pc:
                                                                        low_pc = value.u64;
                                                                        if (abbrev_info->tag == DW_TAG_compile_unit) {
                                                                                // base address to use when reading location lists or range lists
                                                                                base_range_addr = low_pc;
                                                                        }
                                                                        break;

                                                                case DW_AT_high_pc:
                                                                        high_pc          = value.u64;
                                                                        high_pc_relative = it->form != DW_FORM_addr;
                                                                        break;

                                                                case DW_AT_decl_line:
                                                                        decl_line = value.u64;
                                                                        break;

                                                                case DW_AT_ranges: {
                                                                        // Identify the function with the smallest range that contains an address, to properly
                                                                        // handle inline functions, for inline functions the same ranges may match the callee and the inline function
                                                                        //
                                                                        // TODO: support ranges (this makes sense for inline functions)
                                                                        // we currenttly don't support them, but we should, eventually
                                                                        for (const auto *p = dso->sections.debug_ranges.offset + value.u64, *const e = dso->sections.debug_ranges.stop(); p < e;) {
                                                                                uint64_t lo, hi;

                                                                                if (addr_size == sizeof(uint64_t)) {
                                                                                        lo = decode_pod<uint64_t>(p);
                                                                                        hi = decode_pod<uint64_t>(p);
                                                                                } else {
                                                                                        lo = decode_pod<uint32_t>(p);
                                                                                        hi = decode_pod<uint32_t>(p);
                                                                                }

                                                                                if (!lo && !hi)
                                                                                        break;

                                                                                const range64_t range(lo, hi - lo);
                                                                        }
                                                                } break;
                                                        }
                                                } else if (abbrev_info->tag == DW_TAG_compile_unit) {
                                                        if (it->name == DW_AT_name) {
                                                                compilation_unit_name = value._str;
                                                        }
                                                }
                                        }

                                        if (in_func && high_pc && func_name.p && !func_range) {
                                                const auto      normalized_high_pc = high_pc_relative ? high_pc + low_pc : high_pc;
                                                const range64_t range(low_pc, (normalized_high_pc - low_pc) + 1 /* inclusive */);

                                                // A return address in the list of addresses returned by backtrace()
                                                // can be contained in the range of MULTIPLE functions
                                                // in the case of inline functions.
                                                //
                                                // See comments
                                                // Thankfully, we get those in proper order, which makes it possible to
                                                // expand inline callsites at the end (see commentary)
                                                for (size_t i{0}; i < dso_frames_size; ++i) {
                                                        const auto [pc, frame_index] = dso_frames[i];

                                                        if (range.Contains(pc)) {
                                                                auto tracked_ref_ptr = tracked_refs + tracked_refs_cnt;

#ifdef DBG_ST
                                                                SLog("Matched pc = ", pc, " IN range = ", range, " func = ", ansifmt::color_cyan, func_name, ansifmt::reset,
                                                                     " call_line = ", call_line, " ", compilation_unit_name, " in ", compilation_unit, " (", tracked_ref_ptr->frame_index, "), call_file = ", call_file, ", frame_index = ", frame_index, "\n");
#endif

                                                                interesting_cus_bm[compilation_unit / 64] |= static_cast<uint64_t>(1) << (compilation_unit & 63);

                                                                if (func_name.p && func_name.len == 0) {
                                                                        // deferred
                                                                        func_name.len = strlen(func_name.p);
                                                                }

                                                                tracked_ref_ptr->addr_range.set(range.offset, range.size());
                                                                tracked_ref_ptr->index              = tracked_refs_cnt++;
                                                                tracked_ref_ptr->func_name          = func_name;
                                                                tracked_ref_ptr->cunit              = compilation_unit;
                                                                tracked_ref_ptr->frame_index        = frame_index;
                                                                tracked_ref_ptr->src_ref.line_addr  = 0;
                                                                tracked_ref_ptr->src_ref.line       = 0;
                                                                tracked_ref_ptr->src_ref.column     = 0;
                                                                tracked_ref_ptr->inline_ctx.line    = call_line;
                                                                tracked_ref_ptr->inline_ctx.column  = call_column;
                                                                tracked_ref_ptr->inline_ctx.file_id = call_file;
                                                                tracked_ref_ptr->src_ref.filename.reset();
                                                                tracked_ref_ptr->src_ref.dir.reset();

                                                                if (stack_frames_capacity == tracked_refs_cnt || tracked_refs_cnt == K_max_tracked_refs) {
                                                                        // can't track no more
#ifdef DBG_ST
                                                                        SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                                                        goto l100;
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }

                        // to the next compilation unit
                        p = compilation_unit_end;
                        ++compilation_unit;

                        if (compilation_unit == K_max_compilation_units) {
                                // Keep it sane
#ifdef DBG_ST
                                SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                break;
                        }
                }
        l100:

                [[maybe_unused]] static constexpr bool trace{false};

                // Section: 6.2
                struct state_machine final {
                        struct {
                                uint64_t address;
                                uint32_t op_index;
                                uint32_t file;
                                uint32_t line;
                                uint32_t column;
                                bool     is_stmt;
                                bool     basic_block;
                                bool     end_sequence;
                                bool     prologue_end;
                                bool     epilogue_begin;
                                uint32_t isa;
                                uint32_t discriminator;
                        } regs;

                        void reset() {
                                // 6.2.3
                                regs.address        = 0;
                                regs.op_index       = 0;
                                regs.file           = 1;
                                regs.line           = 1;
                                regs.column         = 0;
                                regs.is_stmt        = hdr.default_is_stmt;
                                regs.basic_block    = false;
                                regs.end_sequence   = false;
                                regs.prologue_end   = false;
                                regs.epilogue_begin = false;
                                regs.isa            = 0;
                                regs.discriminator  = 0;
                        }

                        struct {
                                uint8_t        minimum_instruction_len;
                                uint8_t        max_ops_per_instruction;
                                bool           default_is_stmt;
                                int8_t         line_base;
                                uint8_t        line_range;
                                uint8_t        opcode_base;
                                const uint8_t *std_opcode_lens;
                        } hdr;
                } vm;
                std::pair<uintptr_t, tracked_ref *> cu_tracked_refs[K_max_compilation_units_tracked_refs];
                unsigned                            cu_tracked_refs_cnt;

                compilation_unit = 0;
                for (const auto *p = dso->sections.debug_line.offset, *const e = p + dso->sections.debug_line.size(); compilation_unit < K_max_compilation_units && p < e; ++compilation_unit) {
                        // 6.2.4 : The Line Number Program Header
                        uint64_t   unit_length = decode_pod<uint32_t>(p);
                        size_t     offset_size;
                        uint64_t   cu_tracked_refs_addr_max{0};

                        if (unit_length == 0xffffffff) {
                                unit_length = decode_pod<uint64_t>(p);
                                offset_size = sizeof(uint64_t);
                        } else {
                                offset_size = sizeof(uint32_t);
                        }

                        if (0 == (interesting_cus_bm[compilation_unit / 64] & (static_cast<uint64_t>(1) << (compilation_unit & 63)))) {
                                // not interested
                                p += unit_length;
                                continue;
                        }

                        // to speed this up, just get all tracked_ref pointers we need specific to this compilation unit
                        cu_tracked_refs_cnt = 0;

                        for (size_t i = dso_tracked_ref_base; i < tracked_refs_cnt; ++i) {
                                auto tracked_ref_ptr = tracked_refs + i;

                                if (tracked_ref_ptr->cunit == compilation_unit) {
                                        const auto pc = reinterpret_cast<uint64_t>(frames[tracked_ref_ptr->frame_index]);

                                        cu_tracked_refs_addr_max               = std::max(cu_tracked_refs_addr_max, pc);
                                        cu_tracked_refs[cu_tracked_refs_cnt++] = {pc, tracked_ref_ptr};

                                        if (cu_tracked_refs_cnt == K_max_compilation_units_tracked_refs) {
                                                // sanity check
#ifdef DBG_ST
                                                SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                                break;
                                        }
                                }
                        }

                        const auto    unit_end              = p + unit_length;
                        const auto    version               = decode_pod<uint16_t>(p); // specific to line number info, and independent of the DWARF version
                        [[maybe_unused]] const uint8_t address_size          = version >= 5 ? decode_pod<uint8_t>(p) : 0;
                        [[maybe_unused]] const uint8_t segment_selector_size = version >= 5 ? decode_pod<uint8_t>(p) : 0;
                        // number of bytes following the header_length field, to the beginning of the first byte
                        // of the line number program itself.
                        [[maybe_unused]] const uint64_t hdr_len = offset_size == sizeof(uint64_t) ? decode_pod<uint64_t>(p) : decode_pod<uint32_t>(p);
                        size_t         files_cnt{0};

                        vm.hdr.minimum_instruction_len = decode_pod<uint8_t>(p);
                        vm.hdr.max_ops_per_instruction = decode_pod<uint8_t>(p);
                        vm.hdr.default_is_stmt         = decode_pod<bool>(p);
                        vm.hdr.line_base               = decode_pod<int8_t>(p);
                        vm.hdr.line_range              = decode_pod<uint8_t>(p);
                        vm.hdr.opcode_base             = decode_pod<uint8_t>(p);
                        vm.hdr.std_opcode_lens         = p;

#ifdef DBG_ST
                        if constexpr (trace) {
                                SLog("version = ", version, ", address_size = ", address_size, ", hdr_len = ", hdr_len, ", minimum_instruction_len = ", vm.hdr.minimum_instruction_len, ", max_ops_per_instruction = ", vm.hdr.max_ops_per_instruction, ", default_is_stmt = ", vm.hdr.default_is_stmt, ", line_base = ", vm.hdr.line_base, ", line_range = ", vm.hdr.line_range, ", opcode_base = ", vm.hdr.opcode_base, "\n");
                        }
#endif

#ifdef DBG_ST
                        if constexpr (!trace) {
                                // skip past the std_opcode_lens
                                p += sizeof(uint8_t) * (vm.hdr.opcode_base - 1);
                        } else {
                                for (size_t i{1}; i < vm.hdr.opcode_base; ++i) {
                                        SLog("Opcode ", i, " has ", *p++, " args\n");
                                }
                        }
#else
                        // skip past the std_opcode_lens
                        p += sizeof(uint8_t) * (vm.hdr.opcode_base - 1);
#endif

                        if (version == 5) {
				tear_down();
#ifdef DBG_ST
				SLog("Not Supported\n");
#endif
                                return -StackResolverErrors::NoSupport;

                                // TODO: support me
                                // number of entries that ocur int he following directory_entry_format field
                                const auto dir_entry_fmt_count = decode_pod<uint8_t>(p);

#ifdef DBG_ST
                                if constexpr (trace)
                                        SLog("dir_entry_fmt_count = ", dir_entry_fmt_count, "\n");
#endif

                                for (size_t i{0}; i < dir_entry_fmt_count; ++i) {
                                        [[maybe_unused]] const auto content_type = decode_LEB128(p);
                                        [[maybe_unused]] const auto form         = decode_LEB128(p);
                                }

                                const auto dirs_cnt = decode_LEB128(p);

#ifdef DBG_ST
                                if constexpr (trace)
                                        SLog("dirs_cnt = ", dirs_cnt, "\n");
#endif

                                for (size_t i{0}; i < dirs_cnt; ++i) {
                                        // directory_entry_format
                                        [[maybe_unused]] const auto path = reinterpret_cast<const char *>(p);
                                        [[maybe_unused]] const auto len  = strlen(path);

#ifdef DBG_ST
                                        if constexpr (trace)
                                                SLog("[", str_view32(path, len), "]\n");
#endif

                                        p += len + 1;
                                }
                                exit(0);

                                const auto file_name_entry_fmt_cnt = decode_pod<uint8_t>(p);

                                for (size_t i{0}; i < file_name_entry_fmt_cnt; ++i) {
                                        [[maybe_unused]] const auto content_type = decode_LEB128(p);
                                        [[maybe_unused]] const auto form         = decode_LEB128(p);
                                }

                                const auto file_names_cnt = decode_LEB128(p);

                                for (size_t i{0}; i < file_names_cnt; ++i) {
                                        // file_name_entry_format
                                }

                        } else {
                                // Page 115 http://www.dwarfstd.org/doc/DWARF4.pdf
                                // include_directories (sequence of path names)
                                while (*p) {
                                        const auto path = reinterpret_cast<const char *>(p);
                                        const auto len  = strlen(path);

#ifdef DBG_ST
                                        if constexpr (trace)
                                                SLog("[", str_view32(path, len), "]\n");
#endif

                                        p += len + 1;
                                }
                                ++p;

                                // file_names(sequence of file entries)
                                while (*p) {
                                        const auto path = reinterpret_cast<const char *>(p);
                                        const auto len  = strlen(path);

#ifdef DBG_ST
                                        if constexpr (trace)
                                                SLog("File ", files_cnt, " [", str_view32(path, len), "]\n");
#endif

                                        p += len + 1;

                                        [[maybe_unused]] const auto dir_index = decode_LEB128(p);
                                        [[maybe_unused]] const auto modts     = decode_LEB128(p);
                                        [[maybe_unused]] const auto file_size = decode_LEB128(p);

                                        if (files_cnt < K_max_compilation_unit_files) {
                                                comp_unit_files[files_cnt++] = str_view32(path, len);
                                        } else {
#ifdef DBG_ST
                                                SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                        }
                                }
                                ++p;
                        }

                        for (size_t i{0}; i < cu_tracked_refs_cnt; ++i) {
                                auto tracked_ref_ptr = cu_tracked_refs[i].second;

                                if (const auto index = tracked_ref_ptr->inline_ctx.file_id; index && index - 1 < files_cnt) {
                                        tracked_ref_ptr->inline_ctx.filename = comp_unit_files[index - 1];
                                }
                        }

                        vm.reset();

                        [[maybe_unused]] static constexpr bool trace{false};
                        auto                  prev_addr = std::numeric_limits<uint64_t>::max();

                        while (p < unit_end) {
                                const auto opcode = *p++;

                                if (opcode >= vm.hdr.opcode_base) {
                                        // extended
                                        const auto adjusted = opcode - vm.hdr.opcode_base;
                                        const auto addr_inc = (adjusted / vm.hdr.line_range) * vm.hdr.minimum_instruction_len;
                                        const auto line_inc = vm.hdr.line_base + (adjusted % vm.hdr.line_range);

                                        vm.regs.address += addr_inc;
                                        vm.regs.line += line_inc;

#ifdef DBG_ST
                                        if constexpr (trace)
                                                SLog("Extended opcode ", adjusted, " addr_inc ", addr_inc, " => (0x", numwithbase_repr(vm.regs.address, 16), ") line_inc ", line_inc, " => ", vm.regs.line, "\n");
#endif

                                        vm.regs.basic_block    = false;
                                        vm.regs.prologue_end   = false;
                                        vm.regs.epilogue_begin = false;
                                        vm.regs.discriminator  = 0;
                                } else {
                                        switch (opcode) {
                                                case DW_LNS_copy:
                                                        vm.regs.discriminator  = 0;
                                                        vm.regs.basic_block    = false;
                                                        vm.regs.prologue_end   = false;
                                                        vm.regs.epilogue_begin = false;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Copy\n");
#endif
                                                        break;

                                                case DW_LNS_advance_pc: {
                                                        const auto dis = decode_LEB128(p) * vm.hdr.minimum_instruction_len;

                                                        vm.regs.address += dis;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Advance PC by ", dis, ": Set address to 0x", numwithbase_repr(vm.regs.address, 16), "\n");
#endif
                                                } break;

                                                case DW_LNS_advance_line:
                                                        vm.regs.line += decode_signed_LEB128(p);

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Advance line to ", vm.regs.line, "\n");
#endif
                                                        break;

                                                case DW_LNS_set_file:
                                                        vm.regs.file = decode_LEB128(p);

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Set file to ", vm.regs.file, "\n");
#endif
                                                        break;

                                                case DW_LNS_set_column:
                                                        vm.regs.column = decode_LEB128(p);

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Set column to ", vm.regs.column, "\n");
#endif
                                                        break;

                                                case DW_LNS_negate_stmt:
                                                        vm.regs.is_stmt = !vm.regs.is_stmt;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Negated is_stmt ", vm.regs.is_stmt, "\n");
#endif
                                                        break;

                                                case DW_LNS_set_basic_block:
                                                        vm.regs.basic_block = true;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Set basic block\n");
#endif
                                                        break;

                                                case DW_LNS_const_add_pc:
                                                        vm.regs.address += (((0xff - vm.hdr.opcode_base) / vm.hdr.line_range) * vm.hdr.minimum_instruction_len);

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Add PC: Set address to 0x", numwithbase_repr(vm.regs.address, 16), "\n");
#endif
                                                        break;

                                                case DW_LNS_fixed_advance_pc:
                                                        p += decode_pod<uint16_t>(p);
                                                        break;

                                                case DW_LNS_set_prologue_end:
                                                        vm.regs.prologue_end = true;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Prologue End\n");
#endif
                                                        break;

                                                case DW_LNS_set_epilogue_begin:
                                                        vm.regs.epilogue_begin = true;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Epilogue Begin\n");
#endif
                                                        break;

                                                case DW_LNS_set_isa:
                                                        vm.regs.isa = decode_LEB128(p);
#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Set isa to ", vm.regs.isa, "\n");
#endif
                                                        break;

                                                case DW_LNS_extended_op: {
                                                        const auto saved{p};
                                                        auto       len        = decode_LEB128(p);
                                                        const auto sizeof_len = std::distance(saved, p);

                                                        len += sizeof_len;

#ifdef DBG_ST
                                                        if constexpr (trace)
                                                                SLog("Extended op ", *p, " ", len - sizeof_len, "\n");
#endif

                                                        const auto opcode = *p++;

                                                        switch (opcode) {
                                                                case DW_LNE_end_sequence:
                                                                        vm.regs.end_sequence = true;
                                                                        vm.reset();

#ifdef DBG_ST
                                                                        if constexpr (trace)
                                                                                SLog("End Sequence\n");
#endif
                                                                        break;

                                                                case DW_LNE_set_address:
                                                                        vm.regs.address = (len - sizeof_len - 1) == sizeof(uint64_t) ? decode_pod<uint64_t>(p) : decode_pod<uint32_t>(p);

#ifdef DBG_ST
                                                                        if constexpr (trace)
                                                                                SLog("Set address to 0x", numwithbase_repr(vm.regs.address, 16), "\n");
#endif
                                                                        break;

                                                                case DW_LNE_define_file: {
                                                                        // define a new file
                                                                        str_view32 name;

                                                                        name.set(reinterpret_cast<const char *>(p));
                                                                        p += name.size() + 1;

                                                                        [[maybe_unused]] const auto dir   = decode_LEB128(p);
                                                                        [[maybe_unused]] const auto modts = decode_LEB128(p);
                                                                        [[maybe_unused]] const auto size  = decode_LEB128(p);
#ifdef DBG_ST
									if constexpr(trace) {
										SLog("Defining new file ", files_cnt, " [", name, "]\n");
									}
#endif



                                                                        if (files_cnt < K_max_compilation_unit_files) {
                                                                                comp_unit_files[files_cnt++] = name;
                                                                        } else {
#ifdef DBG_ST
                                                                                SLog(ansifmt::bold, ansifmt::color_red, "Hit limit", ansifmt::reset, "\n");
#endif
                                                                        }

                                                                } break;

                                                                case DW_LNE_set_discriminator:
                                                                        vm.regs.discriminator = decode_LEB128(p);

#ifdef DBG_ST
                                                                        if constexpr (trace)
                                                                                SLog("Set discriminator ", vm.regs.discriminator, "\n");
#endif
                                                                        break;

                                                                case DW_LNE_HP_negate_is_UV_update:
                                                                case DW_LNE_HP_push_context:
                                                                case DW_LNE_HP_pop_context:
                                                                case DW_LNE_HP_set_file_line_column:
                                                                case DW_LNE_HP_set_routine_name:
                                                                case DW_LNE_HP_set_sequence:
                                                                case DW_LNE_HP_negate_post_semantics:
                                                                case DW_LNE_HP_negate_function_exit:
                                                                case DW_LNE_HP_negate_front_end_logical:
                                                                case DW_LNE_HP_define_proc:
                                                                        tear_down();
#ifdef DBG_ST
                                                                        SLog("Unsupported\n");
#endif
                                                                        return -StackResolverErrors::NoSupport;

                                                                default:
                                                                        tear_down();
#ifdef DBG_ST
                                                                        SLog("Unsupported\n");
#endif
                                                                        return -StackResolverErrors::NoSupport;
                                                        }
                                                } break;

                                                default:
                                                        tear_down();
#ifdef DBG_ST
                                                        SLog("Unsupported\n");
#endif
                                                        return -StackResolverErrors::NoSupport;
                                        }
                                }

                                if (const auto addr = vm.regs.address; addr != prev_addr) {
                                        // switched to a new address
                                        // remember that backtrace() RETURN ADDRESSES for the corresponding stack frame
                                        // we are not looking for that though, we are looking for the line that includes the call, not the line
                                        // execution will return to once the called function returns.
                                        //
                                        // To accomplish that, we are simply going to track the line for
                                        // the highest address that's lower than the return address we got from backtrace.
                                        //
                                        // This doesn't seem very efficient, but we are memory constrained
                                        // and we shouldn't really need to iterate that many dso_frames anyway
                                        prev_addr = addr;

                                        if (addr < cu_tracked_refs_addr_max) {
                                                // should save us a few iterations

                                                for (unsigned i{0}; i < cu_tracked_refs_cnt; ++i) {
                                                        const auto [pc, tracked_ref_ptr] = cu_tracked_refs[i];

#if 0
							if (addr < pc && tracked_ref_ptr->func_name.Search(_S("select"))) {
                                                                if (addr > tracked_ref_ptr->src_ref.line_addr) {
                                                                        SLog(ansifmt::bold, ansifmt::color_red, "Closest ", vm.regs.line, " ", vm.regs.file, " ", vm.regs.column, ansifmt::reset, " ", pc - addr, "\n");
                                                                }
                                                        }
#endif

                                                        if (addr < pc && addr > tracked_ref_ptr->src_ref.line_addr) {
                                                                tracked_ref_ptr->src_ref.line_addr = addr;

                                                                if (vm.regs.line) {
                                                                        tracked_ref_ptr->src_ref.line     = vm.regs.line;
                                                                        tracked_ref_ptr->src_ref.column   = vm.regs.column;
                                                                        tracked_ref_ptr->src_ref.filename = vm.regs.file - 1 < files_cnt && vm.regs.file
                                                                                                                ? comp_unit_files[vm.regs.file - 1]
                                                                                                                : str_view32();
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                }


                std::sort(tracked_refs + dso_tracked_ref_base, tracked_refs + tracked_refs_cnt, [](const auto &a, const auto &b) noexcept {
                        return a.frame_index < b.frame_index || (a.frame_index == b.frame_index && b.index < a.index);
                });

#ifdef DBG_ST
                for (size_t i = dso_tracked_ref_base; i < tracked_refs_cnt; ++i) {
                        const auto tracked_ref_ptr = tracked_refs + i;

                        SLog(ansifmt::bold, ansifmt::color_red, "TRACK [", tracked_ref_ptr->func_name, "] in [", tracked_ref_ptr->src_ref.filename, "] frame_index = ", tracked_ref_ptr->frame_index, ", index = ", tracked_ref_ptr->index, ", line =", tracked_ref_ptr->src_ref.line, " column = ", tracked_ref_ptr->src_ref.column, ", call_line = ", tracked_ref_ptr->inline_ctx.line, ansifmt::reset, "\n");
                }

                SLog("END  - CU\n");
#endif
        }

        // This is somewhat convoluted, but not by much.
        // Effectively, we need to sort by (frame index ASC, tracked ref index DESC)
        // because multiple (inline) functions may match the same return address (provided by backtrace()), which
        // means multiple tracked refs may share the same frame index.
        //
        // Thankfully, because we get them in the right order in .debug_info, and each inlined function
        // includes (line, column, file) expansion information (see comments above)
        // so all we need to do is use that information from the previous callsite(based on this ordering) for the callsite we are processing now
        std::sort(tracked_refs, tracked_refs + tracked_refs_cnt, [](const auto &a, const auto &b) noexcept {
                return a.frame_index < b.frame_index || (a.frame_index == b.frame_index && b.index < a.index);
        });

        size_t   captured{0};
        uint32_t next_frame_index{0};

        // restore order because
        // we may need to access frame->dso later
        std::sort(frame_dso, frame_dso + frame_dso_size, [](const auto &a, const auto &b) noexcept { return a.first < b.first; });

        const auto process = [ &captured, out,  &storage, &storage_size](const auto frame_index,
                                                                                                                 auto func_name, const auto line, const auto column, auto filename) {
                // XXX: __cxa_demangle() always allocates memory
                // See http://opensource.apple.com//source/libcppabi/libcppabi-14/src/cp-demangle.c
                // we should probably roll our own
                int    status;
                auto   demangle_res = abi::__cxa_demangle(func_name.data() /* its 0 terminated so this works */, nullptr, 0, &status);
                size_t req;
                bool   have_filename{false};

		(void)frame_index;

                if (demangle_res) {
                        func_name.set(demangle_res);
                        req = func_name.size();
                } else {
                        req = func_name.size() + 2;
                }

                // Do we already have this filename?
                for (size_t i{0}; i < captured; ++i) {
                        if (out[i].filename == filename) {
                                filename      = out[i].filename;
                                have_filename = true;
                                break;
                        }
                }

                if (!have_filename)
                        req += filename.size();

                if (req <= storage_size) {
                        auto sf = out + captured++;

                        sf->line   = line;
                        sf->column = column;
                        sf->func.p = reinterpret_cast<const char *>(storage);

                        storage = reinterpret_cast<uint8_t *>(func_name.CopyTo(reinterpret_cast<char *>(storage)));
                        if (demangle_res) {
                                sf->func.len = func_name.size();
                                storage_size -= func_name.size();
                                sf->func.len = func_name.size();
                        } else {
                                *storage++ = '(';
                                *storage++ = ')';
                                storage_size -= func_name.size() + 2;
                                sf->func.len = func_name.size() + 2;
                        }

                        if (!have_filename) {
                                sf->filename.set(reinterpret_cast<const char *>(storage), filename.size());
                                storage = reinterpret_cast<uint8_t *>(filename.CopyTo(reinterpret_cast<char *>(storage)));
                                storage_size -= filename.size();
                        } else {
                                sf->filename = filename;
                        }

                } else {
                        // we are done
                        storage_size = 0;
                }

                if (demangle_res)
                        std::free(demangle_res);
        };

#ifdef DBG_ST
        SLog("depth = ", depth, "\n");

	for (size_t i{0}; i < tracked_refs_cnt; ++i) {
		const auto ref = tracked_refs + i;

		SLog("REF ", i, " ", ref->frame_index, "\n");
	}

	SLog("tracked_refs_cnt = ", tracked_refs_cnt, "\n");
#endif

        for (size_t i{0}; i < tracked_refs_cnt;) {
                auto       ref         = tracked_refs + i;
                const auto frame_index = ref->frame_index;

#ifdef DBG_ST
		SLog(ansifmt::bold, ansifmt::color_green, "next frame index = ", next_frame_index, ", frame_index = ", frame_index, ", frame_index = ",  frame_index, ansifmt::reset, "\n");
#endif

                while (next_frame_index < frame_index) {
                        auto sf  = out + captured;
                        auto dso = tracked_dsos + frame_dso[next_frame_index].second;

                        sf->column   = 0;
                        sf->line     = 0;
                        sf->filename = dso->path_s8();
                        sf->func.reset();
                        ++next_frame_index;
                        if (++captured == stack_frames_capacity)
                                goto l1;
                }

                next_frame_index = ref->frame_index + 1;
                process(ref->frame_index, ref->func_name, ref->src_ref.line, ref->src_ref.column, ref->src_ref.filename);
                if (!storage_size || captured == stack_frames_capacity) {
                        break;
                }

                if (++i < tracked_refs_cnt && tracked_refs[i].frame_index == ref->frame_index) {
                        // inline seq
                        do {
                                const auto ref = tracked_refs + i;

                                process(ref->frame_index, ref->func_name, ref[-1].inline_ctx.line, ref[-1].inline_ctx.column,
                                        ref[-1].src_ref.filename ? ref[-1].src_ref.filename : ref[-1].inline_ctx.filename);

                                if (!storage_size || captured == stack_frames_capacity) {
                                        goto l1;
                                }

                        } while (++i < tracked_refs_cnt && tracked_refs[i].frame_index == frame_index);
                }
        }

#ifdef DBG_ST
        SLog("Now at ", next_frame_index, " ", depth, "\n");
#endif

        while (next_frame_index < depth && captured < stack_frames_capacity) {
                auto sf  = out + captured++;
                auto dso = tracked_dsos + frame_dso[next_frame_index].second;

                sf->column   = 0;
                sf->line     = 0;
                sf->filename = dso->path_s8();
                sf->func.reset();

                ++next_frame_index;
        }

l1:;

	tear_down();
        return captured;
}

int Switch::stacktrace(stack_frame *out, const size_t stack_frames_capacity, uint8_t *storage, const size_t storage_size) {
        void *     frames[7];
        const auto depth = backtrace(frames, sizeof_array(frames));

        return stacktrace(frames, depth, out, stack_frames_capacity, storage, storage_size);
}

// http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
// http://www.skyfree.org/linux/references/ELF_Format.pdf
// http://www.dwarfstd.org/doc/Dwarf3.pdf
// http://ftp.gnu.org/gnu/binutils/binutils-2.26.tar.bz2
//
// verify with readelf or objdump, e.g
// objdump --dwarf=line ./a.out  (use --dwarf=info, ranges, etc)
// or
// readelf  --debug-dump=info ./a.out
#include <cxxabi.h>
#include <elf.h>
#include <unistd.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <link.h> // if missing, apt-get install binutils-dev
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "switch_stacktraces.h"
#include "switch_bitops.h"

#define DW_TAG_array_type 0x01
#define DW_TAG_class_type 0x02
#define DW_TAG_entry_point 0x03
#define DW_TAG_enumeration_type 0x04
#define DW_TAG_formal_parameter 0x05
#define DW_TAG_imported_declaration 0x08
#define DW_TAG_label 0x0a
#define DW_TAG_lexical_block 0x0b
#define DW_TAG_member 0x0d
#define DW_TAG_pointer_type 0x0f
#define DW_TAG_reference_type 0x10
#define DW_TAG_compile_unit 0x11
#define DW_TAG_string_type 0x12
#define DW_TAG_structure_type 0x13
#define DW_TAG_subroutine_type 0x15
#define DW_TAG_typedef 0x16
#define DW_TAG_union_type 0x17
#define DW_TAG_unspecified_parameters 0x18
#define DW_TAG_variant 0x19
#define DW_TAG_common_block 0x1a
#define DW_TAG_common_inclusion 0x1b
#define DW_TAG_inheritance 0x1c
#define DW_TAG_inlined_subroutine 0x1d
#define DW_TAG_module 0x1e
#define DW_TAG_ptr_to_member_type 0x1f
#define DW_TAG_set_type 0x20
#define DW_TAG_subrange_type 0x21
#define DW_TAG_with_stmt 0x22
#define DW_TAG_access_declaration 0x23
#define DW_TAG_base_type 0x24
#define DW_TAG_catch_block 0x25
#define DW_TAG_const_type 0x26
#define DW_TAG_constant 0x27
#define DW_TAG_enumerator 0x28
#define DW_TAG_friend 0x2a
#define DW_TAG_namelist 0x2b
#define DW_TAG_namelist_item 0x2c
#define DW_TAG_packed_type 0x2d
#define DW_TAG_subprogram 0x2e
#define DW_TAG_template_type_parameter 0x2f
#define DW_TAG_thrown_type 0x31
#define DW_TAG_try_block 0x32
#define DW_TAG_variant_part 0x33
#define DW_TAG_variable 0x34
#define DW_TAG_volatile_type 0x35
#define DW_TAG_dwarf_procedure 0x36
#define DW_TAG_restrict_type 0x37
#define DW_TAG_interface_type 0x38
#define DW_TAG_namespace 0x39
#define DW_TAG_imported_module 0x3a
#define DW_TAG_unspecified_type 0x3b
#define DW_TAG_partial_unit 0x3c
#define DW_TAG_imported_unit 0x3d
#define DW_TAG_condition 0x3f
#define DW_TAG_shared_type 0x40

enum Attribute : uint16_t
{
        // Attributes
        DW_AT_sibling = 0x01,
        DW_AT_location = 0x02,
        DW_AT_name = 0x03,
        DW_AT_ordering = 0x09,
        DW_AT_byte_size = 0x0b,
        DW_AT_bit_offset = 0x0c,
        DW_AT_bit_size = 0x0d,
        DW_AT_stmt_list = 0x10,
        DW_AT_low_pc = 0x11,
        DW_AT_high_pc = 0x12,
        DW_AT_language = 0x13,
        DW_AT_discr = 0x15,
        DW_AT_discr_value = 0x16,
        DW_AT_visibility = 0x17,
        DW_AT_import = 0x18,
        DW_AT_string_length = 0x19,
        DW_AT_common_reference = 0x1a,
        DW_AT_comp_dir = 0x1b,
        DW_AT_const_value = 0x1c,
        DW_AT_containing_type = 0x1d,
        DW_AT_default_value = 0x1e,
        DW_AT_inline = 0x20,
        DW_AT_is_optional = 0x21,
        DW_AT_lower_bound = 0x22,
        DW_AT_producer = 0x25,
        DW_AT_prototyped = 0x27,
        DW_AT_return_addr = 0x2a,
        DW_AT_start_scope = 0x2c,
        DW_AT_bit_stride = 0x2e,
        DW_AT_upper_bound = 0x2f,
        DW_AT_abstract_origin = 0x31,
        DW_AT_accessibility = 0x32,
        DW_AT_address_class = 0x33,
        DW_AT_artificial = 0x34,
        DW_AT_base_types = 0x35,
        DW_AT_calling_convention = 0x36,
        DW_AT_count = 0x37,
        DW_AT_data_member_location = 0x38,
        DW_AT_decl_column = 0x39,
        DW_AT_decl_file = 0x3a,
        DW_AT_decl_line = 0x3b,
        DW_AT_declaration = 0x3c,
        DW_AT_discr_list = 0x3d,
        DW_AT_encoding = 0x3e,
        DW_AT_external = 0x3f,
        DW_AT_frame_base = 0x40,
        DW_AT_friend = 0x41,
        DW_AT_identifier_case = 0x42,
        DW_AT_macro_info = 0x43,
        DW_AT_namelist_item = 0x44,
        DW_AT_priority = 0x45,
        DW_AT_segment = 0x46,
        DW_AT_specification = 0x47,
        DW_AT_static_link = 0x48,
        DW_AT_type = 0x49,
        DW_AT_use_location = 0x4a,
        DW_AT_variable_parameter = 0x4b,
        DW_AT_virtuality = 0x4c,
        DW_AT_vtable_elem_location = 0x4d,
        DW_AT_allocated = 0x4e,
        DW_AT_associated = 0x4f,
        DW_AT_data_location = 0x50,
        DW_AT_byte_stride = 0x51,
        DW_AT_entry_pc = 0x52,
        DW_AT_use_UTF8 = 0x53,
        DW_AT_extension = 0x54,
        DW_AT_ranges = 0x55,
        DW_AT_trampoline = 0x56,
        DW_AT_call_column = 0x57,
        DW_AT_call_file = 0x58,
        DW_AT_call_line = 0x59,
        DW_AT_description = 0x5a,
        DW_AT_binary_scale = 0x5b,
        DW_AT_decimal_scale = 0x5c,
        DW_AT_small = 0x5d,
        DW_AT_decimal_sign = 0x5e,
        DW_AT_digit_count = 0x5f,
        DW_AT_picture_string = 0x60,
        DW_AT_mutable = 0x61,
        DW_AT_threads_scaled = 0x62,
        DW_AT_explicit = 0x63,
        DW_AT_object_pointer = 0x64,
        DW_AT_endianity = 0x65,
        DW_AT_elemental = 0x66,
        DW_AT_pure = 0x67,
        DW_AT_recursive = 0x68,
        DW_AT_signature = 0x69,
        DW_AT_main_subprogram = 0x6a,
        DW_AT_data_bit_offset = 0x6b,
        DW_AT_const_expr = 0x6c,
        DW_AT_enum_class = 0x6d,
        DW_AT_linkage_name = 0x6e,

        // New in DWARF 5:
        DW_AT_string_length_bit_size = 0x6f,
        DW_AT_string_length_byte_size = 0x70,
        DW_AT_rank = 0x71,
        DW_AT_str_offsets_base = 0x72,
        DW_AT_addr_base = 0x73,
        DW_AT_ranges_base = 0x74,
        DW_AT_dwo_id = 0x75,
        DW_AT_dwo_name = 0x76,
        DW_AT_reference = 0x77,
        DW_AT_rvalue_reference = 0x78,
        DW_AT_macros = 0x79,

        DW_AT_lo_user = 0x2000,
        DW_AT_hi_user = 0x3fff,

        DW_AT_MIPS_loop_begin = 0x2002,
        DW_AT_MIPS_tail_loop_begin = 0x2003,
        DW_AT_MIPS_epilog_begin = 0x2004,
        DW_AT_MIPS_loop_unroll_factor = 0x2005,
        DW_AT_MIPS_software_pipeline_depth = 0x2006,
        DW_AT_MIPS_linkage_name = 0x2007,
        DW_AT_MIPS_stride = 0x2008,
        DW_AT_MIPS_abstract_name = 0x2009,
        DW_AT_MIPS_clone_origin = 0x200a,
        DW_AT_MIPS_has_inlines = 0x200b,
        DW_AT_MIPS_stride_byte = 0x200c,
        DW_AT_MIPS_stride_elem = 0x200d,
        DW_AT_MIPS_ptr_dopetype = 0x200e,
        DW_AT_MIPS_allocatable_dopetype = 0x200f,
        DW_AT_MIPS_assumed_shape_dopetype = 0x2010,

        // This one appears to have only been implemented by Open64 for
        // fortran and may conflict with other extensions.
        DW_AT_MIPS_assumed_size = 0x2011,

        // GNU extensions
        DW_AT_sf_names = 0x2101,
        DW_AT_src_info = 0x2102,
        DW_AT_mac_info = 0x2103,
        DW_AT_src_coords = 0x2104,
        DW_AT_body_begin = 0x2105,
        DW_AT_body_end = 0x2106,
        DW_AT_GNU_vector = 0x2107,
        DW_AT_GNU_template_name = 0x2110,

        DW_AT_GNU_odr_signature = 0x210f,
        DW_AT_GNU_macros = 0x2119,

        // Extensions for Fission proposal.
        DW_AT_GNU_dwo_name = 0x2130,
        DW_AT_GNU_dwo_id = 0x2131,
        DW_AT_GNU_ranges_base = 0x2132,
        DW_AT_GNU_addr_base = 0x2133,
        DW_AT_GNU_pubnames = 0x2134,
        DW_AT_GNU_pubtypes = 0x2135,
        DW_AT_GNU_discriminator = 0x2136,

        // Borland extensions.
        DW_AT_BORLAND_property_read = 0x3b11,
        DW_AT_BORLAND_property_write = 0x3b12,
        DW_AT_BORLAND_property_implements = 0x3b13,
        DW_AT_BORLAND_property_index = 0x3b14,
        DW_AT_BORLAND_property_default = 0x3b15,
        DW_AT_BORLAND_Delphi_unit = 0x3b20,
        DW_AT_BORLAND_Delphi_class = 0x3b21,
        DW_AT_BORLAND_Delphi_record = 0x3b22,
        DW_AT_BORLAND_Delphi_metaclass = 0x3b23,
        DW_AT_BORLAND_Delphi_constructor = 0x3b24,
        DW_AT_BORLAND_Delphi_destructor = 0x3b25,
        DW_AT_BORLAND_Delphi_anonymous_method = 0x3b26,
        DW_AT_BORLAND_Delphi_interface = 0x3b27,
        DW_AT_BORLAND_Delphi_ABI = 0x3b28,
        DW_AT_BORLAND_Delphi_return = 0x3b29,
        DW_AT_BORLAND_Delphi_frameptr = 0x3b30,
        DW_AT_BORLAND_closure = 0x3b31,

        // LLVM project extensions.
        DW_AT_LLVM_include_path = 0x3e00,
        DW_AT_LLVM_config_macros = 0x3e01,
        DW_AT_LLVM_isysroot = 0x3e02,

        // Apple extensions.
        DW_AT_APPLE_optimized = 0x3fe1,
        DW_AT_APPLE_flags = 0x3fe2,
        DW_AT_APPLE_isa = 0x3fe3,
        DW_AT_APPLE_block = 0x3fe4,
        DW_AT_APPLE_major_runtime_vers = 0x3fe5,
        DW_AT_APPLE_runtime_class = 0x3fe6,
        DW_AT_APPLE_omit_frame_ptr = 0x3fe7,
        DW_AT_APPLE_property_name = 0x3fe8,
        DW_AT_APPLE_property_getter = 0x3fe9,
        DW_AT_APPLE_property_setter = 0x3fea,
        DW_AT_APPLE_property_attribute = 0x3feb,
        DW_AT_APPLE_objc_complete_type = 0x3fec,
        DW_AT_APPLE_property = 0x3fed
};

enum Form : uint16_t
{
        // Attribute form encodings
        DW_FORM_addr = 0x01,
        DW_FORM_block2 = 0x03,
        DW_FORM_block4 = 0x04,
        DW_FORM_data2 = 0x05,
        DW_FORM_data4 = 0x06,
        DW_FORM_data8 = 0x07,
        DW_FORM_string = 0x08,
        DW_FORM_block = 0x09,
        DW_FORM_block1 = 0x0a,
        DW_FORM_data1 = 0x0b,
        DW_FORM_flag = 0x0c,
        DW_FORM_sdata = 0x0d,
        DW_FORM_strp = 0x0e,
        DW_FORM_udata = 0x0f,
        DW_FORM_ref_addr = 0x10,
        DW_FORM_ref1 = 0x11,
        DW_FORM_ref2 = 0x12,
        DW_FORM_ref4 = 0x13,
        DW_FORM_ref8 = 0x14,
        DW_FORM_ref_udata = 0x15,
        DW_FORM_indirect = 0x16,
        DW_FORM_sec_offset = 0x17,
        DW_FORM_exprloc = 0x18,
        DW_FORM_flag_present = 0x19,
        DW_FORM_ref_sig8 = 0x20,

        // Extensions for Fission proposal
        DW_FORM_GNU_addr_index = 0x1f01,
        DW_FORM_GNU_str_index = 0x1f02,

        // Alternate debug sections proposal (output of "dwz" tool).
        DW_FORM_GNU_ref_alt = 0x1f20,
        DW_FORM_GNU_strp_alt = 0x1f21
};

enum DecimalSignEncoding
{
        // Decimal sign attribute values
        DW_DS_unsigned = 0x01,
        DW_DS_leading_overpunch = 0x02,
        DW_DS_trailing_overpunch = 0x03,
        DW_DS_leading_separate = 0x04,
        DW_DS_trailing_separate = 0x05
};

enum EndianityEncoding
{
        // Endianity attribute values
        DW_END_default = 0x00,
        DW_END_big = 0x01,
        DW_END_little = 0x02,
        DW_END_lo_user = 0x40,
        DW_END_hi_user = 0xff
};

enum AccessAttribute
{
        // Accessibility codes
        DW_ACCESS_public = 0x01,
        DW_ACCESS_protected = 0x02,
        DW_ACCESS_private = 0x03
};

enum VisibilityAttribute
{
        // Visibility codes
        DW_VIS_local = 0x01,
        DW_VIS_exported = 0x02,
        DW_VIS_qualified = 0x03
};

struct attr_value
{
        uint64_t val;
        const char *str;
};

static uint64_t parseLEB128(const uint8_t *&data)
{
        const auto *p = data;
        uint8_t shift{0}, byte;
        int64_t result{0};

        do
        {
                byte = *p++;

                result |= ((unsigned long int)(byte & 0x7f)) << shift;
                shift += 7;
        } while (byte & 0x80);

        data = p;

        return result;
}

static int64_t parseSignedLEB128(const uint8_t *&data)
{
        const auto *p = data;
        uint8_t shift{0}, byte;
        int64_t result{0};

        do
        {
                byte = *p++;

                result |= ((unsigned long int)(byte & 0x7f)) << shift;
                shift += 7;
        } while (byte & 0x80);

        data = p;

        if ((shift < 8 * sizeof(result)) && (byte & 0x40))
                result |= -1L << shift;

        return result;
}

struct abbrev_attr
{
        uint16_t name;
        uint16_t form;
};

struct abbrev_entry
{
        uint32_t entry;
        uint32_t tag;
        bool children;
        abbrev_attr *allAttrs;
        uint8_t attrsCnt;
        const abbrev_entry *next;
};

struct parse_attrvalue_ctx
{
        const uint8_t *fileDataU8;
        const range64_t debugStr;
        const uint16_t version;
        const uint8_t offsetSize;
        const uint8_t address_size;

        const abbrev_entry **dict;
        size_t dictSize;

        const uint8_t *declsBase;
};

static bool parseAttrValue(const parse_attrvalue_ctx *const parserCtx, const uint32_t form, const uint8_t *&it, attr_value *const val)
{
        val->str = nullptr;

        switch (form)
        {
                case DW_FORM_ref_addr:
                        if (parserCtx->version == 3 || parserCtx->version == 4)
                        {
                                if (parserCtx->offsetSize == sizeof(uint32_t))
                                        val->val = *(uint32_t *)it;
                                else
                                        val->val = *(uint64_t *)it;

                                it += parserCtx->offsetSize;
                                break;
                        }
                // fallthrough
                case DW_FORM_addr:
                        switch (parserCtx->address_size)
                        {
                                case sizeof(uint64_t):
                                        val->val = *(uint64_t *)it;
                                        break;

                                case sizeof(uint32_t):
                                        val->val = *(uint32_t *)it;
                                        break;

                                case sizeof(uint16_t):
                                        val->val = *(uint16_t *)it;
                                        break;
                        }
                        it += parserCtx->address_size;
                        break;

                case DW_FORM_GNU_ref_alt:
                case DW_FORM_sec_offset:
                        if (parserCtx->offsetSize == sizeof(uint32_t))
                                val->val = *(uint32_t *)it;
                        else if (parserCtx->offsetSize == sizeof(uint64_t))
                                val->val = *(uint64_t *)it;
                        it += parserCtx->offsetSize;
                        break;

                case DW_FORM_block2:
                        it += (*(uint16_t *)it) + sizeof(uint16_t);
                        break;

                case DW_FORM_block4:
                        it += (*(uint32_t *)it) + sizeof(uint32_t);
                        break;

                case DW_FORM_data2:
                        val->val = *(uint16_t *)it;
                        it += sizeof(uint16_t);
                        break;

                case DW_FORM_data4:
                        val->val = *(uint32_t *)it;
                        it += sizeof(uint32_t);
                        break;

                case DW_FORM_data8:
                        val->val = *(uint64_t *)it;
                        it += sizeof(uint64_t);
                        break;

                case DW_FORM_string:
                        for (val->str = (char *)it++; *it; ++it)
                                continue;
                        ++it;
                        break;

                case DW_FORM_strp:
                {
                        uint64_t o;

                        if (parserCtx->offsetSize == sizeof(uint64_t))
                                o = *(uint64_t *)it;
                        else
                                o = *(uint32_t *)it;

                        it += parserCtx->offsetSize;

                        assert(parserCtx->debugStr.Contains(parserCtx->debugStr.offset + o));

                        val->str = reinterpret_cast<const char *>(parserCtx->fileDataU8) + parserCtx->debugStr.offset + o;
                }
                break;

                case DW_FORM_GNU_strp_alt:
                        it += parserCtx->offsetSize;
                        break;

                case DW_FORM_exprloc:
                case DW_FORM_block:
                        it += parseLEB128(it);
                        break;

                case DW_FORM_block1:
                        it += (*it) + sizeof(uint8_t);
                        break;

                case DW_FORM_data1:
                        ++it;
                        break;

                case DW_FORM_flag:
                        ++it;
                        break;

                case DW_FORM_flag_present:
                        break;

                case DW_FORM_sdata:
                        parseLEB128(it);
                        break;

                case DW_FORM_udata:
                        parseLEB128(it);
                        break;

                case DW_FORM_ref1:
                        val->val = *(uint8_t *)it;
                        it += sizeof(uint8_t);
                        break;

                case DW_FORM_ref2:
                        val->val = *(uint16_t *)it;
                        it += sizeof(uint16_t);
                        break;

                case DW_FORM_ref4:
                        val->val = *(uint32_t *)it;
                        it += sizeof(uint32_t);
                        break;

                case DW_FORM_ref8:
                        val->val = *(uint64_t *)it;
                        it += sizeof(uint64_t);
                        break;

                case DW_FORM_ref_udata:
                        parseLEB128(it);
                        break;

                case DW_FORM_indirect:
                {
                        const auto f = parseLEB128(it);
                        attr_value otherAttrValue;

                        if (!parseAttrValue(parserCtx, f, it, &otherAttrValue))
                                return false;
                }
                break;

                default:
                        return false;
        }

        return true;
}

static void logError(const char *const reason, const size_t len)
{
        // fopen()/fputs() may allocate memory; just write directly to stdout
        write(STDERR_FILENO, reason, len);
}

static const char *locateAbstractInstanceName(const parse_attrvalue_ctx *const ctx, const uint32_t form, const uint32_t ref)
{
        const char *name{nullptr};

        if (form == DW_FORM_ref_addr)
        {
                logError(_S("Support pending for DW_FORM_ref_addr\n"));
                return nullptr;
        }
        else if (form == DW_FORM_GNU_ref_alt)
        {
                logError(_S("Support pending for DW_FORM_GNU_ref_alt\n"));
                return nullptr;
        }
        else
        {
                const auto dict = ctx->dict;
                const auto dictSize = ctx->dictSize;
                const auto *p = ctx->declsBase + ref;
                const auto anum = parseLEB128(p);

                if (anum)
                {
                        const abbrev_entry *ent;
                        attr_value atValue;

                        for (ent = dict[anum & (dictSize - 1)]; ent && ent->entry != anum; ent = ent->next)
                                continue;

                        if (unlikely(!ent))
                                return (char *)UINTPTR_MAX;

                        for (const auto *ait = ent->allAttrs, *const e = ait + ent->attrsCnt; ait != e; ++ait)
                        {
                                if (!parseAttrValue(ctx, ait->form, p, &atValue))
                                        return (char *)UINTPTR_MAX;

                                switch (ait->name)
                                {
                                        case DW_AT_name:
                                                if (!name && atValue.str)
                                                        name = atValue.str;
                                                break;

                                        case DW_AT_specification:
                                                name = locateAbstractInstanceName(ctx, ait->form, atValue.val);
                                                break;

                                        case DW_AT_linkage_name:
                                        case DW_AT_MIPS_linkage_name:
                                                if (atValue.str)
                                                        name = atValue.str;
                                                break;

                                        default:
                                                break;
                                }
                        }
                }
        }

        return name;
}

struct callback_ctx
{
        size_t n;
        dl_phdr_info *dsos;
};

static int dl_iterate_phdr_callback(struct dl_phdr_info *const info, size_t size, void *data)
{
        auto *const ctx = (callback_ctx *)data;

        if (ctx->n != 512)
                ctx->dsos[ctx->n++] = *info;

        return 0;
}

int32_t Switch::Stacktraces::captureFrames(void **pcs, size_t pcsCnt, simple_allocator &allocator, Switch::Stacktraces::Frame *const frames, const size_t maxFrames)
{
        if (!maxFrames)
                return 0;

        // Maybe 32- or 64-bit so let's just alias and support whatever the type
        // During linking, the ELF file is comprised of an ELF header, an optional program header table,a nd SECTIONs
        // During execution(when loaded), sections are identfied as segments.
        // So different semantics and name but both refer to the same core concstruct
        using segment_hdr_t = std::remove_reference<decltype(*(dl_phdr_info{}).dlpi_phdr)>::type;

        struct dir_desc
        {
                strwlen32_t name;
                dir_desc *next;
        };

        struct file_desc
        {
                strwlen32_t name;
                uint32_t dirIdx;
                file_desc *next;
        };

        dl_phdr_info dsos[512];
        callback_ctx ctx{0, dsos};

        uint64_t dsoFrames[32];
        uint32_t pci{0}, frameIdx{0};
        // It is essential that we use a mmap backing store so that we won't have to interface with the allocator
        // we can't allocate memory in this exec.ctx
        simple_allocator localAllocator(2 * 1024 * 1024, simple_allocator::BackingStore{});

        // Keep it sane
        pcsCnt = std::min<size_t>(pcsCnt, sizeof_array(dsoFrames));

        // We are not going to use dladdr() because it internally allocates memory
        // it's also likely it just iterates the DSOs registry and each section like we do anyway.
        // dladdr() also attempts to match PC with a symbol and we don't want to do that
        dl_iterate_phdr(dl_iterate_phdr_callback, &ctx);

        const auto dsosCnt = ctx.n;

        auto segmentVMA = [](const dl_phdr_info *const dso, const segment_hdr_t *const sectionHdr)
        {
                return range64_t{uintptr_t(dso->dlpi_addr) + uintptr_t(sectionHdr->p_vaddr), sectionHdr->p_memsz};
        };

        // we could have sorted collected DSOs and memory resident sections and performed binary search instead of a linear search
        // but in practice it's not really a concern, though we may end up doing that in the future e.g if we identify too many DSOs/memory resident sections
        // for a few usecs worth of performance gains
        auto dsoLookup = [&dsos, dsosCnt, &segmentVMA](const uintptr_t pc) -> std::pair<const dl_phdr_info *, const segment_hdr_t *>
        {
                for (const auto dso : Switch::make_range(dsos, dsosCnt))
                {
                        for (uint32_t i{0}; i != dso->dlpi_phnum; ++i)
                        {
                                const auto section = dso->dlpi_phdr + i;
                                const auto vma = segmentVMA(dso, section);

                                if (vma.Contains(pc))
                                        return {dso, section};
                        }
                }

                return {nullptr, nullptr};
        };

        while (pci != pcsCnt)
        {
                uint32_t dsoFramesCnt{0};
                const auto pc = uintptr_t(pcs[pci]);
                const auto res = dsoLookup(pc);
                const auto dso = res.first;

                if (!dso)
                {
                        logError(_S("Cannot determine DSO from PC\n"));
                        return -1;
                }

                // Simple heuristics - abort early if we are not going to need for system libraries hooks
                if (dso->dlpi_name && strstr(dso->dlpi_name, "libpthread.so"))
                        break;

                const auto relocationOffset = uintptr_t(dso->dlpi_addr);

                // Collect all frames for this DSO
                // Perform fix-up for relocations
                do
                {
                        const auto offset = uintptr_t(pcs[pci]) - relocationOffset;

                        dsoFrames[dsoFramesCnt++] = offset;
                } while ((++pci) != pcsCnt && dsoLookup(uintptr_t(pcs[pci])).first == dso);

                // if we were only interested in the loaded segments, we could just access all that directly because
                // they are already memory resident
                // but we are interested in debug sections, which are not
                const char *const path = dso->dlpi_name && dso->dlpi_name[0] ? dso->dlpi_name : "/proc/self/exe";
                int fd = open(path, O_RDONLY | O_LARGEFILE);

                if (unlikely(fd == -1))
                {
                        logError(_S("open() failed\n"));
                        return -1;
                }

                const auto fileSize = lseek64(fd, 0, SEEK_END);

                if (unlikely(fileSize < 16))
                {
                        logError(_S("Unexpected filesize\n"));
                        close(fd);
                        return -1;
                }

                auto *const fileData = mmap(nullptr, fileSize, PROT_READ, MAP_SHARED, fd, 0);

                close(fd);

                if (unlikely(fileData == MAP_FAILED))
                {
                        logError(_S("Unable to mmap module file\n"));
                        return -1;
                }

                madvise(fileData, fileSize, MADV_SEQUENTIAL);
                localAllocator.Reuse();

                const auto *const fileDataU8 = static_cast<const uint8_t *>(fileData);
                const uint8_t *p = fileDataU8;

                if (unlikely(*p != 0x7f || memcmp(p + 1, _S("ELF"))))
                {
                        logError(_S("Unexpected header magic number\n"));
                        munmap(fileData, fileSize);
                        return -1;
                }
                p += 4;

                const bool format64 = (*(p++) == 2), format32 = !format64;
                const bool littleEndian = (*(p++) == 1), bigEndian = !littleEndian; // affects interpretation of multi-byte fields, starting with offset 0x10
                const uint8_t ident = *p++;                                         // always set to 1, for the original version of ELF
                const uint8_t ABI = *p++;
                const uint8_t ABIversion = *p++; // LK 2.6+ has no definition for it, can safely ignore it

                if (ABI != 0x03 && ABI)
                {
                        logError(_S("ABI is specified, and it's not Linux\n"));
                        munmap(fileData, fileSize);
                        return -1;
                }

                (void)littleEndian;
                (void)bigEndian;
                (void)ident;
                (void)ABIversion;

                p += 7; // padding(currently unused)

                // type (relocatable, executable, shared, or core). See ET_DYN
                const uint16_t type = *(uint16_t *)p;
                p += 2; // We care for ET_DYN(3)

                // We care for 0x3E(x864-64) and to a lesser 0x03(x86). See EM_386
                const uint16_t targetISA = *(uint16_t *)p;
                p += 2;

                // Set to 1, for the original version of ELF
                const uint32_t version = *(uint32_t *)p;
                p += sizeof(uint32_t);

                uint64_t entryOffset, programHeaderOffset, sectionHeaderOffset;

                (void)type;
                (void)targetISA;
                (void)version;

                if (format32)
                {
                        entryOffset = *(uint32_t *)p;
                        p += sizeof(uint32_t);
                        programHeaderOffset = *(uint32_t *)p;
                        p += sizeof(uint32_t);
                        sectionHeaderOffset = *(uint32_t *)p;
                        p += sizeof(uint32_t);
                }
                else
                {
                        // Memory address of the entry point, from where the process starts executing
                        entryOffset = *(uint64_t *)p;
                        p += sizeof(uint64_t);

                        // Points to the start of the program header table.
                        // It usually follows the file header immediately, making the offset 0x34 or ox40, for 32- and 64-bit ELF exexutables respectively
                        programHeaderOffset = *(uint64_t *)p;
                        p += sizeof(uint64_t);

                        // Points to the start of the section header table
                        sectionHeaderOffset = *(uint64_t *)p;
                        p += sizeof(uint64_t);
                }

                // Interpretation of flags depends on the target arch.
                const uint32_t fileFlags = *(uint32_t *)p;
                p += sizeof(uint32_t);

                // Contains the size of this header, normally 64bytes for 64-bit and 52 for 32-bit format
                const uint16_t headerSize = *(uint16_t *)p;
                p += sizeof(uint16_t); // ELF header size

                // size of the program header table entry(should be same size for all)
                const uint16_t programHeaderEntrySize = *(uint16_t *)p;
                p += sizeof(uint16_t);

                // Number of the entries in the program header table (program header size = programHeaderEntrySize * programHeaderEntries)
                const uint16_t programHeaderEntries = *(uint16_t *)p;
                p += sizeof(uint16_t);

                // size of section header table entry
                const uint16_t sectionHeaderEntrySize = *(uint16_t *)p;
                p += sizeof(uint16_t);

                // number of entries in the section header table
                const uint16_t sectionHeaderEntries = *(uint16_t *)p;
                p += sizeof(uint16_t);

                // index of the section header table entry that contains the section names
                const uint16_t sectionHeaderNameEntriesIndex = *(uint16_t *)p;
                p += sizeof(uint16_t);

                (void)fileFlags;
                (void)headerSize;
                (void)programHeaderEntrySize;
                (void)programHeaderEntries;
                (void)sectionHeaderNameEntriesIndex;

                // Where's the STRTAB section?
                const auto *shrTabP = fileDataU8 + sectionHeaderOffset + sectionHeaderEntrySize * sectionHeaderNameEntriesIndex;
                range64_t debugInfo, debugLine, debugAbbrev, debugRanges, debugStr, shrTab, strTab;

                // we 'll need access to the STRTAB in order to resolve names of the sections later
                {
                        const auto n = *(uint32_t *)shrTabP;
                        shrTabP += sizeof(uint32_t);
                        const auto t = *(uint32_t *)shrTabP;
                        shrTabP += sizeof(uint32_t);

                        (void)n;
                        assert(t == SHT_STRTAB);

                        if (format32)
                        {
                                shrTabP += sizeof(uint32_t) + sizeof(uint32_t);
                                shrTab.offset = *(uint32_t *)shrTabP;
                                shrTabP += sizeof(uint32_t);
                                shrTab.len = *(uint32_t *)shrTabP;
                                shrTabP += sizeof(uint32_t);
                        }
                        else
                        {
                                shrTabP += sizeof(uint64_t) + sizeof(uint64_t);
                                shrTab.offset = *(uint64_t *)shrTabP;
                                shrTabP += sizeof(uint64_t);
                                shrTab.len = *(uint64_t *)shrTabP;
                                shrTabP += sizeof(uint64_t);
                        }

                        assert(shrTab);
                        assert(*(fileDataU8 + shrTab.offset) == 0); // STRTAB section holds an empty string as the first encoded string
                }

                p = fileDataU8 + sectionHeaderOffset;

                for (uint32_t i{0}; i != sectionHeaderEntries; ++i)
                {
                        uint64_t flags, addr, offset, size;
                        const auto *const sectionBase = p;
                        strwlen32_t nameRepr;

                        // An offset to a string in the ".shstrtab" section, that represents the name of this section
                        const uint32_t name = *(uint32_t *)p;
                        p += sizeof(uint32_t);

                        // Identifies the type of this header.
                        // Some common examples include (0x00000000: NULL, 0x00000001: PROGBITS, 0x00000002: SYMTAB, 0x00000003: STRTAB)
                        const uint32_t type = *(uint32_t *)p;
                        p += sizeof(uint32_t);

                        if (format32)
                        {
                                flags = *(uint32_t *)p;
                                p += sizeof(uint32_t);

                                addr = *(uint32_t *)p;
                                p += sizeof(uint32_t);

                                offset = *(uint32_t *)p;
                                p += sizeof(uint32_t);

                                size = *(uint32_t *)p;
                                p += sizeof(uint32_t);
                        }
                        else
                        {
                                flags = *(uint64_t *)p;
                                p += sizeof(uint64_t);

                                // Virtual address of the section in memory, for sections that are loaded
                                // If this section will appear in the memory image, this is where it should reside. Otherwise its 0
                                addr = *(uint64_t *)p;
                                p += sizeof(uint64_t);

                                // byte offset from the beginning of the file to the first byte in the section
                                // one section, SHT_NOBITS, occupies no space in the file, and its sh_offset locates the conceptual placement in the file
                                offset = *(uint64_t *)p;
                                p += sizeof(uint64_t);

                                // Size in bytes of the section in the file image. Maybe 0
                                // Unless section type is SHT_NOBITS, the section occupies that many bytes in the file.
                                // A section of type SHT_NOBITS may have non-zero size, but occupies no space in the file
                                size = *(uint64_t *)p;
                                p += sizeof(uint64_t);
                        }

                        // Section header index link, whose interprestation depends on the section type
                        const uint32_t link = *(uint32_t *)p;
                        p += sizeof(uint32_t);

                        // Extra information, depends on section type
                        const uint32_t info = *(uint32_t *)p;
                        p += sizeof(uint32_t);

                        uint64_t addrAlign, entSize;

                        if (format32)
                        {
                                addrAlign = *(uint32_t *)p;
                                p += sizeof(uint32_t);

                                entSize = *(uint32_t *)p;
                                p += sizeof(uint32_t);
                        }
                        else
                        {
                                // Some sections have address alignment contraints.
                                // For example, if a section holds a doubleword, the system must ensure doubleword alignemnt for the entire section.
                                // That is, the value of sh_addr must be congruent to 0, module the value of shr_addralign.
                                // Currently, onl 0 and positive integral powers of two are allowed.
                                // Values 0 and 1 mean the section has no alignemnt constraints
                                addrAlign = *(uint64_t *)p;
                                p += sizeof(uint64_t);

                                // Some sections hold a table of fixed-size entries, sych as a symbol table.
                                // For such a section, this member gives the size in bytes of each entry.
                                // It is 0 if the section does not hold a table of fixed-size entries.
                                entSize = *(uint64_t *)p;
                                p += sizeof(uint64_t);
                        }

                        assert(p - sectionBase == sectionHeaderEntrySize);

                        const char *n = reinterpret_cast<const char *>(fileDataU8 + shrTab.offset + name);

                        for (nameRepr.p = n; *n; ++n)
                                continue;

                        nameRepr.SetEnd(n);


                        if (type == SHT_SYMTAB || type == SHT_DYNSYM)
                        {
                                // We are accessident that directly from the DSO memory resident sections
                        }
                        else if (type == SHT_STRTAB)
                                strTab.Set(offset, size);
                        else if (nameRepr.Eq(_S(".debug_info")))
                                debugInfo.Set(offset, size);
                        else if (nameRepr.Eq(_S(".debug_line")))
                                debugLine.Set(offset, size);
                        else if (nameRepr.Eq(_S(".debug_abbrev")))
                                debugAbbrev.Set(offset, size);
                        else if (nameRepr.Eq(_S(".debug_ranges")))
                                debugRanges.Set(offset, size);
                        else if (nameRepr.Eq(_S(".debug_str")))
                                debugStr.Set(offset, size);
                        (void)link;
                        (void)info;
                        (void)addrAlign;
                        (void)entSize;
                }

                struct function
                {
                        const char *name;
                        uint32_t declLine;
                        FuncType funcType;

                        uint32_t pcLine;

                        uint32_t frameIdx;
                        uint32_t nestingLevel;

                        range64_t range;
                        FuncType type;

                        // for the line
                        uint32_t file;
                        uint64_t best;
                        uint32_t line;
                        file_desc *filesList;
                        dir_desc *dirsList;
                };

                uint64_t compilationUnitsMap[4096 / sizeof(uint64_t)] = {0};
                function matchedFunctions[256 + 64];
                uint32_t matchedFunctionsCnt{0};

                if (debugInfo && debugAbbrev && debugRanges && debugStr && debugLine)
                {
                        struct CompilationUnitHeader
                        {
                                uint64_t unit_length;
                                uint16_t version;
                                uint64_t debug_abbrev_offset;
                                uint8_t address_size;
                        };

                        const auto *const sectionBase = fileDataU8 + debugInfo.offset, *const end = sectionBase + debugInfo.len;
                        const auto *start = sectionBase;
                        size_t unit{0};
                        CompilationUnitHeader cuh;
                        function _function;

                        for (; start != end; ++unit)
                        {
                                uint8_t initialLengthSize, offsetSize;
                                const auto *p = start;
                                const auto *const declsBase = p;

                                cuh.unit_length = *(uint32_t *)p;
                                p += sizeof(uint32_t);

                                if (cuh.unit_length == 0xffffffff)
                                {
                                        cuh.unit_length = *(uint64_t *)p;
                                        p += sizeof(uint64_t);

                                        offsetSize = sizeof(uint64_t);
                                        initialLengthSize = sizeof(uint32_t) + sizeof(uint64_t);
                                }
                                else
                                {
                                        offsetSize = sizeof(uint32_t);
                                        initialLengthSize = sizeof(uint32_t);
                                }

                                cuh.version = *(uint16_t *)p;
                                p += sizeof(uint16_t);

                                const uintptr_t cuOffset = p - start;

                                if (offsetSize == sizeof(uint64_t))
                                {
                                        cuh.debug_abbrev_offset = *(uint64_t *)p;
                                        p += sizeof(uint64_t);
                                }
                                else
                                {
                                        cuh.debug_abbrev_offset = *(uint32_t *)p;
                                        p += sizeof(uint32_t);
                                }

                                cuh.address_size = *p++;

                                if (cuOffset + cuh.unit_length + initialLengthSize > debugInfo.len)
                                {
                                        logError(_S("Debug info is corrupt; extends beyond end of the section of CU\n"));
                                        munmap(fileData, fileSize);
                                        return -1;
                                }

                                const auto *tags = p;

                                // Skip to the end of this compilation unit
                                start += cuh.unit_length + initialLengthSize;

                                if (cuh.version != 2 && cuh.version != 3 && cuh.version != 4)
                                {
                                        logError(_S("Unsupported CU version\n"));
                                        munmap(fileData, fileSize);
                                        return -1;
                                }

                                // Process abbreviations used by this compilation unit.
                                // In theory, the same abbrevations seciton may be used by multiple C/Us, but haven't seen that here in practice
                                // Dwarf3 7.5.3
                                range64_t range(debugAbbrev.offset + cuh.debug_abbrev_offset, debugAbbrev.len - cuh.debug_abbrev_offset);
                                const abbrev_entry *dict[256] = {nullptr};
                                abbrev_attr local[200];
                                uint8_t localCnt{0};

                                for (const auto *it = fileDataU8 + range.offset, *const e = it + range.len; it != e;)
                                {
                                        const auto entry = parseLEB128(it);

                                        if (!entry)
                                                break;

                                        auto ent = localAllocator.New<abbrev_entry>();

                                        ent->tag = parseLEB128(it);
                                        ent->children = *it++;
                                        ent->allAttrs = nullptr;
                                        ent->attrsCnt = 0;
                                        ent->entry = entry;

                                        localCnt = 0;
                                        for (;;)
                                        {
                                                uint64_t attr = parseLEB128(it);
                                                const auto form = parseLEB128(it);

                                                if (!attr)
                                                        break;

                                                assert(localCnt != sizeof_array(local));
                                                assert(attr <= UINT16_MAX);
                                                assert(form <= UINT16_MAX);
                                                local[localCnt++] = {uint16_t(attr), uint16_t(form)};
                                        }

                                        const auto idx = entry & (sizeof_array(dict) - 1);

                                        ent->next = dict[idx];
                                        ent->attrsCnt = localCnt;
                                        if (localCnt)
                                                ent->allAttrs = localAllocator.CopyOf(local, localCnt);

                                        dict[idx] = ent;
                                }

                                // Nesting level
                                // We can rely on that to maintain a stack of in-scope functions and inline functions, and use that to identify the caller of a function
                                // e.g use funcinfo *nestedFuncs[128];
                                // nestedFuncs[level] = nullptr;
                                int32_t level{1};
                                parse_attrvalue_ctx valueParserCtx{fileDataU8, debugStr, cuh.version, offsetSize, cuh.address_size, dict, sizeof_array(dict), declsBase};

                                // Now that we have the abbrevations, scan all entries upto the end of this compilation unit
                                while (tags != start)
                                {
                                        // Dwarf3 : 7.5.2
                                        const auto abbrevNumber = parseLEB128(tags);

                                        if (!abbrevNumber)
                                        {
                                                --level;
                                                continue;
                                        }

                                        const abbrev_entry *ent;
                                        uint64_t lowPC{0}, hiPC{0};
                                        bool hiPCIsRelative{false};
                                        attr_value atValue;
                                        function *func{nullptr};

                                        for (ent = dict[abbrevNumber & (sizeof_array(dict) - 1)]; ent && ent->entry != abbrevNumber; ent = ent->next)
                                                continue;

                                        if (unlikely(!ent))
                                        {
                                                char msg[256];

                                                logError(msg, snprintf(msg, sizeof(msg), "Unknown abbreviation entry %u in CU %u\n", uint32_t(abbrevNumber), uint32_t(unit)));
                                                munmap(fileData, fileSize);
                                                return -1;
                                        }

                                        switch (ent->tag)
                                        {
                                                case DW_TAG_inlined_subroutine:
#if 0
							for (int32_t i = level - 1; i >= 1; --i)
							{
								if (nestedFuncs[i])
								{
									thisFunc->caller = nestedFuncs[i];
									break;
								}
							}
#endif
                                                case DW_TAG_subprogram:
                                                case DW_TAG_entry_point:
                                                        func = &_function;

                                                        func->name = nullptr;
                                                        func->nestingLevel = level;
                                                        func->declLine = 0;
                                                        func->range.Unset();

                                                        // nestedFucns[level] = func;
                                                        break;

                                                default:
                                                        // no inline function in scope at this nesting level
                                                        // nestedFuncs[level] = nullptr;
                                                        break;
                                        }

                                        uint64_t baseRangeAddr{0};
                                        for (auto it : Switch::make_range(ent->allAttrs, ent->attrsCnt))
                                        {
                                                // TODO: only bother with DW_FORM_indirect
                                                // iff we are going to need that value
                                                if (!parseAttrValue(&valueParserCtx, it->form, tags, &atValue))
                                                {
                                                        munmap(fileData, fileSize);
                                                        return -1;
                                                }

                                                if (func)
                                                {
                                                        switch (it->name)
                                                        {
                                                                case DW_AT_call_file:
                                                                case DW_AT_call_line:
                                                                        // If a function is inlined (DW_TAG_inlined_subroutine), it may have two additional attributes
                                                                        // DW_AT_call_file and DW_AT_call_line, which specify the source code location where that
                                                                        // function was inlined
                                                                        break;

                                                                case DW_AT_name:
                                                                        if (!func->name)
                                                                                func->name = atValue.str;
                                                                        break;

                                                                case DW_AT_abstract_origin:
                                                                case DW_AT_specification:
                                                                        func->name = locateAbstractInstanceName(&valueParserCtx, it->form, atValue.val);
                                                                        if (unlikely(func->name == (char *)UINTPTR_MAX))
                                                                        {
                                                                                munmap(fileData, fileSize);
                                                                                logError(_S("locateAbstractInstanceName() error\n"));
                                                                                return -1;
                                                                        }
                                                                        break;

                                                                case DW_AT_linkage_name:
                                                                case DW_AT_MIPS_linkage_name:
                                                                        if (atValue.str)
                                                                                func->name = atValue.str;
                                                                        break;

                                                                case DW_AT_low_pc:
                                                                        lowPC = atValue.val;
                                                                        if (ent->tag == DW_TAG_compile_unit)
                                                                        {
                                                                                // This is the base address to use when reading location lists or range lists
                                                                                baseRangeAddr = lowPC;
                                                                        }
                                                                        break;

                                                                case DW_AT_high_pc:
                                                                        hiPC = atValue.val;
                                                                        hiPCIsRelative = it->form != DW_FORM_addr;
                                                                        break;

                                                                case DW_AT_decl_line:
                                                                        func->declLine = atValue.val;
                                                                        break;

                                                                case DW_AT_ranges:
                                                                        // We need to find the function that has the smallest range that contains an address, to properly handle inline functions
                                                                        // for inline functions, the same ranges may match the callee and the inline function
                                                                        // so ideally we need to do something about it
                                                                        {
                                                                                range64_t range;
                                                                                uint64_t hi, lo;

                                                                                for (const auto *p = fileDataU8 + debugRanges.offset + atValue.val, *const e = fileDataU8 + debugRanges.End(); p != e;)
                                                                                {
                                                                                        switch (cuh.address_size)
                                                                                        {
                                                                                                case sizeof(uint64_t):
                                                                                                        lo = *(uint64_t *)p;
                                                                                                        p += sizeof(uint64_t);
                                                                                                        hi = *(uint64_t *)p;
                                                                                                        p += sizeof(uint64_t);
                                                                                                        break;

                                                                                                case sizeof(uint32_t):
                                                                                                        lo = *(uint32_t *)p;
                                                                                                        p += sizeof(uint32_t);
                                                                                                        hi = *(uint32_t *)p;
                                                                                                        p += sizeof(uint32_t);
                                                                                                        break;
                                                                                        }

                                                                                        if (!lo && !hi)
                                                                                                break;

                                                                                        range.len = hi - lo;
                                                                                        range.offset = lo + baseRangeAddr;

                                                                                        for (uint32_t i{0}; i != dsoFramesCnt; ++i)
                                                                                        {
                                                                                                const auto q = dsoFrames[i];

                                                                                                if (range.Contains(q))
                                                                                                {

                                                                                                        func->frameIdx = i;
                                                                                                        func->range = range;
                                                                                                        func->funcType = ent->tag == DW_TAG_inlined_subroutine ? FuncType::Inline
                                                                                                                                                               : ent->tag == DW_TAG_subprogram
                                                                                                                                                                     ? FuncType::Func
                                                                                                                                                                     : FuncType::Entry;

                                                                                                        assert(unit < (sizeof(compilationUnitsMap) * sizeof(uint8_t)));
                                                                                                        SwitchBitOps::Bitmap<uint64_t>::Set(compilationUnitsMap, unit);

                                                                                                        if (likely(matchedFunctionsCnt != sizeof_array(matchedFunctions)))
                                                                                                                matchedFunctions[matchedFunctionsCnt++] = _function;
                                                                                                }
                                                                                        }
                                                                                }
                                                                        }
                                                                        break;
                                                        }
                                                }
                                                else if (ent->tag == DW_TAG_compile_unit)
                                                {
                                                        if (it->name == DW_AT_name)
                                                        {

                                                        }
                                                        else if (it->name == DW_AT_ranges)
                                                        {
                                                                // This is great -- we can quickly check the ranges and if none of the addresses we are interestred in
                                                                // is contained in those ranges, we can skip this CU
                                                                range64_t range;
                                                                uint64_t hi, lo;
                                                                bool anyMatched{false};

                                                                for (const auto *p = fileDataU8 + debugRanges.offset + atValue.val, *const e = fileDataU8 + debugRanges.End(); p != e;)
                                                                {
                                                                        switch (cuh.address_size)
                                                                        {
                                                                                case sizeof(uint64_t):
                                                                                        lo = *(uint64_t *)p;
                                                                                        p += sizeof(uint64_t);
                                                                                        hi = *(uint64_t *)p;
                                                                                        p += sizeof(uint64_t);
                                                                                        break;

                                                                                case sizeof(uint32_t):
                                                                                        lo = *(uint32_t *)p;
                                                                                        p += sizeof(uint32_t);
                                                                                        hi = *(uint32_t *)p;
                                                                                        p += sizeof(uint32_t);
                                                                                        break;
                                                                        }

                                                                        if (!lo && !hi)
                                                                                break;

                                                                        const range64_t range(lo, (hi - lo) + 1); // inclusive
                                                                        uint32_t i;

                                                                        for (i = 0; i != dsoFramesCnt; ++i)
                                                                        {
                                                                                const auto q = dsoFrames[i];

                                                                                if (range.Contains(q))
                                                                                {

                                                                                        anyMatched = true;
                                                                                        break;
                                                                                }
                                                                        }

                                                                        if (anyMatched)
                                                                                break;
                                                                }

                                                                if (!anyMatched)
                                                                {
                                                                        // Great! we can skip this CU completely

                                                                        goto nextCU;
                                                                }
                                                        }
                                                }
                                        }

                                        if (func && hiPC && func->name && !func->range) // if already matched don't bother
                                        {
                                                if (hiPCIsRelative)
                                                        hiPC += lowPC;

                                                const range64_t range(lowPC, (hiPC - lowPC) + 1); // inclusive

                                                for (uint32_t i{0}; i != dsoFramesCnt; ++i)
                                                {
                                                        const auto q = dsoFrames[i];

                                                        if (range.Contains(q))
                                                        {

                                                                func->frameIdx = i;
                                                                func->range = range;
                                                                func->funcType = ent->tag == DW_TAG_inlined_subroutine ? FuncType::Inline
                                                                                                                       : ent->tag == DW_TAG_subprogram
                                                                                                                             ? FuncType::Func
                                                                                                                             : FuncType::Entry;

                                                                assert(unit < (sizeof(compilationUnitsMap) * sizeof(uint8_t)));
                                                                SwitchBitOps::Bitmap<uint64_t>::Set(compilationUnitsMap, unit);

                                                                if (likely(matchedFunctionsCnt != sizeof_array(matchedFunctions)))
                                                                        matchedFunctions[matchedFunctionsCnt++] = _function;
                                                        }
                                                }
                                        }

                                        if (ent->children)
                                        {
                                                ++level;

                                                // nestedFuncs[level] = nullptr;
                                        }
                                }

                        nextCU:;
                        }
                }

                std::sort(matchedFunctions, matchedFunctions + matchedFunctionsCnt, [](const auto &a, const auto &b)
                          {
                                  return a.frameIdx < b.frameIdx || (a.frameIdx == b.frameIdx && b.nestingLevel < a.nestingLevel);
                          });

                for (uint32_t i{0}; i != matchedFunctionsCnt; ++i)
                {
                        auto f = matchedFunctions + i;

                        f->best = UINT64_MAX;
                        f->line = 0;
                        f->file = 0;
                        f->filesList = nullptr;
                        f->dirsList = nullptr;
                }


                // TODO: There appears to be no way to match an inlined function's VMA to a line number
                // In some cases, same VMA is associated with multiple functions (i.e caller and inline functions called, etc)
                // and objdump verified that indeed lines within the inline function are missing from .debug_lineinfo
                // so there is clearly no way around it -- but maybe we can come up with something else in the future - maybe look into gdb impl. for ideas
                // At least we can identify the file and the function for now, and if the frame.funcType == FuncType::Inline we can
                // know that we can't trust the line number

                if (debugLine)
                {
                        // Dwarf3: 6.2.4
                        struct LineNumberProgramHeader
                        {
                                uint64_t unit_length;
                                uint16_t version;
                                uint64_t header_length;
                                uint8_t minimum_instruction_length;
                                bool default_is_stmt;
                                int8_t line_base;
                                uint8_t line_range;
                                uint8_t opcode_base;
                        };

                        // Line number opcodes
                        enum dwarf_line_number_ops
                        {
                                DW_LNS_extended_op = 0,
                                DW_LNS_copy = 1,
                                DW_LNS_advance_pc = 2,
                                DW_LNS_advance_line = 3,
                                DW_LNS_set_file = 4,
                                DW_LNS_set_column = 5,
                                DW_LNS_negate_stmt = 6,
                                DW_LNS_set_basic_block = 7,
                                DW_LNS_const_add_pc = 8,
                                DW_LNS_fixed_advance_pc = 9,
                                // DWARF 3.
                                DW_LNS_set_prologue_end = 10,
                                DW_LNS_set_epilogue_begin = 11,
                                DW_LNS_set_isa = 12
                        };

                        // Line number extended opcodes
                        enum dwarf_line_number_x_ops
                        {
                                DW_LNE_end_sequence = 1,
                                DW_LNE_set_address = 2,
                                DW_LNE_define_file = 3,
                                DW_LNE_set_discriminator = 0x04,
                                // HP extensions
                                DW_LNE_HP_negate_is_UV_update = 0x11,
                                DW_LNE_HP_push_context = 0x12,
                                DW_LNE_HP_pop_context = 0x13,
                                DW_LNE_HP_set_file_line_column = 0x14,
                                DW_LNE_HP_set_routine_name = 0x15,
                                DW_LNE_HP_set_sequence = 0x16,
                                DW_LNE_HP_negate_post_semantics = 0x17,
                                DW_LNE_HP_negate_function_exit = 0x18,
                                DW_LNE_HP_negate_front_end_logical = 0x19,
                                DW_LNE_HP_define_proc = 0x20
                        };

                        struct FSM
                        {
                                // Dwarf 6.2.2
                                // the PC corresponding to a machine instruction, geerated by the compiler
                                uintptr_t address;
                                // indicates the identify of the source fiel corresponding to a machine instruction
                                uint32_t file;
                                // Lines numbered at 1 -- the compiler may emit value 0 in cases where an instruction cannot be attributed to any source line
                                uint32_t line;
                                // columns are numbered beginning at 1.
                                // value 0s is reserved to indicate that a statement begins at the "left edge" of the line
                                uint32_t column;
                                // A boolean indicating that the current instruction is a recommended breakpoint location. A recommended breakpoint location is intended to "represent" a line, a statement and/or a semantically distinct subpart of a statement.
                                bool is_stmt;
                                // If set, indsicates that the current instruction is the beginning of a block
                                bool basic_block;
                                // A boolean indicating that the current address is that of the first byte after the end of a sequence of target machine instructions.
                                bool end_sequence;
                                // A boolean indicating that the current address is one (of possibly many) where execution should be suspended for an entry breakpoint of a function.
                                bool prologue_end;
                                // A boolean indicating that the current address is one (of possibly many) where execution should be suspended for an exit breakpoint of a function.
                                bool epilogue_begin;
                                // This value encodes the applicable instruction set for the current instr.
                                // The encoding of instruction sets should be shared by all users of a given arch.
                                uint64_t isa;

                                uint32_t regFiles{0};
                                uint32_t discriminator;

                                void reset(const bool isStatement)
                                {
                                        // Dwarf 6.2.1
                                        address = 0;
                                        file = 1; // base 1
                                        line = 1;
                                        column = 0;
                                        is_stmt = isStatement; // determined by default_is_stmt in the line number program header
                                        basic_block = false;
                                        end_sequence = false;
                                        prologue_end = false;
                                        epilogue_begin = false;
                                        isa = 0;

                                        discriminator = 0;
                                }
                        } fsm;

                        const auto base = fileDataU8 + debugLine.offset;
                        size_t unit{0};
                        LineNumberProgramHeader programHeader;

                        for (const auto *data = base, *const end = data + debugLine.len; data != end; ++unit)
                        {
                                // Parse the Line Number Program hader
                                // Dwarf3 6.2.3
                                const auto *hdr = data;
                                uint8_t offsetSize, initialLenSize;

                                programHeader.unit_length = *(uint32_t *)hdr;

                                hdr += sizeof(uint32_t);
                                if (programHeader.unit_length == 0xffffffff)
                                {
                                        programHeader.unit_length = *(uint64_t *)hdr;
                                        hdr += sizeof(uint64_t);
                                        offsetSize = sizeof(uint64_t);
                                        initialLenSize = sizeof(uint32_t) + sizeof(uint64_t);
                                }
                                else
                                {
                                        offsetSize = sizeof(uint32_t);
                                        initialLenSize = sizeof(uint32_t);
                                }

                                if (!SwitchBitOps::Bitmap<uint64_t>::IsSet(compilationUnitsMap, unit))
                                {
                                        // We can safely ignore it -- no functions were matched in this here CU

                                        data += programHeader.unit_length + initialLenSize;
                                        continue;
                                }

                                programHeader.version = *(uint16_t *)hdr;
                                hdr += sizeof(uint16_t);

                                if (offsetSize == sizeof(uint64_t))
                                {
                                        programHeader.header_length = *(uint64_t *)hdr; // header_length
                                        hdr += sizeof(uint64_t);
                                }
                                else
                                {
                                        programHeader.header_length = *(uint32_t *)hdr;
                                        hdr += sizeof(uint32_t);
                                }

                                programHeader.minimum_instruction_length = *hdr++;
                                programHeader.default_is_stmt = *(bool *)hdr++;
                                programHeader.line_base = *hdr++;
                                programHeader.line_range = *hdr++;
                                programHeader.opcode_base = *hdr++;

                                strwlen32_t name;
                                const auto eofCompilationUnitChunk = data + programHeader.unit_length + initialLenSize;
                                const auto standard_opcode_lengths = hdr;
                                dir_desc *dirTail{nullptr}, *dirHead{nullptr};
                                file_desc *fileTail{nullptr}, *fileHead{nullptr};

                                // Skip past std opcodes lengths
                                data = standard_opcode_lengths + programHeader.opcode_base - 1;

                                fsm.reset(programHeader.default_is_stmt);

                                // Directories table(sequence of path names): include_directories
                                while (*data)
                                {
                                        auto desc = localAllocator.New<dir_desc>();

                                        for (name.p = (char *)data++; *data; ++data)
                                                continue;

                                        name.SetEnd((char *)data++);

                                        desc->name = name;
                                        desc->next = nullptr;
                                        if (dirHead)
                                                dirHead->next = desc;
                                        else
                                                dirTail = desc;
                                        dirHead = desc;
                                }
                                ++data; // skip table term.

#if 0	
				uint32_t interestingFiles[16];
				uint8_t interestingFilesCnt{0};
#endif

                                // Files table (sequence of file entries): file_names
                                while (*data)
                                {
                                        auto desc = localAllocator.New<file_desc>();

                                        for (name.p = (char *)data++; *data; ++data)
                                                continue;

                                        name.SetEnd((char *)data++);

#if 0
					if (name.Eq(_S("switch_stacktraces.cpp")))
						interestingFiles[interestingFilesCnt++] = fsm.regFiles + 1;
#endif

                                        const auto dir = parseLEB128(data);
                                        const auto time = parseLEB128(data); // implemented-defined time of last modification of the file
                                        const auto size = parseLEB128(data); // length of the file in bytes

                                        (void)time;
                                        (void)size;

                                        desc->name = name;
                                        desc->dirIdx = dir;
                                        desc->next = nullptr;
                                        if (fileHead)
                                                fileHead->next = desc;
                                        else
                                                fileTail = desc;
                                        fileHead = desc;
                                        ++fsm.regFiles;
                                }
                                ++data; // skip table term.

                                uint64_t uladv;
                                int64_t adv;

                                // The Line Number Program
                                while (data != eofCompilationUnitChunk)
                                {
                                        const auto opCode = *data++;

                                        if (opCode >= programHeader.opcode_base)
                                        {
                                                const auto adjusted_opcode = opCode - programHeader.opcode_base;
                                                const auto address_increment = (adjusted_opcode / programHeader.line_range) * programHeader.minimum_instruction_length;
                                                const auto line_increment = programHeader.line_base + (adjusted_opcode % programHeader.line_range);

                                                fsm.address += address_increment;
                                                fsm.line += line_increment;


                                                fsm.basic_block = false;
                                                fsm.prologue_end = false;
                                                fsm.epilogue_begin = false;
                                                fsm.discriminator = 0;
                                        }
                                        else
                                        {
                                                switch (opCode)
                                                {
                                                        case DW_LNS_copy:
                                                                fsm.discriminator = 0;
                                                                fsm.basic_block = false;
                                                                fsm.prologue_end = false;
                                                                fsm.epilogue_begin = false;

                                                                break;

                                                        case DW_LNS_advance_pc:
                                                                uladv = parseLEB128(data) * programHeader.minimum_instruction_length;
                                                                fsm.address += uladv;
                                                                break;

                                                        case DW_LNS_advance_line:
                                                                adv = parseSignedLEB128(data);
                                                                fsm.line += adv;
                                                                break;

                                                        case DW_LNS_set_file:
                                                                fsm.file = parseLEB128(data);
                                                                break;

                                                        case DW_LNS_set_column:
                                                                fsm.column = parseLEB128(data);
                                                                break;

                                                        case DW_LNS_negate_stmt:
                                                                fsm.is_stmt = !fsm.is_stmt;
                                                                break;

                                                        case DW_LNS_set_basic_block:
                                                                fsm.basic_block = true;
                                                                break;

                                                        case DW_LNS_const_add_pc:
                                                                uladv = (((255 - programHeader.opcode_base) / programHeader.line_range) * programHeader.minimum_instruction_length);
                                                                fsm.address += uladv;
                                                                break;

                                                        case DW_LNS_fixed_advance_pc:
                                                                uladv = *(uint16_t *)data;
                                                                data += sizeof(uint16_t);
                                                                fsm.address += uladv;
                                                                break;

                                                        case DW_LNS_set_prologue_end:
                                                                // When a breakpoint is set on entry to a function, it is generally desirable for execution to be suspended, not on
                                                                // the very first instruction of the function, but rather
                                                                // at a point after the function's frame has been set up, after any language defined local declaration processing
                                                                // has been completed, and before execution of the first statement of the function begins.
                                                                // Debuggers generally cannot properly determine where this point is. This command allows a compiler to communicate the location(s) to use.
                                                                fsm.prologue_end = true;
                                                                break;

                                                        case DW_LNS_set_epilogue_begin:
                                                                // When a breakpoint is set on the exit of a function or execution steps over the last executable statement of a function,
                                                                // it is generally desirable to suspend
                                                                // execution after completion of the last statement but prior to tearing down the frame
                                                                // (so that local variables can still be examined). Debuggers generally cannot properly determine where
                                                                // this point is. This command allows a compiler to communicate the location(s) to use.
                                                                fsm.epilogue_begin = true;
                                                                break;

                                                        case DW_LNS_set_isa:
                                                                // Encodes the app-ISA arch for the current instr.
                                                                // This should be shared by all users of a given arch.
                                                                fsm.isa = parseLEB128(data);
                                                                break;

                                                        case DW_LNS_extended_op:
                                                        {
                                                                const auto *const ckpt = data;
                                                                auto len = parseLEB128(data);
                                                                const auto sizeofLen = data - ckpt;

                                                                len += sizeofLen;

                                                                const auto opCode = *data++;

                                                                switch (opCode)
                                                                {
                                                                        case DW_LNE_end_sequence:
                                                                                // Sets the endSeq register of the state machine to true
                                                                                // and appends a row to the matrix using the current values of the state machine regs.
                                                                                // Then it resets the regs to the initial values
                                                                                // specified above.
                                                                                // Every line number program sequence must end with a DW_LNE_end_sequence instruction which creates a row whose address
                                                                                // is that of the byte after the last target machine instruction of the sequence.

                                                                                fsm.end_sequence = true;
                                                                                fsm.reset(programHeader.default_is_stmt);
                                                                                break;

                                                                        case DW_LNE_set_address:
                                                                        {
                                                                                // Takes a single relocatable address as an operand
                                                                                uint64_t addr;

                                                                                if (len - sizeofLen - 1 == sizeof(uint64_t))
                                                                                {
                                                                                        addr = *(uint64_t *)data;
                                                                                        data += sizeof(uint64_t);
                                                                                }
                                                                                else
                                                                                {
                                                                                        addr = *(uint32_t *)data;
                                                                                        data += sizeof(uint32_t);
                                                                                }

                                                                                fsm.address = addr;

                                                                        }
                                                                        break;

                                                                        case DW_LNE_define_file:
                                                                        {
                                                                                // The files are numbered, starting at base 1, an dthe order in which htey appear, the names in the header come
                                                                                // before names defined by LW_LNE_define_file instructions.
                                                                                auto desc = localAllocator.New<file_desc>();

                                                                                for (name.p = (char *)data++; *data; ++data)
                                                                                        continue;

                                                                                name.SetEnd((char *)data++);

                                                                                const auto dir = parseLEB128(data);
                                                                                const auto time = parseLEB128(data);
                                                                                const auto size = parseLEB128(data);

                                                                                (void)time;
                                                                                (void)size;

                                                                                desc->name = name;
                                                                                desc->dirIdx = dir;
                                                                                desc->next = nullptr;
                                                                                if (fileHead)
                                                                                        fileHead->next = desc;
                                                                                else
                                                                                        fileTail = desc;
                                                                                fileHead = desc;
                                                                                ++fsm.regFiles;
                                                                        }
                                                                        break;

                                                                        case DW_LNE_set_discriminator:
                                                                        {
                                                                                // Identifies the block to which the current
                                                                                // instruction belongs.
                                                                                // They are assigned arbitrary bh the DWARF producer and serve to distinguish among multiple blocks
                                                                                // that may all be associated with the same source file, line, and column
                                                                                // Where only one block exists for a given source position, the discriminator value should be 0.
                                                                                fsm.discriminator = parseLEB128(data);
                                                                        }
                                                                        break;

                                                                        // HP extensions
                                                                        case DW_LNE_HP_negate_is_UV_update:
                                                                                break;
                                                                        case DW_LNE_HP_push_context:
                                                                                break;
                                                                        case DW_LNE_HP_pop_context:
                                                                                break;
                                                                        case DW_LNE_HP_set_file_line_column:
                                                                                break;
                                                                        case DW_LNE_HP_set_routine_name:
                                                                                break;
                                                                        case DW_LNE_HP_set_sequence:
                                                                                break;
                                                                        case DW_LNE_HP_negate_post_semantics:
                                                                                break;
                                                                        case DW_LNE_HP_negate_function_exit:
                                                                                break;
                                                                        case DW_LNE_HP_negate_front_end_logical:
                                                                                break;
                                                                        case DW_LNE_HP_define_proc:
                                                                                break;

                                                                        default:
                                                                                exit(1);
                                                                                break;
                                                                }
                                                                break;
                                                        }
                                                        break;

                                                        default:
                                                                break;
                                                }
                                        }

#if 0
                                        uint32_t it;

					for (it = 0; it != interestingFilesCnt && interestingFiles[it] != fsm.file; ++it)
						continue;
					if (it != interestingFilesCnt)
	                                        SLog("LINE:", fsm.line, ", ", fsm.column, "\n");
#endif

#if 0
					if (fsm.line == 2385)
					{
                                                if (auto fdIdx = fsm.file)
                                                {
                                                        auto it = fileTail;

                                                        while (--fdIdx)
                                                                it = it->next;

							Print("LINE ", fsm.line, " ", it->name, "\n");
						}
					}
#endif

                                        if (fsm.is_stmt && likely(fsm.address))
                                        {
                                                // This may not be the optimal way to do this, but it works
                                                // TODO: reconsider

                                                for (auto f : Switch::make_range(matchedFunctions, matchedFunctionsCnt))
                                                {
                                                        if (f->range.Contains(fsm.address))
                                                        {
                                                                const auto queryPC = dsoFrames[f->frameIdx];

                                                                if (fsm.address < queryPC)
                                                                {
                                                                        const auto delta = queryPC >= fsm.address ? queryPC - fsm.address : fsm.address - queryPC;

                                                                        if (delta <= f->best)
                                                                        {
                                                                                f->best = delta;
                                                                                f->file = fsm.file;
                                                                                f->line = fsm.line;
                                                                                f->filesList = fileTail;
                                                                                f->dirsList = dirTail;
                                                                        }
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                }

                // Generate frames out of all collected and processed module frames
                for (uint32_t i{0}; i != dsoFramesCnt && frameIdx != maxFrames; ++i)
                {
                        bool any{false};

                        for (const auto f : Switch::make_range(matchedFunctions, matchedFunctionsCnt))
                        {
                                if (f->frameIdx == i)
                                {
                                        auto frame = frames + frameIdx++;

                                        frame->funcName.Unset();
                                        frame->declLine = f->declLine;

                                        // if we don't have frame->funcName, we can try to resolve it
                                        // see dladdr() impl: https://github.com/lattera/glibc/blob/a2f34833b1042d5d8eeb263b4cf4caaea138c4ad/elf/dl-addr.c
                                        // we 'll just need to iterate dos's sections looking for e.g PT_DYNAMIC and do what we need to do
                                        // We don't currently need that though

                                        if (f->best != UINT64_MAX)
                                        {
                                                // c->file and c->dir is base(1)
                                                strwlen32_t fileName, dirName;

                                                if (auto fdIdx = f->file)
                                                {
                                                        auto it = f->filesList;

                                                        while (--fdIdx)
                                                                it = it->next;

                                                        fileName = it->name;

                                                        if (auto dirIdx = it->dirIdx)
                                                        {
                                                                auto it = f->dirsList;

                                                                while (--dirIdx)
                                                                        it = it->next;

                                                                dirName = it->name;
                                                        }

                                                        auto p = (char *)allocator.Alloc(dirName.len + fileName.len + (dirName.len != 0));

                                                        frame->fileName.p = p;

                                                        memcpy(p, dirName.p, dirName.len);
                                                        p += dirName.len;
                                                        if (dirName)
                                                                *p++ = '/';
                                                        memcpy(p, fileName.p, fileName.len);
                                                        p += fileName.len;
                                                        frame->fileName.SetEnd(p);

                                                        if (f->name)
                                                        {
                                                                const auto len = strlen(f->name);
                                                                // may or may not be enough
                                                                size_t demangledLen = len * 3 + 128;
                                                                auto demangled = (char *)allocator.Alloc(demangledLen);
                                                                int status;

                                                                // TODO: https://github.com/phaistos-networks/Switch/issues/36
                                                                // XXX: we may not have a choice but roll out our own abi::__cxa_demangle() impl.
                                                                // it always allocates memory, based on log-malloc2 traces
                                                                // See: http://opensource.apple.com//source/libcppabi/libcppabi-14/src/cp-demangle.c
                                                                // We can't really do much about it - turns out, save from re-implemnting the whole thing ourselves
                                                                // and we probably have no choice here but to do, just that
                                                                if (const auto res = abi::__cxa_demangle(f->name, demangled, &demangledLen, &status))
                                                                {
                                                                        const auto finalLen = strlen(res);

                                                                        assert(res == demangled); // Make sure it was stored in provided output buf, otherwise it didn't have enough memory and it allocated
                                                                        frame->funcName.Set(demangled, finalLen);
                                                                }
                                                                else
                                                                        frame->funcName.Set(allocator.CopyOf(f->name, len), len);
                                                        }
                                                }

                                                frame->funcType = f->funcType;
                                                frame->line = f->line;
                                        }
                                        else
                                        {
                                                frame->line = 0;
                                                frame->funcType = FuncType::Unknown;

                                                if (dso->dlpi_name && *dso->dlpi_name)
                                                {
                                                        const auto filename = dso->dlpi_name;
                                                        const auto len = strlen(filename);

                                                        frame->fileName.Set(allocator.CopyOf(filename, len), len);
                                                }
                                                else
                                                        frame->fileName.Unset();
                                        }


                                        any = true;
                                        if (frameIdx == maxFrames)
                                        {
                                                munmap(fileData, fileSize);
                                                return frameIdx;
                                        }
                                }
                        }

                        if (!any)
                        {
                                auto frame = frames + frameIdx++;

                                frame->funcName.Unset();
                                frame->line = 0;
                                frame->funcType = FuncType::Unknown;

                                if (dso->dlpi_name && *dso->dlpi_name)
                                {
                                        const auto filename = dso->dlpi_name;
                                        const auto len = strlen(filename);

                                        frame->fileName.Set(allocator.CopyOf(filename, len), len);
                                }
                                else
                                        frame->fileName.Unset();


                                if (frameIdx == maxFrames)
                                {
                                        munmap(fileData, fileSize);
                                        return frameIdx;
                                }
                        }
                }

        	munmap(fileData, fileSize);
        }

        return frameIdx;
}

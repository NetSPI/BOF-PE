#ifndef PEPLUS_HEADERS_HPP_
#define PEPLUS_HEADERS_HPP_

#include <cstddef>
#include <cstdint>

namespace peplus {

using BYTE      = std::uint8_t;
using WORD      = std::uint16_t;
using DWORD     = std::uint32_t;
using QWORD     = std::uint64_t;

using UCHAR     = std::uint8_t;
using USHORT    = std::uint16_t;
using ULONG     = std::uint32_t;
using ULONGLONG = std::uint64_t;

template <unsigned int XX>
struct UIntPtr;

template <>
struct UIntPtr<32>
{
	using type = std::uint32_t;
};

template <>
struct UIntPtr<64>
{
	using type = std::uint64_t;
};

template <unsigned int XX>
using ULONG_PTR = typename UIntPtr<XX>::type;

using ULONG_PTR32 = ULONG_PTR<32>;
using ULONG_PTR64 = ULONG_PTR<64>;

template <unsigned int XX>
using DWORD_PTR = typename UIntPtr<XX>::type;

using DWORD_PTR32 = DWORD_PTR<32>;
using DWORD_PTR64 = DWORD_PTR<64>;

const WORD DOS_SIGNATURE = 0x5a4d;

struct DosHeader
{
	WORD  e_magic;
	WORD  e_cblp;
	WORD  e_cp;
	WORD  e_crlc;
	WORD  e_cparhdr;
	WORD  e_minalloc;
	WORD  e_maxalloc;
	WORD  e_ss;
	WORD  e_sp;
	WORD  e_csum;
	WORD  e_ip;
	WORD  e_cs;
	WORD  e_lfarlc;
	WORD  e_ovno;
	WORD  e_res[4];
	WORD  e_oemid;
	WORD  e_oeminfo;
	WORD  e_res2[10];
	DWORD e_lfanew;
};

enum FileMachine
{
	FILE_MACHINE_I386  = 0x014c,
	FILE_MACHINE_IA64  = 0x0200,
	FILE_MACHINE_AMD64 = 0x8664,
};

enum FileCharacteristics
{
	FILE_RELOCS_STRIPPED         = 0x0001,
	FILE_EXECUTABLE_IMAGE        = 0x0002,
	FILE_LINE_NUMS_STRIPPED      = 0x0004,
	FILE_LOCAL_SYMS_STRIPPED     = 0x0008,
	FILE_AGGRESSIVE_WS_TRIM      = 0x0010,
	FILE_LARGE_ADDRESS_AWARE     = 0x0020,
	FILE_BYTES_RESERVED_LO       = 0x0080,
	FILE_32BIT_MACHINE           = 0x0100,
	FILE_DEBUG_STRIPPED          = 0x0200,
	FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
	FILE_NET_RUN_FROM_SWAP       = 0x0800,
	FILE_SYSTEM                  = 0x1000,
	FILE_DLL                     = 0x2000,
	FILE_UP_SYSTEM_ONLY          = 0x4000,
	FILE_BYTES_REVERSED_HI       = 0x8000,
};

struct FileHeader
{
	WORD  machine;
	WORD  number_of_sections;
	DWORD time_date_stamp;
	DWORD pointer_to_symbol_table;
	DWORD number_of_symbols;
	WORD  size_of_optional_header;
	WORD  characteristics;
};

struct DataDirectory
{
	DWORD virtual_address;
	DWORD size;
};

const std::size_t NUMBEROF_DIRECTORY_ENTRIES = 16;

enum DirectoryEntryIndex : unsigned
{
	DIRECTORY_ENTRY_EXPORT        = 0,
	DIRECTORY_ENTRY_IMPORT        = 1,
	DIRECTORY_ENTRY_RESOURCE      = 2,
	DIRECTORY_ENTRY_EXCEPTION     = 3,
	DIRECTORY_ENTRY_SECURITY      = 4,
	DIRECTORY_ENTRY_BASERELOC     = 5,
	DIRECTORY_ENTRY_DEBUG         = 6,
	DIRECTORY_ENTRY_COPYRIGHT     = 7,
	DIRECTORY_ENTRY_ARCHITECTURE  = 7,
	DIRECTORY_ENTRY_GLOBALPTR     = 8,
	DIRECTORY_ENTRY_TLS           = 9,
	DIRECTORY_ENTRY_LOADCONFIG    = 10,
	DIRECTORY_ENTRY_BOUNDIMPORT   = 11,
	DIRECTORY_ENTRY_IAT           = 12,
	DIRECTORY_ENTRY_DELAYIMPORT   = 13,
	DIRECTORY_ENTRY_COMDESCRIPTOR = 14,
};

template <unsigned int XX>
struct OptionalHdrMagic;

template <>
struct OptionalHdrMagic<32>
{
	enum { value = 0x10b };
};

template <>
struct OptionalHdrMagic<64>
{
	enum { value = 0x20b };
};

template <unsigned int XX>
const WORD OPTIONAL_HDR_MAGIC = OptionalHdrMagic<XX>::value;

const WORD OPTIONAL_HDR32_MAGIC = OPTIONAL_HDR_MAGIC<32>;
const WORD OPTIONAL_HDR64_MAGIC = OPTIONAL_HDR_MAGIC<64>;

enum ImageSubsystem
{
	SUBSYSTEM_UNKNOWN                   = 0,
	SUBSYSTEM_NATIVE                    = 1,
	SUBSYSTEM_WINDOWS_GUI               = 2,
	SUBSYSTEM_WINDOWS_CUI               = 3,
	SUBSYSTEM_OS2_CUI                   = 5,
	SUBSYSTEM_POSIX_CUI                 = 7,
	SUBSYSTEM_WINDOWS_CE_GUI            = 9,
	SUBSYSTEM_EFI_APPLICATION           = 10,
	SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER   = 11,
	SUBSYSTEM_EFI_RUNTIME_DRIVER        = 12,
	SUBSYSTEM_EFI_ROM                   = 13,
	SUBSYSTEM_XBOX                      = 14,
	SUBSYSTEM_WINDOWS_BOOST_APPLICATION = 16,
};

enum DllCharacteristics
{
	DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040,
	DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080,
	DLLCHARACTERISTICS_NX_COMPAT             = 0x0100,
	DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200,
	DLLCHARACTERISTICS_NO_SEH                = 0x0400,
	DLLCHARACTERISTICS_NO_BIND               = 0x0800,
	DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000,
	DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
};

template <unsigned int>
struct OptionalHeader;

template <>
struct OptionalHeader<32>
{
	WORD          magic;
	BYTE          major_linker_version;
	BYTE          minor_linker_version;
	DWORD         size_of_code;
	DWORD         size_of_initialized_data;
	DWORD         size_of_uninitialized_data;
	DWORD         address_of_entry_point;
	DWORD         base_of_code;
	DWORD         base_of_data;
	DWORD         image_base;
	DWORD         section_alignment;
	DWORD         file_alignment;
	WORD          major_operating_system_version;
	WORD          minor_operating_system_version;
	WORD          major_image_version;
	WORD          minor_image_version;
	WORD          major_subsystem_version;
	WORD          minor_subsystem_version;
	DWORD         win32_version_value;
	DWORD         size_of_image;
	DWORD         size_of_headers;
	DWORD         check_sum;
	WORD          subsystem;
	WORD          dll_characteristics;
	DWORD         size_of_stack_reserve;
	DWORD         size_of_stack_commit;
	DWORD         size_of_heap_reserve;
	DWORD         size_of_heap_commit;
	DWORD         loader_flags;
	DWORD         number_of_rvas_and_sizes;
	DataDirectory data_directory[NUMBEROF_DIRECTORY_ENTRIES];
};

template <>
struct OptionalHeader<64>
{
	WORD          magic;
	BYTE          major_linker_version;
	BYTE          minor_linker_version;
	DWORD         size_of_code;
	DWORD         size_of_initialized_data;
	DWORD         size_of_uninitialized_data;
	DWORD         address_of_entry_point;
	DWORD         base_of_code;
	ULONGLONG     image_base;
	DWORD         section_alignment;
	DWORD         file_alignment;
	WORD          major_operating_system_version;
	WORD          minor_operating_system_version;
	WORD          major_image_version;
	WORD          minor_image_version;
	WORD          major_subsystem_version;
	WORD          minor_subsystem_version;
	DWORD         win32_version_value;
	DWORD         size_of_image;
	DWORD         size_of_headers;
	DWORD         check_sum;
	WORD          subsystem;
	WORD          dll_characteristics;
	ULONGLONG     size_of_stack_reserve;
	ULONGLONG     size_of_stack_commit;
	ULONGLONG     size_of_heap_reserve;
	ULONGLONG     size_of_heap_commit;
	DWORD         loader_flags;
	DWORD         number_of_rvas_and_sizes;
	DataDirectory data_directory[NUMBEROF_DIRECTORY_ENTRIES];
};

const DWORD NT_SIGNATURE = 0x4550;

template <unsigned int XX>
struct NtHeaders
{
	DWORD              signature;
	FileHeader         file_header;
	OptionalHeader<XX> optional_header;
};

const std::size_t SIZEOF_SHORT_NAME = 8;

enum SectionCharacteristics
{
	SCN_TYPE_NO_PAD            = 0x00000008,
	SCN_CNT_CODE               = 0x00000020,
	SCN_CNT_INITIALIZED_DATA   = 0x00000040,
	SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
	SCN_CNT_LNK_OTHER          = 0x00000100,
	SCN_LNK_INFO               = 0x00000200,
	SCN_LNK_REMOVE             = 0x00000800,
	SCN_LNK_COMDAT             = 0x00001000,
	SCN_NO_DEFER_SPEC_EXC      = 0x00004000,
	SCN_GPREL                  = 0x00008000,
	SCN_MEM_PURGEABLE          = 0x00020000,
	SCN_MEM_LOCKED             = 0x00040000,
	SCN_MEM_PRELOAD            = 0x00080000,
	SCN_ALIGN_1BYTES           = 0x00100000,
	SCN_ALIGN_2BYTES           = 0x00200000,
	SCN_ALIGN_4BYTES           = 0x00300000,
	SCN_ALIGN_8BYTES           = 0x00400000,
	SCN_ALIGN_16BYTES          = 0x00500000,
	SCN_ALIGN_32BYTES          = 0x00600000,
	SCN_ALIGN_64BYTES          = 0x00700000,
	SCN_ALIGN_128BYTES         = 0x00800000,
	SCN_ALIGN_256BYTES         = 0x00900000,
	SCN_ALIGN_512BYTES         = 0x00a00000,
	SCN_ALIGN_1024BYTES        = 0x00b00000,
	SCN_ALIGN_2048BYTES        = 0x00c00000,
	SCN_ALIGN_4096BYTES        = 0x00d00000,
	SCN_ALIGN_8192BYTES        = 0x00e00000,
	SCN_LNK_NRELOC_OVFL        = 0x01000000,
	SCN_MEM_DISCARDABLE        = 0x02000000,
	SCN_MEM_NOT_CACHED         = 0x04000000,
	SCN_MEM_NOT_PAGED          = 0x08000000,
	SCN_MEM_SHARED             = 0x10000000,
	SCN_MEM_EXECUTE            = 0x20000000,
	SCN_MEM_READ               = 0x40000000,
	SCN_MEM_WRITE              = 0x80000000,
};

struct SectionHeader
{
	BYTE      name[SIZEOF_SHORT_NAME];
	union {
		DWORD physical_address;
		DWORD virtual_size;
	};
	DWORD     virtual_address;
	DWORD     size_of_raw_data;
	DWORD     pointer_to_raw_data;
	DWORD     pointer_to_relocations;
	DWORD     pointer_to_line_numbers;
	WORD      number_of_relocations;
	WORD      number_of_line_numbers;
	DWORD     characteristics;
};

struct ExportDirectory
{
	DWORD characteristics;
	DWORD time_date_stamp;
	WORD  major_version;
	WORD  minor_version;
	DWORD name;
	DWORD base;
	DWORD number_of_functions;
	DWORD number_of_names;
	DWORD address_of_functions;
	DWORD address_of_names;
	DWORD address_of_name_ordinals;
};

struct ImportDescriptor
{
	union {
		DWORD characteristics;
		DWORD original_first_thunk;
	};
	DWORD     time_date_stamp;
	DWORD     forwarder_chain;
	DWORD     name;
	DWORD     first_thunk;
};

struct ResourceDirectoryEntry
{
	DWORD name;
	DWORD offset_to_data;
};

struct ResourceDirectory
{
	DWORD                  characteristics;
	DWORD                  time_date_stamp;
	WORD                   major_version;
	WORD                   minor_version;
	WORD                   number_of_named_entries;
	WORD                   number_of_id_entries;
	ResourceDirectoryEntry directory_entries[1];
};

struct ResourceDataEntry
{
	DWORD offset_to_data;
	DWORD size;
	DWORD code_page;
	DWORD reserved;
};

template <unsigned int XX>
const ULONG_PTR<XX> ORDINAL_FLAG = 1ull << (XX - 1);

const ULONG_PTR32 ORDINAL_FLAG32 = ORDINAL_FLAG<32>;
const ULONG_PTR64 ORDINAL_FLAG64 = ORDINAL_FLAG<64>;

template <unsigned int XX>
struct ThunkData
{
	union {
		ULONG_PTR<XX> forwarder_string;
		ULONG_PTR<XX> function;
		ULONG_PTR<XX> ordinal;
		ULONG_PTR<XX> address_of_data;
	};
};

struct ImportByName
{
	WORD hint;
	char name[1];
};

enum RelocationType
{
	REL_BASED_ABSOLUTE       = 0,
	REL_BASED_HIGH           = 1,
	REL_BASED_LOW            = 2,
	REL_BASED_HIGHLOW        = 3,
	REL_BASED_HIGHADJ        = 4,
	REL_BASED_MIPS_JMPADDR   = 5,
	REL_BASED_ARM_MOV32A     = 5,
	REL_BASED_ARM_MOV32      = 6,
	REL_BASED_REL            = 7,
	REL_BASED_ARM_MOV32T     = 7,
	REL_BASED_THUMB_MOV32    = 7,
	REL_BASED_MIPS_JMPADDR16 = 9,
	REL_BASED_IA64_IMM64     = 9,
	REL_BASED_DIR64          = 10,
	REL_BASED_HIGH3ADJ       = 11,

	REL_AMD64_ABSOLUTE       = 0,
	REL_AMD64_ADDR64         = 1,
	REL_AMD64_ADDR32         = 2,
	REL_AMD64_ADDR32NB       = 3,
	REL_AMD64_REL32          = 4,
	REL_AMD64_REL32_1        = 5,
	REL_AMD64_REL32_2        = 6,
	REL_AMD64_REL32_3        = 7,
	REL_AMD64_REL32_4        = 8,
	REL_AMD64_REL32_5        = 9,
	REL_AMD64_SECTION        = 10,
	REL_AMD64_SECREL         = 11,
	REL_AMD64_SECREL7        = 12,
	REL_AMD64_TOKEN          = 13,
	REL_AMD64_SREL32         = 14,
	REL_AMD64_PAIR           = 15,
	REL_AMD64_SSPAN32        = 16,

	REL_ARM_ABSOLUTE         = 0,
	REL_ARM_ADDR32           = 1,
	REL_ARM_ADDR32_NB        = 2,
	REL_ARM_BRANCH24         = 3,
	REL_ARM_BRANCH11         = 4,
	REL_ARM_SECTION          = 14,
	REL_ARM_SECREL           = 15,
	REL_ARM_MOV32            = 16,
	REL_THUMB_MOV32          = 17,
	REL_THUMB_BRANCH20       = 18,
	REL_THUMB_BRANCH24       = 20,
	REL_THUMB_BLX23          = 21,
	REL_ARM_PAIR             = 22,

	REL_ARM64_ABSOLUTE       = 0,
	REL_ARM64_ADDR32         = 1,
	REL_ARM64_ADDR32NB       = 2,
	REL_ARM64_BRANCH26       = 3,
	REL_ARM64_PAGEBASE_REL32 = 4,
	REL_ARM64_REL21          = 5,
	REL_ARM64_PAGEOFFSET_12A = 6,
	REL_ARM64_PAGEOFFSET_12L = 7,
	REL_ARM64_SECREL         = 8,
	REL_ARM64_SECREL_LOW12A  = 9,
	REL_ARM64_SECREL_HIGH12A = 10,
	REL_ARM64_SECREL_LOW12L  = 11,
	REL_ARM64_TOKEN          = 12,
	REL_ARM64_SECTION        = 13,
	REL_ARM64_ADDR64         = 14,
	REL_ARM64_BRANCH19       = 15,
	REL_ARM64_BRANCH14       = 16,

	REL_I386_ABSOLUTE        = 0,
	REL_I386_DIR16           = 1,
	REL_I386_REL16           = 2,
	REL_I386_DIR32           = 6,
	REL_I386_DIR32NB         = 7,
	REL_I386_SEG12           = 9,
	REl_I386_SECTION         = 10,
	REL_I386_SECREL          = 11,
	REL_I386_TOKEN           = 12,
	REL_I386_SECREL7         = 13,
	REL_I386_REL32           = 20,
};

struct BaseRelocation
{
	DWORD virtual_address;
	DWORD size_of_block;
	WORD  type_offset[1];
};

struct DebugDirectory
{
	DWORD characteristics;
	DWORD time_date_stamp;
	WORD  major_version;
	WORD  minor_version;
	DWORD type;
	DWORD size_of_data;
	DWORD address_of_raw_data;
	DWORD pointer_to_raw_data;
};

template <unsigned int XX>
struct TlsDirectory
{
	ULONG_PTR<XX> start_address_of_raw_data;
	ULONG_PTR<XX> end_address_of_raw_data;
	ULONG_PTR<XX> address_of_index;
	ULONG_PTR<XX> address_of_callbacks;
	DWORD         size_of_zero_fill;
	union {
		DWORD     characteristics;
		struct {
			DWORD reserved_0 : 20;
			DWORD alignment  : 4;
			DWORD reserved_1 : 8;
		};
	};
};

struct RuntimeFunction
{
	ULONG begin_address;
	ULONG end_address;
	ULONG unwind_data;
};

enum {
	UNW_FLAG_NHANDLER  = 0,
	UNW_FLAG_EHANDLER  = 1,
	UNW_FLAG_UHANDLER  = 2,
	UNW_FLAG_CHAININFO = 4,
};

enum {
	UWOP_PUSH_NONVOL,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_SAVE_XMM128,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME,
};

struct UnwindCode
{
	BYTE code_offset    ;
	BYTE unwind_op   : 4;
	BYTE op_info     : 4;
};

struct UnwindInfo
{
	BYTE       version        : 3;
	BYTE       flags          : 5;
	BYTE       size_of_prolog    ;
	BYTE       count_of_codes    ;
	BYTE       frame_register : 4;
	BYTE       frame_offset   : 4;
	UnwindCode unwind_code[1]    ;
};

struct ScopeTable
{
	ULONG count;
	struct {
		ULONG begin_address;
		ULONG end_address;
		ULONG handler_address;
		ULONG jump_target;
	} scope_record[1];
};

using NtHeaders32 = NtHeaders<32>;
using NtHeaders64 = NtHeaders<64>;

using ThunkData32 = ThunkData<32>;
using ThunkData64 = ThunkData<64>;

using TlsDirectory32 = TlsDirectory<32>;
using TlsDirectory64 = TlsDirectory<64>;

using OptionalHeader32 = OptionalHeader<32>;
using OptionalHeader64 = OptionalHeader<64>;

}

#endif
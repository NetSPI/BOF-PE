#ifndef PEPLUS_DETAIL_IMAGEBASE_HPP_
#define PEPLUS_DETAIL_IMAGEBASE_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_offset.hpp>
#include <peplus/detail/image_helpers.hpp>
#include <peplus/detail/facades/base_relocation_facade.hpp>
#include <peplus/detail/facades/export_directory_facade.hpp>
#include <peplus/detail/facades/import_descriptor_facade.hpp>
#include <peplus/detail/facades/resource_directory_facade.hpp>
#include <peplus/detail/facades/runtime_function_facade.hpp>
#include <peplus/detail/facades/tls_directory_facade.hpp>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <sstream>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/endian/conversion.hpp>

namespace peplus::detail {

enum class ImageType
{
	Unknown, Executable, Dynamic,
};

enum class ImageMachine
{
	Unknown, I386, IA64, AMD64,
};

template <unsigned int XX, class Offset, class MemoryBuffer>
class ImageBase
{
public:
	using offset_type = Offset;
	using buffer_type = typename MemoryBuffer::value_type;

	template <typename T>
	using Pointed = PointedValue<Offset, T>;

	using ExportInfo = typename ExportDirectoryFacade<ImageBase>::ExportInfo;
	using ImportEntry = typename ImportDescriptorFacade<XX, ImageBase>::ImportEntry;

	using SectionHeaderRange = EntryRange <
		ImageBase, read_pointed_value<read_section_header>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(SectionHeader)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>,
		std::size_t
	>;

	using ImportDescriptorRange = EntryRange <
		ImageBase, read_pointed_value<read_proxy_object<ImportDescriptorFacade<XX, ImageBase>>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(ImportDescriptor)>>,
		default_value_stop_iteration_policy<ImportDescriptor>
	>;

	using BaseRelocationRange = EntryRange <
		ImageBase, read_proxy_object<BaseRelocationFacade<ImageBase>>,
		base_relocation_advance_pointer_policy,
		fixed_distance_stop_iteration_policy<runtime_param<0>>,
		std::size_t
	>;

	using DebugDirectoryRange = EntryRange <
		ImageBase, read_pointed_value<read_debug_directory>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(DebugDirectory)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>,
		std::size_t
	>;

	using RuntimeFunctionRange = EntryRange <
		ImageBase, read_pointed_value<read_proxy_object<RuntimeFunctionFacade<ImageBase>>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(RuntimeFunction)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>,
		std::size_t
	>;

	static bool is_valid(const buffer_type & image_data);

	explicit ImageBase(buffer_type image_data);

	ImageType type() const;
	ImageMachine machine() const;
	VirtualOffset entry_point() const;

	Pointed<DosHeader> dos_header() const;
	Pointed<FileHeader> file_header() const;
	Pointed<NtHeaders<XX>> nt_headers() const;
	Pointed<OptionalHeader<XX>> optional_header() const;

	SectionHeaderRange section_headers() const;
	BaseRelocationRange base_relocations() const;
	DebugDirectoryRange debug_directories() const;
	RuntimeFunctionRange exception_entries() const;
	ImportDescriptorRange import_descriptors() const;

	std::optional<Pointed<std::string>> copyright_str() const;

	std::optional<ResourceDirectoryFacade<ImageBase>> resource_directory() const;
	std::optional<Pointed<TlsDirectoryFacade<XX, ImageBase>>> tls_directory() const;
	std::optional<Pointed<ExportDirectoryFacade<ImageBase>>> export_directory() const;

	std::optional<FileOffset> to_file_offset(VirtualOffset rva) const;
	std::optional<VirtualOffset> to_virtual_offset(FileOffset offs) const;

	std::optional<Pointed<DataDirectory>> data_directory(DirectoryEntryIndex index) const;

	template <class CharT = char, class DataOffset>
	Pointed<std::basic_string<CharT>> read_string(DataOffset offset) const;

	template <class CharT = char, class DataOffset>
	Pointed<std::basic_string<CharT>> read_string(DataOffset offset, std::size_t length) const;

	template <class DataOffset>
	std::pair<std::size_t, Offset> read(DataOffset offset, std::size_t size, void * into_buffer) const;

private:
	void do_read_from_buffer(std::size_t offset, std::size_t size, void * into_buffer) const;

	buffer_type _image_data;
};

template <unsigned int XX, class Offset, class MemoryBuffer>
bool ImageBase<XX, Offset, MemoryBuffer>::is_valid(const buffer_type & image_data)
{
	DosHeader dos_header;
	std::size_t bytes_read = MemoryBuffer::read(image_data, 0, sizeof(DosHeader),
	                                            &dos_header);
	if (bytes_read < sizeof(DosHeader)) return false;

	boost::endian::little_to_native_inplace(dos_header.e_magic);
	if (dos_header.e_magic != DOS_SIGNATURE) return false;

	NtHeaders<XX> nt_headers;
	boost::endian::little_to_native_inplace(dos_header.e_lfanew);
	bytes_read = MemoryBuffer::read(image_data, dos_header.e_lfanew,
	                                sizeof(NtHeaders<XX>), &nt_headers);
	if (bytes_read < sizeof(NtHeaders<XX>)) return false;

	boost::endian::little_to_native_inplace(nt_headers.signature);
	if (nt_headers.signature != NT_SIGNATURE) return false;

	boost::endian::little_to_native_inplace(nt_headers.optional_header.magic);
	if (nt_headers.optional_header.magic != OPTIONAL_HDR_MAGIC<XX>) return false;

	return true;
}

template <unsigned int XX, class Offset, class MemoryBuffer>
ImageBase<XX, Offset, MemoryBuffer>::ImageBase(buffer_type image_data)
	: _image_data { std::move(image_data) }
{
	if (!is_valid(_image_data))
		throw std::runtime_error("Image format not valid");
}

template <unsigned int XX, class Offset, class MemoryBuffer>
ImageType ImageBase<XX, Offset, MemoryBuffer>::type() const
{
	const Pointed<FileHeader> file_header = this->file_header();
	if ((file_header.characteristics & FILE_EXECUTABLE_IMAGE) != 0) {
		if ((file_header.characteristics & FILE_DLL) != 0)
			return ImageType::Dynamic;
		return ImageType::Executable;
	}
	return ImageType::Unknown;
}

template <unsigned int XX, class Offset, class MemoryBuffer>
ImageMachine ImageBase<XX, Offset, MemoryBuffer>::machine() const
{
	switch (file_header().machine) {
		case FILE_MACHINE_I386:  return ImageMachine::I386;
		case FILE_MACHINE_IA64:  return ImageMachine::IA64;
		case FILE_MACHINE_AMD64: return ImageMachine::AMD64;
		default:                 return ImageMachine::Unknown;
	}
}

template <unsigned int XX, class Offset, class MemoryBuffer>
inline VirtualOffset ImageBase<XX, Offset, MemoryBuffer>::entry_point() const
{
	return VirtualOffset(optional_header().address_of_entry_point);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::dos_header() const -> Pointed<DosHeader>
{
	DosHeader dos_header;
	do_read_from_buffer(0, sizeof(DosHeader), &dos_header);
	boost::endian::little_to_native_inplace(dos_header.e_magic   );
	boost::endian::little_to_native_inplace(dos_header.e_cblp    );
	boost::endian::little_to_native_inplace(dos_header.e_cp      );
	boost::endian::little_to_native_inplace(dos_header.e_crlc    );
	boost::endian::little_to_native_inplace(dos_header.e_cparhdr );
	boost::endian::little_to_native_inplace(dos_header.e_minalloc);
	boost::endian::little_to_native_inplace(dos_header.e_maxalloc);
	boost::endian::little_to_native_inplace(dos_header.e_ss      );
	boost::endian::little_to_native_inplace(dos_header.e_sp      );
	boost::endian::little_to_native_inplace(dos_header.e_csum    );
	boost::endian::little_to_native_inplace(dos_header.e_ip      );
	boost::endian::little_to_native_inplace(dos_header.e_cs      );
	boost::endian::little_to_native_inplace(dos_header.e_lfarlc  );
	boost::endian::little_to_native_inplace(dos_header.e_ovno    );
	for (auto & e_res  : dos_header.e_res)
		boost::endian::little_to_native_inplace(       e_res     );
	boost::endian::little_to_native_inplace(dos_header.e_oemid   );
	boost::endian::little_to_native_inplace(dos_header.e_oeminfo );
	for (auto & e_res2 : dos_header.e_res2)
		boost::endian::little_to_native_inplace(       e_res2    );
	boost::endian::little_to_native_inplace(dos_header.e_lfanew  );
	return PointedValue(Offset(0), dos_header);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::nt_headers() const -> Pointed<NtHeaders<XX>>
{
	NtHeaders<XX> nt_headers;
	const std::size_t nt_headers_offset = dos_header().e_lfanew;
	do_read_from_buffer(nt_headers_offset, sizeof(NtHeaders<XX>), &nt_headers);

	boost::endian::little_to_native_inplace(nt_headers.signature);
	nt_headers.file_header     = file_header();
	nt_headers.optional_header = optional_header();

	return PointedValue(Offset(nt_headers_offset), nt_headers);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::file_header() const -> Pointed<FileHeader>
{
	FileHeader file_header;
	const std::size_t file_header_offset = dos_header().e_lfanew + offsetof(NtHeaders<XX>, file_header);
	do_read_from_buffer(file_header_offset, sizeof(FileHeader), &file_header);

	boost::endian::little_to_native_inplace(file_header.machine                );
	boost::endian::little_to_native_inplace(file_header.number_of_sections     );
	boost::endian::little_to_native_inplace(file_header.time_date_stamp        );
	boost::endian::little_to_native_inplace(file_header.pointer_to_symbol_table);
	boost::endian::little_to_native_inplace(file_header.number_of_symbols      );
	boost::endian::little_to_native_inplace(file_header.size_of_optional_header);
	boost::endian::little_to_native_inplace(file_header.characteristics        );
	return PointedValue(Offset(file_header_offset), file_header);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::optional_header() const -> Pointed<OptionalHeader<XX>>
{
	OptionalHeader<XX> optional_header;
	const std::size_t opt_header_offset = dos_header().e_lfanew + offsetof(NtHeaders<XX>, optional_header);
	do_read_from_buffer(opt_header_offset, sizeof(OptionalHeader<XX>), &optional_header);

	boost::endian::little_to_native_inplace(optional_header.magic                         );
	boost::endian::little_to_native_inplace(optional_header.size_of_code                  );
	boost::endian::little_to_native_inplace(optional_header.size_of_initialized_data      );
	boost::endian::little_to_native_inplace(optional_header.size_of_uninitialized_data    );
	boost::endian::little_to_native_inplace(optional_header.address_of_entry_point        );
	boost::endian::little_to_native_inplace(optional_header.base_of_code                  );
	if constexpr (XX == 32) {
		boost::endian::little_to_native_inplace(optional_header.base_of_data              );
		boost::endian::little_to_native_inplace(optional_header.image_base                );
	} else if constexpr (XX == 64) {
		boost::endian::little_to_native_inplace(optional_header.image_base                );
	}
	boost::endian::little_to_native_inplace(optional_header.section_alignment             );
	boost::endian::little_to_native_inplace(optional_header.file_alignment                );
	boost::endian::little_to_native_inplace(optional_header.major_operating_system_version);
	boost::endian::little_to_native_inplace(optional_header.minor_operating_system_version);
	boost::endian::little_to_native_inplace(optional_header.major_image_version           );
	boost::endian::little_to_native_inplace(optional_header.minor_image_version           );
	boost::endian::little_to_native_inplace(optional_header.major_subsystem_version       );
	boost::endian::little_to_native_inplace(optional_header.minor_subsystem_version       );
	boost::endian::little_to_native_inplace(optional_header.win32_version_value           );
	boost::endian::little_to_native_inplace(optional_header.size_of_image                 );
	boost::endian::little_to_native_inplace(optional_header.size_of_headers               );
	boost::endian::little_to_native_inplace(optional_header.check_sum                     );
	boost::endian::little_to_native_inplace(optional_header.subsystem                     );
	boost::endian::little_to_native_inplace(optional_header.dll_characteristics           );
	if constexpr (XX == 32) {
		boost::endian::little_to_native_inplace(optional_header.size_of_stack_reserve     );
		boost::endian::little_to_native_inplace(optional_header.size_of_stack_commit      );
		boost::endian::little_to_native_inplace(optional_header.size_of_heap_reserve      );
		boost::endian::little_to_native_inplace(optional_header.size_of_heap_commit       );
	} else if constexpr (XX == 64) {
		boost::endian::little_to_native_inplace(optional_header.size_of_stack_reserve     );
		boost::endian::little_to_native_inplace(optional_header.size_of_stack_commit      );
		boost::endian::little_to_native_inplace(optional_header.size_of_heap_reserve      );
		boost::endian::little_to_native_inplace(optional_header.size_of_heap_commit       );
	}
	boost::endian::little_to_native_inplace(optional_header.loader_flags                  );
	boost::endian::little_to_native_inplace(optional_header.number_of_rvas_and_sizes      );
	for (std::size_t i = 0; i < NUMBEROF_DIRECTORY_ENTRIES; ++i) {
		boost::endian::little_to_native_inplace(optional_header.data_directory[i].virtual_address);
		boost::endian::little_to_native_inplace(optional_header.data_directory[i].size           );
	}

	return PointedValue(Offset(opt_header_offset), optional_header);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::section_headers() const -> SectionHeaderRange
{
	const Pointed<NtHeaders<XX>> nt_headers = this->nt_headers();
	const Offset offset_to_opt_header = nt_headers.offset() + offsetof(NtHeaders<XX>, optional_header);
	const Offset offset_to_section_headers = offset_to_opt_header + nt_headers.file_header.size_of_optional_header;
	const std::size_t distance_to_last_header = nt_headers.file_header.number_of_sections * sizeof(SectionHeader);
	return SectionHeaderRange(*this, offset_to_section_headers, distance_to_last_header);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::base_relocations() const -> BaseRelocationRange
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_BASERELOC);
	if (!data_dir || data_dir->size == 0) return BaseRelocationRange(*this, Offset(0), 0);

	const std::optional<Offset> data_offset = to_image_offset(*this, VirtualOffset(data_dir->virtual_address));
	if (!data_offset) return BaseRelocationRange(*this, Offset(0), 0);

	return BaseRelocationRange(*this, *data_offset, data_dir->size);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::debug_directories() const -> DebugDirectoryRange
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_DEBUG);
	if (!data_dir || data_dir->size == 0) return DebugDirectoryRange(*this, Offset(0), 0);

	const std::optional<Offset> data_offset = to_image_offset(*this, VirtualOffset(data_dir->virtual_address));
	if (!data_offset) return DebugDirectoryRange(*this, Offset(0), 0);

	return DebugDirectoryRange(*this, *data_offset, data_dir->size);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::exception_entries() const -> RuntimeFunctionRange
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_EXCEPTION);
	if (!data_dir || data_dir->size == 0) return RuntimeFunctionRange(*this, Offset(0), 0);

	const std::optional<Offset> data_offset = to_image_offset(*this, VirtualOffset(data_dir->virtual_address));
	if (!data_offset) return RuntimeFunctionRange(*this, Offset(0), 0);

	return RuntimeFunctionRange(*this, *data_offset, data_dir->size);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::import_descriptors() const -> ImportDescriptorRange
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_IMPORT);
	if (!data_dir || data_dir->size < sizeof(ImportDescriptor)) throw std::runtime_error("Invalid import data directory");

	const std::optional<Offset> data_offset = to_image_offset(*this, VirtualOffset(data_dir->virtual_address));
	if (!data_offset) throw std::runtime_error("Invalid import data directory");

	return ImportDescriptorRange(*this, *data_offset);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::resource_directory() const -> std::optional<ResourceDirectoryFacade<ImageBase>>
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_RESOURCE);
	if (!data_dir || data_dir->size < offsetof(ResourceDirectory, directory_entries)) return std::nullopt;

	const std::optional<Offset> data_offset = to_image_offset(*this, VirtualOffset(data_dir->virtual_address));
	if (!data_offset) return std::nullopt;

	return ResourceDirectoryFacade(*this, *data_offset);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::tls_directory() const -> std::optional<Pointed<TlsDirectoryFacade<XX, ImageBase>>>
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_TLS);
	if (!data_dir || data_dir->size < sizeof(TlsDirectory<XX>)) return std::nullopt;

	const std::optional<Offset> data_offset = to_image_offset(*this, VirtualOffset(data_dir->virtual_address));
	if (!data_offset) return std::nullopt;

	TlsDirectoryFacade<XX, ImageBase> tls_directory { *this, *data_offset };
	return PointedValue(*data_offset, std::move(tls_directory));
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::export_directory() const -> std::optional<Pointed<ExportDirectoryFacade<ImageBase>>>
{
	const std::optional<Pointed<DataDirectory>> data_dir = data_directory(DIRECTORY_ENTRY_EXPORT);
	if (!data_dir || data_dir->size < sizeof(ExportDirectory)) return std::nullopt;

	const VirtualOffset data_rva { data_dir->virtual_address };
	const std::optional<Offset> data_offset = to_image_offset(*this, data_rva);
	if (!data_offset) return std::nullopt;

	ExportDirectoryFacade<ImageBase> export_dir { *this, *data_offset };
	return PointedValue(*data_offset, std::move(export_dir));
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::copyright_str() const -> std::optional<Pointed<std::string>>
{
	if (const auto data_dir = data_directory(DIRECTORY_ENTRY_COPYRIGHT); data_dir)
		return read_string(VirtualOffset(data_dir->virtual_address), data_dir->size);

	return std::nullopt;
}

template <unsigned int XX, class Offset, class MemoryBuffer>
auto ImageBase<XX, Offset, MemoryBuffer>::data_directory(DirectoryEntryIndex index) const -> std::optional<Pointed<DataDirectory>>
{
	const Pointed<OptionalHeader<XX>> opt_header = optional_header();
	if (index >= NUMBEROF_DIRECTORY_ENTRIES) return std::nullopt;

	const DataDirectory & data_dir = opt_header.data_directory[index];
	const Offset datadir_offset = opt_header.offset() + offsetof(OptionalHeader<XX>, data_directory[index]);
	if (data_dir.virtual_address == 0 || data_dir.size == 0) return std::nullopt;

	return PointedValue(datadir_offset, data_dir);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
std::optional<FileOffset> ImageBase<XX, Offset, MemoryBuffer>::to_file_offset(VirtualOffset rva) const
{
	if (rva < VirtualOffset(optional_header().size_of_headers))
		return FileOffset(rva.value());

	for (const Pointed<SectionHeader> & section_header : section_headers()) {
		const FileOffset section_start { section_header.pointer_to_raw_data };
		const VirtualOffset section_vstart { section_header.virtual_address };
		const VirtualOffset section_end = section_vstart + section_header.size_of_raw_data;
		if (section_vstart <= rva && rva < section_end)
			return section_start + (rva - section_vstart).value();
	}

	return std::nullopt;
}

template <unsigned int XX, class Offset, class MemoryBuffer>
std::optional<VirtualOffset> ImageBase<XX, Offset, MemoryBuffer>::to_virtual_offset(FileOffset offs) const
{
	if (offs < FileOffset(optional_header().size_of_headers))
		return VirtualOffset(offs.value());

	for (const Pointed<SectionHeader> & section_header : section_headers()) {
		const FileOffset section_start { section_header.pointer_to_raw_data };
		const VirtualOffset section_vstart { section_header.virtual_address };
		const FileOffset section_end = section_start + section_header.size_of_raw_data;
		if (section_start <= offs && offs < section_end)
			return section_vstart + (offs - section_start).value();
	}

	return std::nullopt;
}

template <unsigned int XX, class Offset, class MemoryBuffer> template <class CharT, class DataOffset>
auto ImageBase<XX, Offset, MemoryBuffer>::read_string(DataOffset from) const -> Pointed<std::basic_string<CharT>>
{
	const std::optional<Offset> data_offset = to_image_offset(*this, from);
	if (!data_offset) throw std::runtime_error("Invalid offset given");

	std::vector<CharT> strbuf (10);
	Offset read_offset = *data_offset;
	std::basic_ostringstream<CharT> oss;
	for (;;) {
		const auto [bytes_read, _] = read(read_offset, strbuf.size() * sizeof(CharT), strbuf.data());
		const auto strbuf_read_end = std::next(strbuf.begin(), bytes_read / sizeof(CharT));
		const auto nul_iter = std::find(strbuf.begin(), strbuf_read_end, CharT('\0'));
		std::copy(strbuf.begin(), nul_iter, std::ostream_iterator<CharT, CharT>(oss));
		if (nul_iter != strbuf_read_end || strbuf_read_end != strbuf.end()) break;
		strbuf.resize(static_cast<std::size_t>(strbuf.size() * 1.5));
		read_offset += bytes_read;
	}

	return PointedValue(*data_offset, oss.str());
}

template <unsigned int XX, class Offset, class MemoryBuffer> template <class CharT, class DataOffset>
auto ImageBase<XX, Offset, MemoryBuffer>::read_string(DataOffset from, std::size_t length) const -> Pointed<std::basic_string<CharT>>
{
	std::vector<CharT> strbuf (length);
	const auto [size, offset] = read(from, length * sizeof(CharT), strbuf.data());
	return PointedValue(offset, std::basic_string<CharT>(strbuf.data(), size / sizeof(CharT)));
}

template <unsigned int XX, class Offset, class MemoryBuffer> template <class DataOffset>
std::pair<std::size_t, Offset> ImageBase<XX, Offset, MemoryBuffer>::read(DataOffset offset, std::size_t size, void * into_buffer) const
{
	const std::optional<Offset> data_offset = to_image_offset(*this, offset);
	if (!data_offset) throw std::runtime_error("Invalid offset given");

	const std::size_t bytes_read = MemoryBuffer::read(_image_data, data_offset->value(),
	                                                  size, into_buffer);
	return std::pair(bytes_read, *data_offset);
}

template <unsigned int XX, class Offset, class MemoryBuffer>
void ImageBase<XX, Offset, MemoryBuffer>::do_read_from_buffer(std::size_t offset, std::size_t size, void * into_buffer) const
{
	const std::size_t bytes_read = MemoryBuffer::read(_image_data, offset, size, into_buffer);
	if (bytes_read < size) throw std::runtime_error("Malformed image");
}

}

#endif

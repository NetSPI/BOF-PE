#ifndef PEPLUS_DETAIL_FACADES_EXPORTDIRECTORYFACADE_HPP_
#define PEPLUS_DETAIL_FACADES_EXPORTDIRECTORYFACADE_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_helpers.hpp>
#include <peplus/detail/image_offset.hpp>

#include <boost/endian/conversion.hpp>

#include <cassert>
#include <cstddef>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace peplus::detail {

template <class Image>
class ExportDirectoryFacade : public ExportDirectory
{
public:
	using offset_type = typename Image::offset_type;

	template <typename T>
	using Pointed = PointedValue<offset_type, T>;

	struct ExportInfo
	{
		std::optional<Pointed<std::string>> name;
		DWORD                               ordinal;
		VirtualOffset                       address;
		std::optional<Pointed<WORD>>        name_ordinal;
		bool                                is_forwarded;
		std::optional<Pointed<std::string>> forwarder_string;
	};

	using ExportNameRange = EntryRange <
		Image, read_pointed_value<read_rva_string>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(DWORD)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>, std::size_t
	>;

	using ExportFunctionRvaRange = EntryRange <
		Image, read_pointed_trivial_le_value_as<VirtualOffset, DWORD>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(DWORD)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>, std::size_t
	>;

	ExportDirectoryFacade(const Image & image, offset_type offset);

	Pointed<std::string> name_str() const;

	ExportNameRange names() const;
	ExportFunctionRvaRange functions() const;

	std::optional<ExportInfo> find(unsigned int ordinal) const;
	std::optional<ExportInfo> find(std::string_view name) const;

private:
	using ExportNameOrdinalRange = EntryRange <
		Image, read_pointed_value<read_trivial_le_value<WORD>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(WORD)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>, std::size_t
	>;

	ExportNameOrdinalRange name_ordinals() const;

	const Image * _image;
};

template <class Image, class Offset = typename Image::offset_type>
ExportDirectory read_export_directory_from_image(const Image & image, Offset offset)
{
	ExportDirectory export_dir;
	image_do_read(image, offset, sizeof(ExportDirectory), &export_dir);
	boost::endian::little_to_native_inplace(export_dir.characteristics         );
	boost::endian::little_to_native_inplace(export_dir.time_date_stamp         );
	boost::endian::little_to_native_inplace(export_dir.major_version           );
	boost::endian::little_to_native_inplace(export_dir.minor_version           );
	boost::endian::little_to_native_inplace(export_dir.name                    );
	boost::endian::little_to_native_inplace(export_dir.base                    );
	boost::endian::little_to_native_inplace(export_dir.number_of_functions     );
	boost::endian::little_to_native_inplace(export_dir.number_of_names         );
	boost::endian::little_to_native_inplace(export_dir.address_of_functions    );
	boost::endian::little_to_native_inplace(export_dir.address_of_names        );
	boost::endian::little_to_native_inplace(export_dir.address_of_name_ordinals);
	return export_dir;
}

template <class Image>
bool is_export_forwarded(const Image & image, VirtualOffset fn_address)
{
	assert(image.data_directory(DIRECTORY_ENTRY_EXPORT).has_value());

	const auto & data_dir = *image.data_directory(DIRECTORY_ENTRY_EXPORT);
	const VirtualOffset expdir_begin { data_dir.virtual_address };
	const VirtualOffset expdir_end = expdir_begin + data_dir.size;
	return expdir_begin <= fn_address && fn_address < expdir_end;
}

template <class Image>
ExportDirectoryFacade<Image>::ExportDirectoryFacade(const Image & image, offset_type offset)
	: ExportDirectory { read_export_directory_from_image(image, offset) }
	, _image { &image } {}

template <class Image>
auto ExportDirectoryFacade<Image>::name_str() const -> Pointed<std::string>
{
	return _image->read_string(VirtualOffset(this->name));
}

template <class Image>
auto ExportDirectoryFacade<Image>::names() const -> ExportNameRange
{
	if (this->address_of_names == 0) return ExportNameRange(*_image, offset_type(0), 0);

	const VirtualOffset names_rva { this->address_of_names };
	const std::optional<offset_type> names_offset = to_image_offset(*_image, names_rva);
	if (!names_offset) return ExportNameRange(*_image, offset_type(0), 0);

	const std::size_t names_size = this->number_of_names * sizeof(DWORD);
	return ExportNameRange(*_image, *names_offset, names_size);
}

template <class Image>
auto ExportDirectoryFacade<Image>::functions() const -> ExportFunctionRvaRange
{
	if (this->address_of_functions == 0) return ExportFunctionRvaRange(*_image, offset_type(0), 0);

	const VirtualOffset functions_rva { this->address_of_functions };
	const std::optional<offset_type> functions_offset = to_image_offset(*_image, functions_rva);
	if (!functions_offset) return ExportFunctionRvaRange(*_image, offset_type(0), 0);

	const std::size_t functions_size = this->number_of_functions * sizeof(DWORD);
	return ExportFunctionRvaRange(*_image, *functions_offset, functions_size);
}

template <class Image>
auto ExportDirectoryFacade<Image>::name_ordinals() const -> ExportNameOrdinalRange
{
	if (this->address_of_name_ordinals == 0) return ExportNameOrdinalRange(*_image, offset_type(0), 0);

	const VirtualOffset name_ordinals_rva { this->address_of_name_ordinals };
	const std::optional<offset_type> name_ordinals_offset = to_image_offset(*_image, name_ordinals_rva);
	if (!name_ordinals_offset) return ExportNameOrdinalRange(*_image, offset_type(0), 0);

	const std::size_t name_ordinals_size = this->number_of_names * sizeof(WORD);
	return ExportNameOrdinalRange(*_image, *name_ordinals_offset, name_ordinals_size);
}

template <class Image>
auto ExportDirectoryFacade<Image>::find(unsigned int ordinal) const -> std::optional<ExportInfo>
{
	if (ordinal > this->number_of_functions) return std::nullopt;

	ExportInfo export_info;
	export_info.ordinal = ordinal;

	const auto export_fn_range = this->functions();
	const auto export_fn_it = std::next(export_fn_range.begin(), ordinal);
	const VirtualOffset fn_address = export_info.address = *export_fn_it;

	if (export_info.is_forwarded = is_export_forwarded(*_image, fn_address))
		export_info.forwarder_string = _image->read_string(fn_address);

	unsigned int name_index = 0;
	const unsigned int name_ordinal = ordinal - this->base;
	for (const auto exported_name_ordinal : name_ordinals()) {
		if (exported_name_ordinal != name_ordinal) {
			++name_index;
		} else {
			assert(name_index < this->number_of_names);
			const auto export_name_range = this->names();
			const auto export_name_it = std::next(export_name_range.begin(), name_index);
			export_info.name_ordinal = exported_name_ordinal;
			export_info.name = *export_name_it;
			break;
		}
	}

	return export_info;
}

template <class Image>
auto ExportDirectoryFacade<Image>::find(std::string_view name) const -> std::optional<ExportInfo>
{
	unsigned int name_index = 0;
	for (auto & exported_name : names()) {
		if (exported_name != name) {
			++name_index;
		} else {
			assert(name_index < this->number_of_names);
			const auto name_ordinal_range = this->name_ordinals();
			const auto name_ordinal_it = std::next(name_ordinal_range.begin(), name_index);

			if (*name_ordinal_it >= this->number_of_names)
				throw std::runtime_error("Invalid export name ordinal");

			ExportInfo export_info;
			export_info.name = std::move(exported_name);
			export_info.name_ordinal = *name_ordinal_it;
			export_info.ordinal = this->base + *name_ordinal_it;

			const auto exported_fn_range = this->functions();
			const auto exported_fn_it = std::next(exported_fn_range.begin(), *name_ordinal_it);
			const VirtualOffset fn_address = export_info.address = *exported_fn_it;

			if (export_info.is_forwarded = is_export_forwarded(*_image, fn_address))
				export_info.forwarder_string = _image->read_string(fn_address);

			return export_info;
		}
	}

	return std::nullopt;
}

}

#endif

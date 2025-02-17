#ifndef PEPLUS_DETAIL_FACADES_IMPORTDESCRIPTORFACADE_HPP_
#define PEPLUS_DETAIL_FACADES_IMPORTDESCRIPTORFACADE_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_helpers.hpp>
#include <peplus/detail/transform_range.hpp>

#include <boost/endian/conversion.hpp>

#include <cstdlib>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace peplus::detail {

template <unsigned int XX>
struct read_thunk_data
{
	template <class Image, class Offset, class RtParams>
	static ThunkData<XX> read_value(const Image & image, Offset offset, const RtParams &)
	{
		ThunkData<XX> thunk_data;
		image_do_read(image, offset, sizeof(ThunkData<XX>), &thunk_data);
		boost::endian::little_to_native_inplace(thunk_data.function);
		return thunk_data;
	}
};

template <unsigned int XX, class Image>
class ImportDescriptorFacade : public ImportDescriptor
{
public:
	using offset_type = typename Image::offset_type;

	template <typename T>
	using Pointed = PointedValue<offset_type, T>;

	struct NamedImport
	{
		Pointed<std::string> name;
	};

	struct UnnamedImport
	{
		unsigned int ordinal;
	};

	using ImportEntry = std::variant<NamedImport, UnnamedImport>;

	using ThunkDataRange = EntryRange <
		Image, read_pointed_value<read_thunk_data<XX>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(ThunkData<XX>)>>,
		either_stop_iteration_policy < condition_stop_iteration_policy<runtime_param<0>>,
		                               default_value_stop_iteration_policy<ThunkData<XX>> >,
		bool
	>;

	class thunk_data_to_import_entry_transformer;

	using ImportEntryRange = TransformRange <
		thunk_data_to_import_entry_transformer, ThunkDataRange
	>;

	ImportDescriptorFacade(const Image & image, offset_type offset);

	Pointed<std::string> name_str() const;

	ThunkDataRange thunks() const;
	ThunkDataRange original_thunks() const;

	ImportEntryRange entries() const;

	template <class ImportEntry>
	static constexpr bool is_named_import();

	template <class ImportEntry>
	static constexpr bool is_unnamed_import();

	bool is_named_import(const ImportEntry & import_entry) const;
	bool is_unnamed_import(const ImportEntry & import_entry) const;

private:
	const Image * _image;
};

template <unsigned int XX, class Image>
class ImportDescriptorFacade<XX, Image>::thunk_data_to_import_entry_transformer
{
public:
	using offset_type = typename Image::offset_type;

	explicit thunk_data_to_import_entry_transformer(const Image & image)
		: _image { &image } {}

	ImportEntry operator()(const ThunkData<XX> & thunk_data) const
	{
		if ((thunk_data.ordinal & ORDINAL_FLAG<XX>) != 0) {
			const auto ordinal = thunk_data.ordinal & ~ORDINAL_FLAG<XX>;
			return UnnamedImport { static_cast<unsigned int>(ordinal) };
		} else {
			const VirtualOffset hint_name_rva ( thunk_data.address_of_data );
			const VirtualOffset name_rva = hint_name_rva + offsetof(ImportByName, name);
			return NamedImport { _image->read_string(name_rva) };
		}
	}

private:
	const Image * _image;
};

template <class Image, class Offset = typename Image::offset_type>
ImportDescriptor read_import_descriptor_from_image(const Image & image, Offset offset)
{
	ImportDescriptor import_descriptor;
	image.read(offset, sizeof(ImportDescriptor), &import_descriptor);
	boost::endian::little_to_native_inplace(import_descriptor.original_first_thunk);
	boost::endian::little_to_native_inplace(import_descriptor.time_date_stamp     );
	boost::endian::little_to_native_inplace(import_descriptor.forwarder_chain     );
	boost::endian::little_to_native_inplace(import_descriptor.name                );
	boost::endian::little_to_native_inplace(import_descriptor.first_thunk         );
	return import_descriptor;
}

template <unsigned int XX, class Image>
ImportDescriptorFacade<XX, Image>::ImportDescriptorFacade(const Image & image, offset_type offset)
	: ImportDescriptor { read_import_descriptor_from_image(image, offset) }
	, _image { &image } {}

template <unsigned int XX, class Image>
auto ImportDescriptorFacade<XX, Image>::name_str() const -> Pointed<std::string>
{
	return _image->read_string(VirtualOffset(this->name));
}

template <unsigned int XX, class Image>
auto ImportDescriptorFacade<XX, Image>::thunks() const -> ThunkDataRange
{
	if (this->first_thunk == 0) return ThunkDataRange(*_image, offset_type(0), false);

	const VirtualOffset thunks_rva { this->first_thunk };
	const std::optional<offset_type> thunks_offset = to_image_offset(*_image, thunks_rva);
	return ThunkDataRange(*_image, thunks_offset.value_or(offset_type(0)), thunks_offset.has_value());
}

template <unsigned int XX, class Image>
auto ImportDescriptorFacade<XX, Image>::original_thunks() const -> ThunkDataRange
{
	if (this->original_first_thunk == 0) return ThunkDataRange(*_image, offset_type(0), false);

	const VirtualOffset thunks_rva { this->original_first_thunk };
	const std::optional<offset_type> thunks_offset = to_image_offset(*_image, thunks_rva);
	return ThunkDataRange(*_image, thunks_offset.value_or(offset_type(0)), thunks_offset.has_value());
}

template <unsigned int XX, class Image>
auto ImportDescriptorFacade<XX, Image>::entries() const -> ImportEntryRange
{
	thunk_data_to_import_entry_transformer to_import_entries { *_image };
	return ImportEntryRange(original_thunks(), std::move(to_import_entries));
}

template <unsigned int XX, class Image> template <class ImportEntry>
constexpr bool ImportDescriptorFacade<XX, Image>::is_named_import()
{
	return std::is_base_of_v<NamedImport, std::decay_t<ImportEntry>>;
}

template <unsigned int XX, class Image> template <class ImportEntry>
constexpr bool ImportDescriptorFacade<XX, Image>::is_unnamed_import()
{
	return std::is_base_of_v<UnnamedImport, std::decay_t<ImportEntry>>;
}

template <unsigned int XX, class Image>
bool ImportDescriptorFacade<XX, Image>::is_named_import(const ImportEntry & import_entry) const
{
	return import_entry.index() == 0;
}

template <unsigned int XX, class Image>
bool ImportDescriptorFacade<XX, Image>::is_unnamed_import(const ImportEntry & import_entry) const
{
	return import_entry.index() == 1;
}

constexpr bool operator ==(const ImportDescriptor & lhs, const ImportDescriptor & rhs)
{
	return lhs.original_first_thunk == rhs.original_first_thunk
	    && lhs.time_date_stamp      == rhs.time_date_stamp
	    && lhs.forwarder_chain      == rhs.forwarder_chain
	    && lhs.name                 == rhs.name
	    && lhs.first_thunk          == rhs.first_thunk;
}

template <unsigned int XX>
constexpr bool operator ==(const ThunkData<XX> & lhs, const ThunkData<XX> & rhs)
{
	return lhs.function == rhs.function;
}

}

#endif

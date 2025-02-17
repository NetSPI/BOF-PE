#ifndef PEPLUS_DETAIL_FACADES_RESOURCEDIRECTORYFACADE_HPP_
#define PEPLUS_DETAIL_FACADES_RESOURCEDIRECTORYFACADE_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_helpers.hpp>
#include <peplus/detail/image_offset.hpp>

#include <boost/endian/conversion.hpp>

#include <optional>
#include <string>
#include <utility>

namespace peplus::detail {

template <class Image>
class ResourceDirectoryEntryFacade;

template <class Image>
class ResourceDirectoryFacade
	: public PointedValue<typename Image::offset_type, ResourceDirectory>
{
public:
	using offset_type = typename Image::offset_type;

	template <typename T>
	using Pointed = PointedValue<offset_type, T>;

	using ResourceDirectoryEntryRange = EntryRange <
		Image, read_pointed_value<read_proxy_object<ResourceDirectoryEntryFacade<Image>, runtime_param<0>>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(ResourceDirectoryEntry)>>,
		fixed_distance_stop_iteration_policy<runtime_param<1>>, offset_type, std::size_t
	>;

	ResourceDirectoryFacade(const Image & image, offset_type offset);
	ResourceDirectoryFacade(const Image & image, offset_type offset, offset_type rdata_begin);

	ResourceDirectoryEntryRange entries() const;
	ResourceDirectoryEntryRange id_entries() const;
	ResourceDirectoryEntryRange named_entries() const;

private:
	const Image * _image;
	offset_type   _rdata_begin;
};

template <class Image>
class ResourceDirectoryEntryFacade : public ResourceDirectoryEntry
{
public:
	using offset_type = typename Image::offset_type;

	template <typename T>
	using Pointed = PointedValue<offset_type, T>;

	ResourceDirectoryEntryFacade(const Image & image, offset_type offset,
	                             offset_type rdata_begin);

	bool is_directory() const;
	bool is_data_entry() const;
	bool is_named_entry() const;

	std::optional<Pointed<std::wstring>> name_str() const;

	std::optional<std::pair<offset_type, std::size_t>> data() const;
	std::optional<Pointed<ResourceDataEntry>> as_data_entry() const;
	std::optional<ResourceDirectoryFacade<Image>> as_directory() const;

protected:
	const Image * _image;
	offset_type   _rdata_begin;
};

template <class Image, class Offset = typename Image::offset_type>
ResourceDirectoryEntry read_resource_directory_entry_from_image(const Image & image, Offset offset)
{
	ResourceDirectoryEntry resource_entry;
	image_do_read(image, offset, sizeof(ResourceDirectoryEntry), &resource_entry);
	boost::endian::little_to_native_inplace(resource_entry.name          );
	boost::endian::little_to_native_inplace(resource_entry.offset_to_data);
	return resource_entry;
}

template <class Image, class Offset = typename Image::offset_type>
ResourceDirectory read_resource_directory_from_image(const Image & image, Offset offset)
{
	ResourceDirectory resource_directory;
	image_do_read(image, offset, sizeof(ResourceDirectory), &resource_directory);
	boost::endian::little_to_native_inplace(resource_directory.characteristics        );
	boost::endian::little_to_native_inplace(resource_directory.time_date_stamp        );
	boost::endian::little_to_native_inplace(resource_directory.major_version          );
	boost::endian::little_to_native_inplace(resource_directory.minor_version          );
	boost::endian::little_to_native_inplace(resource_directory.number_of_named_entries);
	boost::endian::little_to_native_inplace(resource_directory.number_of_id_entries   );
	return resource_directory;
}

template <typename T, class Image, class Offset>
T read_le_integral(const Image & image, Offset offset)
{
	T value;
	image_do_read(image, offset, sizeof(T), &value);
	return boost::endian::little_to_native(value);
}

template <class Image, class Offset>
auto read_resource_string(const Image & image, Offset offset) -> PointedValue<Offset, std::wstring>
{
	const std::size_t length = read_le_integral<unsigned short>(image, offset);
	return image.template read_string<wchar_t>(offset + sizeof(unsigned short), length);
}

template <class Image>
ResourceDirectoryFacade<Image>::ResourceDirectoryFacade(const Image & image, offset_type offset)
	: ResourceDirectoryFacade { image, offset, offset } {}

template <class Image>
ResourceDirectoryFacade<Image>::ResourceDirectoryFacade(const Image & image, offset_type offset,
                                                        offset_type rdata_begin)
	: Pointed<ResourceDirectory> { offset, read_resource_directory_from_image(image, offset) }
	, _image { &image }, _rdata_begin { rdata_begin } {}

template <class Image>
auto ResourceDirectoryFacade<Image>::entries() const -> ResourceDirectoryEntryRange
{
	const std::size_t number_of_entries = this->number_of_named_entries + this->number_of_id_entries;
	const std::size_t size_of_entries = number_of_entries * sizeof(ResourceDirectoryEntry);
	const offset_type entries_offset = this->offset() + offsetof(ResourceDirectory, directory_entries);
	return ResourceDirectoryEntryRange(*_image, entries_offset, _rdata_begin, size_of_entries);
}

template <class Image>
auto ResourceDirectoryFacade<Image>::id_entries() const -> ResourceDirectoryEntryRange
{
	const std::size_t size_of_entries = this->number_of_id_entries * sizeof(ResourceDirectoryEntry);
	const offset_type entries_offset = this->offset() + offsetof(ResourceDirectory, directory_entries);
	return ResourceDirectoryEntryRange(*_image, entries_offset, _rdata_begin, size_of_entries);
}

template <class Image>
auto ResourceDirectoryFacade<Image>::named_entries() const -> ResourceDirectoryEntryRange
{
	const std::size_t size_of_entries = this->number_of_named_entries * sizeof(ResourceDirectoryEntry);
	const offset_type entries_offset = this->offset() + offsetof(ResourceDirectory, directory_entries);
	return ResourceDirectoryEntryRange(*_image, entries_offset, _rdata_begin, size_of_entries);
}

template <class Image>
ResourceDirectoryEntryFacade<Image>::ResourceDirectoryEntryFacade(const Image & image, offset_type offset,
                                                                  offset_type rdata_begin)
	: ResourceDirectoryEntry { read_resource_directory_entry_from_image(image, offset) }
	, _image { &image }, _rdata_begin { rdata_begin } {}

template <class Image>
bool ResourceDirectoryEntryFacade<Image>::is_directory() const
{
	return (this->offset_to_data & (1 << 31)) != 0;
}

template <class Image>
bool ResourceDirectoryEntryFacade<Image>::is_data_entry() const
{
	return (this->offset_to_data & (1 << 31)) == 0;
}

template <class Image>
bool ResourceDirectoryEntryFacade<Image>::is_named_entry() const
{
	return (this->name & (1 << 31)) != 0;
}

template <class Image>
auto ResourceDirectoryEntryFacade<Image>::name_str() const -> std::optional<Pointed<std::wstring>>
{
	if (!is_named_entry()) return std::nullopt;

	const offset_type name_offset { this->name & ~(1 << 31) };
	return read_resource_string(*_image, _rdata_begin + name_offset);
}

template <class Image>
auto ResourceDirectoryEntryFacade<Image>::data() const -> std::optional<std::pair<offset_type, std::size_t>>
{
	const std::optional<ResourceDataEntry> rdata_entry = as_data_entry();
	if (!rdata_entry) return std::nullopt;

	const offset_type data_offset = _rdata_begin + rdata_entry->offset_to_data;
	return std::pair(data_offset, rdata_entry->size);
}

template <class Image>
auto ResourceDirectoryEntryFacade<Image>::as_data_entry() const -> std::optional<Pointed<ResourceDataEntry>>
{
	if (!is_data_entry()) return std::nullopt;

	ResourceDataEntry data_entry;
	const offset_type data_offset { this->offset_to_data };
	image_do_read(*_image, data_offset, sizeof(ResourceDataEntry), &data_entry);

	boost::endian::little_to_native_inplace(data_entry.offset_to_data);
	boost::endian::little_to_native_inplace(data_entry.size          );
	boost::endian::little_to_native_inplace(data_entry.code_page     );
	boost::endian::little_to_native_inplace(data_entry.reserved      );
	return PointedValue(data_offset, data_entry);
}

template <class Image>
std::optional<ResourceDirectoryFacade<Image>> ResourceDirectoryEntryFacade<Image>::as_directory() const
{
	if (!is_directory()) return std::nullopt;

	const offset_type resdir_offset { this->offset_to_data & ~(1 << 31) };
	return ResourceDirectoryFacade(*_image, _rdata_begin + resdir_offset, _rdata_begin);
}

}

#endif

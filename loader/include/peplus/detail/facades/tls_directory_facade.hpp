#ifndef PEPLUS_DETAIL_FACADES_TLSDIRECTORYFACADE_HPP_
#define PEPLUS_DETAIL_FACADES_TLSDIRECTORYFACADE_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_helpers.hpp>
#include <peplus/detail/image_offset.hpp>

#include <optional>

namespace peplus::detail {

template <unsigned int XX, class Image>
class TlsDirectoryFacade : public TlsDirectory<XX>
{
public:
	using offset_type = typename Image::offset_type;

	template <typename T>
	using Pointed = PointedValue<offset_type, T>;

	using TlsCallbackRange = EntryRange <
		Image, read_pointed_trivial_le_value_as<VirtualOffset, ULONG_PTR<XX>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(ULONG_PTR<XX>)>>,
		either_stop_iteration_policy < condition_stop_iteration_policy<runtime_param<0>>,
		                               default_value_stop_iteration_policy<VirtualOffset> >,
		bool
	>;

	TlsDirectoryFacade(const Image & image, offset_type offset);

	TlsCallbackRange callbacks() const;

private:
	const Image * _image;
};

template <unsigned int XX, class Image, class Offset = typename Image::offset_type>
TlsDirectory<XX> read_tls_directory_from_image(const Image & image, Offset offset)
{
	TlsDirectory<XX> tls_directory;
	image_do_read(image, offset, sizeof(TlsDirectory<XX>), &tls_directory);
	boost::endian::little_to_native_inplace(tls_directory.start_address_of_raw_data);
	boost::endian::little_to_native_inplace(tls_directory.end_address_of_raw_data  );
	boost::endian::little_to_native_inplace(tls_directory.address_of_index         );
	boost::endian::little_to_native_inplace(tls_directory.address_of_callbacks     );
	boost::endian::little_to_native_inplace(tls_directory.size_of_zero_fill        );
	boost::endian::little_to_native_inplace(tls_directory.characteristics          );
	return tls_directory;
}

template <unsigned int XX, class Image>
TlsDirectoryFacade<XX, Image>::TlsDirectoryFacade(const Image & image, offset_type offset)
	: TlsDirectory<XX> { read_tls_directory_from_image<XX>(image, offset) }
	, _image { &image } {}

template <unsigned int XX, class Image>
auto TlsDirectoryFacade<XX, Image>::callbacks() const -> TlsCallbackRange
{
	if (this->address_of_callbacks == 0) return TlsCallbackRange(*_image, offset_type(0), false);
	const std::optional<offset_type> tls_offset = to_image_offset(*_image, VirtualOffset(this->address_of_callbacks));
	return TlsCallbackRange(*_image, tls_offset.value_or(offset_type(0)), tls_offset.has_value());
}

}

#endif

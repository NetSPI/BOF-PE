#ifndef PEPLUS_VIRTUALIMAGE_HPP_
#define PEPLUS_VIRTUALIMAGE_HPP_

#include <peplus/image_common.hpp>
#include <peplus/detail/image_base.hpp>

#include <optional>
#include <type_traits>

namespace peplus {

template <unsigned int XX, class MemoryBuffer>
using VirtualImage = detail::ImageBase<XX, VirtualOffset, MemoryBuffer>;

template <class MemoryBuffer>
using VirtualImage32 = VirtualImage<32, MemoryBuffer>;

template <class MemoryBuffer>
using VirtualImage64 = VirtualImage<64, MemoryBuffer>;

template <unsigned int XX, class MemoryBuffer, class Offset>
std::optional<VirtualOffset>
	to_image_offset(const VirtualImage<XX, MemoryBuffer> & image, Offset offset)
{
	if constexpr (std::is_same_v<Offset, VirtualOffset>) {
		return offset;
	} else {
		return image.to_virtual_offset(offset);
	}
}

}

#endif
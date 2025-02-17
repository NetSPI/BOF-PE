#ifndef PEPLUS_FILEIMAGE_HPP_
#define PEPLUS_FILEIMAGE_HPP_

#include <peplus/image_common.hpp>
#include <peplus/detail/image_base.hpp>

#include <optional>
#include <type_traits>

namespace peplus {

template <unsigned int XX, class MemoryBuffer>
using FileImage = detail::ImageBase<XX, FileOffset, MemoryBuffer>;

template <class MemoryBuffer>
using FileImage32 = FileImage<32, MemoryBuffer>;

template <class MemoryBuffer>
using FileImage64 = FileImage<64, MemoryBuffer>;

template <unsigned int XX, class MemoryBuffer, class Offset>
std::optional<FileOffset>
	to_image_offset(const FileImage<XX, MemoryBuffer> & image, Offset offset)
{
	if constexpr (std::is_same_v<Offset, FileOffset>) {
		return offset;
	} else {
		return image.to_file_offset(offset);
	}
}

}

#endif
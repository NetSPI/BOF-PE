#ifndef PEPLUS_LOCALBUFFER_HPP_
#define PEPLUS_LOCALBUFFER_HPP_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace peplus {

class LocalBuffer
{
public:
	template <std::size_t N>
	constexpr LocalBuffer(const char (&buffer)[N]);

	constexpr LocalBuffer(const void * mem);
	constexpr LocalBuffer(const void * mem, std::size_t size);

	constexpr const char * data() const;
	constexpr std::size_t  size() const;

private:
	const char  * _mem;
	std::size_t   _size;
};

struct local_buffer
{
	using value_type = LocalBuffer;

	static std::size_t read(const LocalBuffer & buffer, std::size_t offset,
	                        std::size_t data_size, void * into_buffer)
	{
		const std::size_t bytes_to_read = std::min(buffer.size() - offset, data_size);
		std::copy_n(buffer.data(), bytes_to_read, static_cast<char *>(into_buffer));
		return bytes_to_read;
	}
};

template <std::size_t N>
constexpr LocalBuffer::LocalBuffer(const char (&buffer)[N])
	: LocalBuffer { buffer, N } {}

constexpr LocalBuffer::LocalBuffer(const void * mem)
	: LocalBuffer {
		mem, std::numeric_limits<std::uintptr_t>::max() -
		     reinterpret_cast<std::uintptr_t>(mem)
	} {}

constexpr LocalBuffer::LocalBuffer(const void * mem, std::size_t size)
	: _mem { static_cast<const char *>(mem) }, _size { size } {}

constexpr const char * LocalBuffer::data() const
{
	return _mem;
}

constexpr std::size_t LocalBuffer::size() const
{
	return _size;
}

}

#endif
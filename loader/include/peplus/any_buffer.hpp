#ifndef PEPLUS_ANYBUFFER_HPP_
#define PEPLUS_ANYBUFFER_HPP_

#include <cstddef>

namespace peplus {

class MemoryBuffer
{
public:
	virtual ~MemoryBuffer() = default;
	virtual std::size_t read(std::size_t offset, std::size_t data_size, void * into_buffer) const = 0;
};

struct any_buffer
{
	using value_type = const MemoryBuffer &;

	static std::size_t read(const MemoryBuffer & buffer, std::size_t offset,
	                        std::size_t data_size, void * into_buffer)
	{
		return buffer.read(offset, data_size, into_buffer);
	}
};

}

#endif
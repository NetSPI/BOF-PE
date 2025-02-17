#ifndef PEPLUS_DETAIL_IMAGEHELPERS_HPP_
#define PEPLUS_DETAIL_IMAGEHELPERS_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>

#include <cstdlib>
#include <iterator>
#include <tuple>

#include <boost/endian/conversion.hpp>

namespace peplus::detail {

template <auto X>
struct constexpr_
{
	using value_type = decltype(X);
	static constexpr auto value = X;
};

template <std::size_t I>
struct runtime_param
{
	static constexpr std::size_t index = I;
};

template <class Image, class Offset>
void image_do_read(const Image & image, Offset offset, std::size_t size, void * into_buffer)
{
	const auto [bytes_read, _] = image.read(offset, size, into_buffer);
	if (bytes_read < size) throw std::runtime_error("Malformed image");
}

template <typename T>
struct read_trivial_le_value
{
	template <class Image, class Offset, class RtParams>
	static T read_value(const Image & image, Offset offset, RtParams)
	{
		T value;
		image_do_read(image, offset, sizeof(T), &value);
		return boost::endian::little_to_native(value);
	}
};

struct read_rva_string
{
	template <class Image, class Offset, class RtParams>
	static auto read_value(const Image & image, Offset offset, RtParams)
	{
		DWORD string_rva;
		image_do_read(image, offset, sizeof(DWORD), &string_rva);
		boost::endian::little_to_native_inplace(string_rva);

		return image.read_string(VirtualOffset(string_rva));
	}
};

template <typename T, class ReadValue>
struct read_value_as
{
	template <class Image, class Offset, class RtParams>
	static T read_value(const Image & image, Offset offset, const RtParams & rt_params)
	{
		return T(ReadValue::read_value(image, offset, rt_params));
	}
};

template <class ReadValue>
struct read_pointed_value
{
	template <class Image, class Offset, class RtParams>
	static auto read_value(const Image & image, Offset offset, const RtParams & rt_params)
	{
		return PointedValue(offset, ReadValue::read_value(image, offset, rt_params));
	}
};

struct read_section_header
{
	template <class Image, class Offset, class RtParams>
	static SectionHeader read_value(const Image & image, Offset offset, const RtParams &)
	{
		SectionHeader section_header;
		image_do_read(image, offset, sizeof(SectionHeader), &section_header);
		boost::endian::little_to_native_inplace(section_header.virtual_size           );
		boost::endian::little_to_native_inplace(section_header.virtual_address        );
		boost::endian::little_to_native_inplace(section_header.size_of_raw_data       );
		boost::endian::little_to_native_inplace(section_header.pointer_to_raw_data    );
		boost::endian::little_to_native_inplace(section_header.pointer_to_relocations );
		boost::endian::little_to_native_inplace(section_header.pointer_to_line_numbers);
		boost::endian::little_to_native_inplace(section_header.number_of_relocations  );
		boost::endian::little_to_native_inplace(section_header.number_of_line_numbers );
		boost::endian::little_to_native_inplace(section_header.characteristics        );
		return section_header;
	}
};

template <class Param>
struct forward_params_helper;

template <std::size_t I>
struct forward_params_helper<runtime_param<I>>
{
	template <class RtParams>
	static auto forward(RtParams && rt_params)
	{
		return std::get<I>(std::forward<RtParams>(rt_params));
	}
};

template <auto X>
struct forward_params_helper<constexpr_<X>>
{
	template <class RtParams>
	static auto forward(const RtParams &)
	{
		return X;
	}
};

template <class Proxy, typename... Params>
struct read_proxy_object
{
	template <class Image, class Offset, class RtParams>
	static Proxy read_value(const Image & image, Offset offset, const RtParams & rt_params)
	{
		return Proxy { image, offset, forward_params_helper<Params>::forward(rt_params)... };
	}
};

template <typename R, typename T>
using read_pointed_trivial_le_value_as = read_pointed_value <
	read_value_as<R, read_trivial_le_value<T>>
>;

struct read_debug_directory
{
	template <class Image, class Offset, class RtParams>
	static DebugDirectory read_value(const Image & image, Offset offset, const RtParams &)
	{
		DebugDirectory debug_directory;
		image_do_read(image, offset, sizeof(DebugDirectory), &debug_directory);
		boost::endian::little_to_native_inplace(debug_directory.characteristics    );
		boost::endian::little_to_native_inplace(debug_directory.time_date_stamp    );
		boost::endian::little_to_native_inplace(debug_directory.major_version      );
		boost::endian::little_to_native_inplace(debug_directory.minor_version      );
		boost::endian::little_to_native_inplace(debug_directory.type               );
		boost::endian::little_to_native_inplace(debug_directory.size_of_data       );
		boost::endian::little_to_native_inplace(debug_directory.address_of_raw_data);
		boost::endian::little_to_native_inplace(debug_directory.pointer_to_raw_data);
		return debug_directory;
	}
};

template <typename Distance>
struct fixed_distance_advance_pointer_policy;

template <auto Distance>
struct fixed_distance_advance_pointer_policy<constexpr_<Distance>>
{
	template <class Iterator, class Pointer, class RtParams>
	static void advance_pointer(Iterator, Pointer & p, RtParams)
	{
		p += Distance;
	}
};

template <std::size_t I>
struct fixed_distance_advance_pointer_policy<runtime_param<I>>
{
	template <class Iterator, class Pointer, class RtParams>
	static void advance_pointer(Iterator, Pointer & p, RtParams rt_params)
	{
		p += std::get<I>(rt_params);
	}
};

template <typename T>
struct default_value_stop_iteration_policy
{
	template <class Iter, class Ptrdiff, class RtParams>
	static bool is_end_iterator(Iter iter, Ptrdiff, RtParams)
	{
		return *iter == T();
	}
};

template <typename Distance>
struct fixed_distance_stop_iteration_policy;

template <auto Distance>
struct fixed_distance_stop_iteration_policy<constexpr_<Distance>>
{
	template <class Iter, class Ptrdiff, class RtParams>
	static bool is_end_iterator(Iter, Ptrdiff pd, RtParams)
	{
		return pd == Distance;
	}
};

template <std::size_t I>
struct fixed_distance_stop_iteration_policy<runtime_param<I>>
{
	template <class Iterator, class Ptrdiff, class RtParams>
	static bool is_end_iterator(Iterator, Ptrdiff pd, RtParams rt_params)
	{
		return pd == std::get<I>(rt_params);
	}
};

template <class... StopIterationPolicies>
struct either_stop_iteration_policy
{
	template <class Iterator, class Ptrdiff, class RtParams>
	static bool is_end_iterator(Iterator iter, Ptrdiff pd, RtParams rt_params)
	{
		return (StopIterationPolicies::is_end_iterator(iter, pd, rt_params) || ...);
	}
};

template <typename End>
struct condition_stop_iteration_policy;

template <std::size_t I>
struct condition_stop_iteration_policy<runtime_param<I>>
{
	template <class Iterator, class Ptrdiff, class RtParams>
	static bool is_end_iterator(Iterator, Ptrdiff, RtParams rt_params)
	{
		return !std::get<I>(rt_params);
	}
};

struct base_relocation_advance_pointer_policy
{
	template <class Iterator, class Pointer, class RtParams>
	static void advance_pointer(Iterator iter, Pointer & p, RtParams)
	{
		p += iter->size_of_block;
	}
};

}

#endif
#ifndef PEPLUS_DETAIL_FACADES_RUNTIMEFUNCTIONFACADE_HPP_
#define PEPLUS_DETAIL_FACADES_RUNTIMEFUNCTIONFACADE_HPP_

#include <peplus/headers.hpp>
#include <peplus/pointed_value.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_helpers.hpp>

#include <boost/endian/conversion.hpp>

#include <optional>
#include <stdexcept>

namespace peplus::detail {

struct read_unwind_code
{
	template <class Image, class Offset, class RtParams>
	static UnwindCode read_value(const Image & image, Offset offset, const RtParams &)
	{
		UnwindCode unwind_code;
		image.read(offset, sizeof(UnwindCode), &unwind_code);
		boost::endian::little_to_native_inplace(unwind_code.code_offset);
		unwind_code.unwind_op = boost::endian::little_to_native(unwind_code.unwind_op);
		unwind_code.op_info = boost::endian::little_to_native(unwind_code.op_info);
		return unwind_code;
	}
};

template <class Image, class Offset = typename Image::offset_type>
class UnwindInfoFacade : public PointedValue<Offset, UnwindInfo>
{
public:
	using offset_type = Offset;

	template <typename T>
	using Pointed = PointedValue<offset_type, T>;

	using UnwindCodeRange = EntryRange <
		Image, read_pointed_value<read_unwind_code>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(UnwindCode)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>, unsigned int
	>;

	UnwindInfoFacade(const Image & image, offset_type offset);

	UnwindCodeRange codes() const;
	std::optional<Pointed<VirtualOffset>> handler() const;

private:
	const Image * _image;
};

template <class Image>
class RuntimeFunctionFacade : public RuntimeFunction
{
public:
	using offset_type = typename Image::offset_type;

	RuntimeFunctionFacade(const Image & image, offset_type offset);

	UnwindInfoFacade<Image> unwind_info() const;

private:
	const Image * _image;
};

template <class Image, class Offset = typename Image::offset_type>
RuntimeFunction read_runtime_function_from_image(const Image & image, Offset offset)
{
	RuntimeFunction runtime_function;
	image_do_read(image, offset, sizeof(RuntimeFunction), &runtime_function);
	boost::endian::little_to_native_inplace(runtime_function.begin_address);
	boost::endian::little_to_native_inplace(runtime_function.end_address  );
	boost::endian::little_to_native_inplace(runtime_function.unwind_data  );
	return runtime_function;
}

template <class Image, class Offset = typename Image::offset_type>
UnwindInfo read_unwind_info_from_image(const Image & image, Offset offset)
{
	UnwindInfo unwind_info;
	image_do_read(image, offset, sizeof(UnwindInfo), &unwind_info);
	unwind_info.version = boost::endian::little_to_native(unwind_info.version);
	unwind_info.flags = boost::endian::little_to_native(unwind_info.flags);
	boost::endian::little_to_native_inplace(unwind_info.size_of_prolog);
	boost::endian::little_to_native_inplace(unwind_info.count_of_codes);
	unwind_info.frame_register = boost::endian::little_to_native(unwind_info.frame_register);
	unwind_info.frame_offset = boost::endian::little_to_native(unwind_info.frame_offset);
	return unwind_info;
}

template <class Image>
RuntimeFunctionFacade<Image>::RuntimeFunctionFacade(const Image & image, offset_type offset)
	: RuntimeFunction { read_runtime_function_from_image(image, offset) }
	, _image { &image } {}

template <class Image>
UnwindInfoFacade<Image> RuntimeFunctionFacade<Image>::unwind_info() const
{
	const VirtualOffset unwind_info_rva { this->unwind_data };
	const auto unwind_info_offset = to_image_offset(*_image, unwind_info_rva);
	if (!unwind_info_offset)
		throw std::runtime_error("Invalid unwind data offset");

	return UnwindInfoFacade(*_image, *unwind_info_offset);
}

template <class Image, class Offset>
UnwindInfoFacade<Image, Offset>::UnwindInfoFacade(const Image & image, offset_type offset)
	: PointedValue<Offset, UnwindInfo> { offset, read_unwind_info_from_image(image, offset) }
	, _image { &image } {}

template <class Image, class Offset>
auto UnwindInfoFacade<Image, Offset>::codes() const -> UnwindCodeRange
{
	const Offset codes_offset = this->offset() + offsetof(UnwindInfo, unwind_code);
	return UnwindCodeRange(*_image, codes_offset, this->count_of_codes);
}

template <class Image, class Offset>
auto UnwindInfoFacade<Image, Offset>::handler() const -> std::optional<Pointed<VirtualOffset>>
{
	if ((this->flags & UNW_FLAG_CHAININFO) != 0) return std::nullopt;
	if ((this->flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) == 0) return std::nullopt;

	const Offset codes_offset = this->offset() + offsetof(UnwindInfo, unwind_code);
	const Offset data_offset = codes_offset + this->count_of_codes * sizeof(UnwindCode);

	unsigned long handler;
	image_do_read(*_image, data_offset, sizeof(unsigned long), &handler);
	const VirtualOffset handler_rva { boost::endian::little_to_native(handler) };
	return Pointed<VirtualOffset>(data_offset, handler_rva);
}

}

#endif

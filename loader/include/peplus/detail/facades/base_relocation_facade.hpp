#ifndef PEPLUS_DETAIL_FACADES_BASERELOCATIONFACADE_HPP_
#define PEPLUS_DETAIL_FACADES_BASERELOCATIONFACADE_HPP_

#include <peplus/headers.hpp>
#include <peplus/detail/entry_range.hpp>
#include <peplus/detail/image_helpers.hpp>
#include <peplus/detail/image_offset.hpp>
#include <peplus/detail/transform_range.hpp>

#include <boost/endian/conversion.hpp>

#include <tuple>

namespace peplus::detail {

struct RelocationEntry
{
	WORD          type;
	VirtualOffset address;
};

class rel_type_offset_to_relocation_entry_transformer
{
public:
	explicit rel_type_offset_to_relocation_entry_transformer(VirtualOffset relbase)
		: _base_rva { relbase } {}

	RelocationEntry operator()(WORD type_offset) const
	{
		RelocationEntry relocation_entry;
		const auto reloc_offset = type_offset & ((2 << 12) - 1);
		relocation_entry.address = _base_rva + reloc_offset;
		relocation_entry.type = (type_offset & ((2 << 4) - 1)) >> 12;
		return relocation_entry;
	}

private:
	VirtualOffset _base_rva;
};

template <class Image, class Offset = typename Image::offset_type>
class BaseRelocationFacade : public PointedValue<Offset, BaseRelocation>
{
public:
	using offset_type = Offset;

	using RelTypeOffsetRange = EntryRange <
		Image, read_pointed_value<read_trivial_le_value<WORD>>,
		fixed_distance_advance_pointer_policy<constexpr_<sizeof(WORD)>>,
		fixed_distance_stop_iteration_policy<runtime_param<0>>,
		std::size_t
	>;

	using RelocationEntryRange = TransformRange <
		rel_type_offset_to_relocation_entry_transformer,
		RelTypeOffsetRange
	>;

	BaseRelocationFacade(const Image & image, offset_type offset);

	RelocationEntryRange entries() const;

private:
	RelTypeOffsetRange type_offsets() const;

	const Image * _image;
};

template <class Image, class Offset = typename Image::offset_type>
BaseRelocation read_base_relocation_from_image(const Image & image, Offset offset)
{
	BaseRelocation base_relocation;
	image_do_read(image, offset, sizeof(BaseRelocation), &base_relocation);
	boost::endian::little_to_native_inplace(base_relocation.virtual_address);
	boost::endian::little_to_native_inplace(base_relocation.size_of_block  );
	return base_relocation;
}

template <class Image, class Offset>
BaseRelocationFacade<Image, Offset>::BaseRelocationFacade(const Image & image, offset_type offset)
	: PointedValue<Offset, BaseRelocation> { offset, read_base_relocation_from_image(image, offset) }
	, _image { &image } {}

template <class Image, class Offset>
auto BaseRelocationFacade<Image, Offset>::entries() const -> RelocationEntryRange
{
	const VirtualOffset reloc_base { this->virtual_address };
	rel_type_offset_to_relocation_entry_transformer to_relocation_entries { reloc_base };
	return RelocationEntryRange(type_offsets(), std::move(to_relocation_entries));
}

template <class Image, class Offset>
auto BaseRelocationFacade<Image, Offset>::type_offsets() const -> RelTypeOffsetRange
{
	const offset_type reltypes_offset = this->offset() + offsetof(BaseRelocation, type_offset);
	const std::size_t reltypes_size = this->size_of_block - offsetof(BaseRelocation, type_offset);
	return RelTypeOffsetRange(*_image, reltypes_offset, reltypes_size);
}

}

#endif

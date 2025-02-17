#ifndef PEPLUS_DETAIL_ENTRYRANGE_HPP_
#define PEPLUS_DETAIL_ENTRYRANGE_HPP_

#include <boost/operators.hpp>
#include <boost/iterator/iterator_facade.hpp>

#include <optional>
#include <tuple>
#include <utility>
#include <type_traits>

namespace peplus::detail {

template <
	class Image, class ReadValuePolicy, class AdvancePointerPolicy,
	class StopIterationPolicy, typename... RuntimeParams
>
class EntryRange
{
public:
	using offset_type = typename Image::offset_type;

	using value_type = decltype(ReadValuePolicy::template read_value(
		std::declval<const Image &>(), offset_type(0),
		std::declval<const std::tuple<RuntimeParams...> &>()
	));

	class iterator : public boost::iterator_facade < iterator, value_type,
	                                                 boost::single_pass_traversal_tag >
	{
	public:
		friend class end_iterator;
		friend class boost::iterator_core_access;

		explicit iterator(const EntryRange & entry_range);

	private:
		void increment();
		value_type & dereference() const;
		bool equal(const iterator & other) const;

		const EntryRange * _entry_range;
		offset_type        _offset;
	};

	class end_iterator : private boost::equality_comparable<end_iterator, iterator>
	{
	public:
		bool operator ==(const iterator & iter) const;
	};

	using const_iterator = iterator;

	template <typename... Params>
	explicit EntryRange(const Image & image, offset_type offset, Params && ...params);

	iterator begin() const;
	end_iterator end() const;

	explicit operator bool() const;

private:
	const Image                       * _image;
	offset_type                         _begin_offset;
	std::tuple<RuntimeParams...>        _rt_params;
	mutable std::optional<value_type>   _entry_value;
};

template <class Image, class RVP, class APP, class SIP, typename... RP>
EntryRange<Image, RVP, APP, SIP, RP...>::iterator::iterator(const EntryRange & entry_range)
	: _entry_range { &entry_range }, _offset { entry_range._begin_offset } {}

template <class Image, class RVP, class APP, class SIP, typename... RP>
void EntryRange<Image, RVP, APP, SIP, RP...>::iterator::increment()
{
	APP::template advance_pointer(*this, _offset, _entry_range->_rt_params);
	_entry_range->_entry_value = std::nullopt;
}

template <class Image, class RVP, class APP, class SIP, typename... RP>
auto EntryRange<Image, RVP, APP, SIP, RP...>::iterator::dereference() const -> value_type &
{
	auto & entry_value = _entry_range->_entry_value;
	if (!entry_value)
		entry_value = RVP::template read_value(*_entry_range->_image, _offset, _entry_range->_rt_params);
	return *entry_value;
}

template <class Image, class RVP, class APP, class SIP, typename... RP>
bool EntryRange<Image, RVP, APP, SIP, RP...>::iterator::equal(const iterator & other) const
{
	return _offset == other._offset;
}

template <class Image, class RVP, class APP, class SIP, typename... RP>
bool EntryRange<Image, RVP, APP, SIP, RP...>::end_iterator::operator ==(const iterator & iter) const
{
	const EntryRange & entry_range = *iter._entry_range;
	const std::size_t pdiff = (iter._offset - entry_range._begin_offset).value();
	return SIP::template is_end_iterator(iter, pdiff, entry_range._rt_params);
}

template <class Image, class RVP, class APP, class SIP, typename... RP> template <typename... Params>
EntryRange<Image, RVP, APP, SIP, RP...>::EntryRange(const Image & image, offset_type offset, Params &&... params)
	: _image { &image }, _begin_offset { offset }, _rt_params { std::forward<Params>(params)... } {}

template <class Image, class RVP, class APP, class SIP, typename... RP>
auto EntryRange<Image, RVP, APP, SIP, RP...>::begin() const -> iterator
{
	return iterator(*this);
}

template <class Image, class RVP, class APP, class SIP, typename... RP>
auto EntryRange<Image, RVP, APP, SIP, RP...>::end() const -> end_iterator
{
	return end_iterator();
}

template <class Image, class RVP, class APP, class SIP, typename ...RP>
EntryRange<Image, RVP, APP, SIP, RP...>::operator bool() const
{
	return begin() != end();
}

}

#endif
#ifndef PEPLUS_DETAIL_TRANSFORMRANGE_HPP_
#define PEPLUS_DETAIL_TRANSFORMRANGE_HPP_

#include <boost/operators.hpp>
#include <boost/iterator/iterator_facade.hpp>

#include <functional>
#include <iterator>
#include <optional>
#include <utility>

namespace peplus::detail {

template <class Fn, class Range>
class TransformRange
{
public:
	using range_iterator = decltype(std::declval<const Range>().begin());
	using range_end_iterator = decltype(std::declval<const Range>().end());

	using value_type = std::invoke_result_t <
		Fn, typename std::iterator_traits<range_iterator>::value_type
	>;

	class iterator : public boost::iterator_facade < iterator, const value_type,
	                                                 boost::single_pass_traversal_tag >
	{
	public:
		friend class end_iterator;
		friend class boost::iterator_core_access;

		explicit iterator(const TransformRange & range, range_iterator iter);

	private:
		void increment();
		bool equal(iterator other) const;
		const value_type & dereference() const;

		const TransformRange * _transform_range;
		range_iterator         _iter;
	};

	class end_iterator
		: private boost::equality_comparable<end_iterator, iterator>
	{
	public:
		explicit end_iterator(range_end_iterator end_iter);

		bool operator ==(iterator iter) const;

	private:
		range_end_iterator _end_iter;
	};

	TransformRange(Range range, Fn fn);

	iterator begin() const;
	end_iterator end() const;

private:
	Range                             _range;
	Fn                                _fn;
	mutable std::optional<value_type> _result;
};

template <class Fn, class Range>
TransformRange<Fn, Range>::iterator::iterator(const TransformRange & range, range_iterator iter)
	: _transform_range { &range }, _iter { iter } {}

template <class Fn, class Range>
void TransformRange<Fn, Range>::iterator::increment()
{
	_transform_range->_result = std::nullopt;
	++_iter;
}

template <class Fn, class Range>
bool TransformRange<Fn, Range>::iterator::equal(iterator other) const
{
	return _iter == other._iter;
}

template <class Fn, class Range>
auto TransformRange<Fn, Range>::iterator::dereference() const -> const value_type &
{
	auto & result_value = _transform_range->_result;
	if (!result_value)
		result_value = _transform_range->_fn(*_iter);
	return *result_value;
}

template <class Fn, class Range>
TransformRange<Fn, Range>::end_iterator::end_iterator(range_end_iterator end_iter)
	: _end_iter { end_iter } {}

template <class Fn, class Range>
bool TransformRange<Fn, Range>::end_iterator::operator ==(iterator iter) const
{
	return _end_iter == iter._iter;
}

template <class Fn, class Range>
TransformRange<Fn, Range>::TransformRange(Range range, Fn fn)
	: _range { std::move(range) }, _fn { std::move(fn) } {}

template <class Fn, class Range>
auto TransformRange<Fn, Range>::begin() const -> iterator
{
	return iterator { *this, _range.begin() };
}

template <class Fn, class Range>
auto TransformRange<Fn, Range>::end() const -> end_iterator
{
	return end_iterator { _range.end() };
}

}

#endif
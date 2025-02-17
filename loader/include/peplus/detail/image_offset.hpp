#ifndef PEPLUS_DETAIL_IMAGEOFFSET_HPP_
#define PEPLUS_DETAIL_IMAGEOFFSET_HPP_

#include <boost/operators.hpp>

#include <cstddef>
#include <iostream>

namespace peplus::detail {

template <class Tag>
class ImageOffset : boost::additive<ImageOffset<Tag>>
                  , boost::unit_steppable<ImageOffset<Tag>>
                  , boost::partially_ordered<ImageOffset<Tag>>
                  , boost::additive<ImageOffset<Tag>, std::ptrdiff_t>
{
public:
	constexpr ImageOffset() = default;
	explicit constexpr ImageOffset(std::ptrdiff_t value);

	constexpr ImageOffset & operator ++();
	constexpr ImageOffset & operator --();

	constexpr ImageOffset & operator +=(ImageOffset rhs);
	constexpr ImageOffset & operator -=(ImageOffset rhs);

	constexpr ImageOffset & operator +=(std::ptrdiff_t rhs);
	constexpr ImageOffset & operator -=(std::ptrdiff_t rhs);

	constexpr bool operator <(ImageOffset rhs) const;
	constexpr bool operator ==(ImageOffset rhs) const;

	constexpr std::ptrdiff_t value() const;

	template <class Tag2>
	friend std::ostream & operator <<(std::ostream & os, ImageOffset<Tag2> offset);

private:
	std::ptrdiff_t _value;
};

using FileOffset = ImageOffset<class file_offset_tag>;
using VirtualOffset = ImageOffset<class virtual_offset_tag>;

inline namespace literals { inline namespace offset_literals {

constexpr FileOffset operator ""_offs(unsigned long long value)
{
	return FileOffset(static_cast<std::ptrdiff_t>(value));
}

constexpr VirtualOffset operator ""_rva(unsigned long long value)
{
	return VirtualOffset(static_cast<std::ptrdiff_t>(value));
}

} }

template <class Tag>
constexpr ImageOffset<Tag>::ImageOffset(std::ptrdiff_t value)
	: _value { value } {}

template <class Tag>
constexpr ImageOffset<Tag> & ImageOffset<Tag>::operator ++()
{
	++_value;
	return *this;
}

template <class Tag>
constexpr ImageOffset<Tag> & ImageOffset<Tag>::operator --()
{
	--_value;
	return *this;
}

template <class Tag>
constexpr ImageOffset<Tag> & ImageOffset<Tag>::operator +=(ImageOffset rhs)
{
	_value += rhs._value;
	return *this;
}

template <class Tag>
constexpr ImageOffset<Tag> & ImageOffset<Tag>::operator -=(ImageOffset rhs)
{
	_value -= rhs._value;
	return *this;
}

template <class Tag>
constexpr ImageOffset<Tag> & ImageOffset<Tag>::operator +=(std::ptrdiff_t rhs)
{
	_value += rhs;
	return *this;
}

template <class Tag>
constexpr ImageOffset<Tag> & ImageOffset<Tag>::operator -=(std::ptrdiff_t rhs)
{
	_value -= rhs;
	return *this;
}

template <class Tag>
constexpr bool ImageOffset<Tag>::operator <(ImageOffset rhs) const
{
	return _value < rhs._value;
}

template <class Tag>
constexpr bool ImageOffset<Tag>::operator ==(ImageOffset rhs) const
{
	return _value == rhs._value;
}

template <class Tag>
constexpr std::ptrdiff_t ImageOffset<Tag>::value() const
{
	return _value;
}

template <class Tag>
std::ostream & operator <<(std::ostream & os, ImageOffset<Tag> offset)
{
	return os << offset._value;
}

}

#endif
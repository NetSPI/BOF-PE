#ifndef PEPLUS_POINTEDVALUE_HPP_
#define PEPLUS_POINTEDVALUE_HPP_

#include <type_traits>
#include <utility>

namespace peplus {

template <class Offset, class T, typename = void>
class PointedValue : public T
{
public:
	PointedValue() = default;

	PointedValue(Offset offset, T value)
		: T { std::move(value) }, _offset { offset }
	{}

	constexpr Offset offset() const
	{
		return _offset;
	}

private:
	Offset _offset;
};

template <class Offset, typename T>
class PointedValue<Offset, T, std::enable_if_t<std::is_integral_v<T>>>
{
public:
	constexpr PointedValue() = default;

	constexpr PointedValue(Offset offset, T value)
		: _value  { value  }, _offset { offset }
	{}

	constexpr operator T() const
	{
		return _value;
	}

	constexpr Offset offset() const
	{
		return _offset;
	}

private:
	T      _value;
	Offset _offset;
};

}

#endif
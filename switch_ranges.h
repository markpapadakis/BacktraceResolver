#pragma once
// range is (Start():inclusive ... End():exclusive)
// i.e [left, right)
template<typename VT = uint32_t, typename LT = uint32_t>
struct range_base
{
	struct iterator
	{
		VT i;

		iterator(const VT index)
			: i{index}
		{

		}

		VT inline operator*(void) const
		{
			return i;
		}

		void operator++(void)
		{
			++i;
		}

		bool operator!=(const iterator &o) const
		{
			return i != o.i;
		}
	};

	VT offset;
	LT len;

	iterator begin(void) const
	{
		return iterator(offset);
	}

	iterator end(void) const
	{
		return iterator(End());
	}

	static inline int byOffsetAsc(const range_base &r1, const range_base &r2)
	{
		if (const auto d = TrivialCmp(r1.Start(), r2.Start()))
			return d;
		else
			return TrivialCmp(r1.len, r2.len);
	}

	range_base(void)
		: offset(0), len(0)
	{

	}

	range_base(const range_base &o)
		: offset(o.offset), len(o.len)
	{

	}

	range_base(const VT _o, const LT _l)
		: offset(_o), len(_l)
	{

	}

	[[gnu::always_inline]] inline constexpr operator bool(void) const
	{
		return len;
	}

	[[gnu::always_inline]] inline bool SpansAll(void) const
	{
		return std::numeric_limits<VT>::min() == offset && std::numeric_limits<VT>::max() == End();
	}

	void SetSpansAll(void)
	{
		offset 	= std::numeric_limits<VT>::min();
		len 	= std::numeric_limits<VT>::max() - offset;
	}

	inline void Set(const VT _o, const LT _l)
	{
		offset 	= _o;
		len 	= _l;
	}

	range_base &operator=(const range_base &o)
	{
		offset 	= o.offset;
		len 	= o.len;
		return *this;
	}

	void SetEnd(const VT e)
	{
		len = e - offset;
	}

	[[gnu::always_inline]] inline VT constexpr Mid(void) const 	// (left + right) / 2
	{
		return offset + (len >> 1);
	}

	[[gnu::always_inline]] inline VT constexpr End(void) const
	{
		return offset + len;
	}

	[[gnu::always_inline]] inline VT constexpr Left(void) const
	{
		return offset;
	}

	[[gnu::always_inline]] inline VT constexpr Right(void) const
	{
		return End();
	}

	[[gnu::always_inline]] inline VT constexpr Start(void) const
	{
		return offset;
	}

	range_base<VT, LT> ClippedTo(const VT lim) const
	{
		range_base<VT, LT> res;

		res.offset 	= Min(offset, lim);
		res.len 	= Min(End(), lim) - res.offset;

		return res;
	}

	[[gnu::always_inline]] inline bool constexpr Contains(const VT o) const
	{
		return sizeof(VT) == 8
			? o >= offset && o < End()
			: uint32_t(o - offset) < len; 	// o in [offset, offset+len)
	}

        [[gnu::always_inline]] inline bool constexpr operator<(const range_base &o) const
        {
                return offset < o.offset || (offset == o.offset && len < o.len);
        }
        
        [[gnu::always_inline]] inline bool constexpr operator<=(const range_base &o) const
        {
                return offset < o.offset || (offset == o.offset && len <= o.len);
        }
        
        [[gnu::always_inline]] inline bool operator>(const range_base &o) const
        {       
                return offset > o.offset || (offset == o.offset && len > o.len);
        }               

        [[gnu::always_inline]] inline bool constexpr operator>=(const range_base &o) const
        {               
                return offset > o.offset || (offset == o.offset && len >= o.len);
        }


	template<typename T>
	[[gnu::always_inline]] inline bool constexpr operator==(const T &o) const
	{
		return offset == o.offset && len == o.len;
	}

	template<typename T>
	[[gnu::always_inline]] inline bool constexpr operator!=(const T &o) const
	{
		return offset != o.offset || len != o.len;
	}

	range_base Intersection(const range_base &o) const
	{
		// A range containing the indices that exist in both ranges

		if (End() <= o.offset || o.End() <= offset)
			return range_base(0, 0);
		else
		{
			const auto _o = Max(offset, o.offset);

			return range_base(_o, Min(End(), o.End()) - _o);
		}
	}

	void ClipOffsetTo(const VT o)
	{
		if (offset < o)
		{
			if (o >= End())
			{
				offset = o;
				len 	= 0;
			}
			else
			{
				const auto d = o - offset;

				offset = o;
				len -= d;
			}
		}
	}

	void ClipEndTo(const VT e)
	{
		const auto end = End();

		if (e < end)
		{
			if (e < offset)
				len = 0;
			else	
				len -= end - e;
		}
	}

	[[gnu::always_inline]] inline bool constexpr Overlaps(const range_base &o) const
	{
		// range is (Start() inclusive, End() non inclusive)
		// e.g [start, end)
		//
		// alternative formula: a0 <= b1 && b0 <= a1
		// https://fgiesen.wordpress.com/2011/10/16/checking-for-interval-overlap/
		return !(End() <= o.offset || o.End() <= offset);
	}

	[[gnu::always_inline]] inline bool constexpr Contains(const range_base &o) const
	{
		return offset <= o.offset && End() >= o.End();
	}

	range_base Union(const range_base &o) const
	{
		const auto _o = Min(offset, o.offset);

		return range_base(_o, Max(End(), o.End()) - _o);
	}

	// http://en.wikipedia.org/wiki/Disjoint_union
	// Make sure they overlap
	uint8_t DisjointUnion(const range_base &o, range_base *out) const
	{
		const range_base *const b = out;

		if (offset < o.offset)
		{
			out->offset 	= offset;
			out->len 	= o.offset - offset;
			++out;
		}
		else if (o.offset < offset)
		{
			out->offset 	= o.offset;
			out->len  	= offset - o.offset;
			++out;
		}

		const auto thisEnd = End(), thatEnd = o.End();

		if (thisEnd < thatEnd)
		{
			out->offset 	= thisEnd;
			out->len 	= thatEnd - thisEnd;
			++out;
			
		}
		else if (thatEnd < thisEnd)
		{
			out->offset 	= thatEnd;
			out->len 	= thisEnd - thatEnd;
			++out;
		}

		return out - b;
	}

	void TrimLeft(const LT span)
	{
		offset+=span;
		len-=span;
	}
		

	void Unset(void)
	{
		offset = 0;
		len = 0;
	}
};


template<typename VT>
static inline bool IsBetweenRange(const VT v, const VT s, const VT e)
{
	return sizeof(VT) == 8
		? v >= s && v < e
		: uint32_t(v - s) < (e - s); 	// o in [offset, offset+len)
};

template<typename VT>
static inline bool IsBetweenRangeInclusive(const VT v, const VT s, const VT e)
{
	return sizeof(VT) == 8
		? v >= s && v <= e
		: uint32_t(v - s) <= (e - s); 	// o in [offset, offset+len]
};

template<typename VT = uint32_t, typename LT = uint32_t>
static inline uint32_t HashFor(const range_base<VT, LT> &r)
{
	return SwitchHash(&r, sizeof(r));
}

using range8_t = range_base<uint8_t, uint8_t>;
using range16_t = range_base<uint16_t, uint16_t>;
using range32_t = range_base<uint32_t, uint32_t>;
using range64_t = range_base<uint64_t, uint64_t>;
using rangestr_t = range_base<const char *, uint32_t>; // Please ust strwlen instead

template<typename VT, typename LT>
static inline auto MakeRange(const VT s, const LT l) -> range_base<VT, LT>
{
	return {s, l};
}

namespace Switch
{
	template<typename VT, typename LT>
	static inline auto make_range(const VT s, const LT l)
	{
		return range_base<VT, LT>(s, l);
	}
}

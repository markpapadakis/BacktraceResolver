#pragma once
#include "switch.h"

namespace SwitchBitOps
{
        template <typename T>
        struct Bitmap
        {
                static_assert(std::numeric_limits<T>::is_integer, "T must be an integer");
                static_assert(!std::numeric_limits<T>::is_signed, "T must be an unsigned integer");

                static auto anySet(const T *const bm, const uint32_t n /* in Ts, not in bits */)
                {
                        for (uint32_t i{0}; i != n; ++i)
                        {
                                if (bm[i])
                                        return true;
                        }
                        return false;
                }

                static inline void Set(T *const bm, const uint32_t index)
                {
                        const auto i = index / (sizeof(T) << 3);
                        const T mask = (T)1U << (index & ((sizeof(T) * 8) - 1));

                        bm[i] |= mask;
                }

                static inline void Toggle(T *const bm, const uint32_t index)
                {
                        const auto i = index / (sizeof(T) << 3);
                        const T mask = (T)1U << (index & ((sizeof(T) * 8) - 1));

                        bm[i] ^= mask;
                }

                static inline bool SetIfUnset(T *const bm, const uint32_t index)
                {
                        const auto i = index / (sizeof(T) << 3);
                        const T mask = (T)1U << (index & ((sizeof(T) * 8) - 1));
                        auto &v = bm[i];

                        if (v & mask)
                                return false;
                        else
                        {
                                v |= mask;
                                return true;
                        }
                }

                static inline void Unset(T *const bm, const uint32_t index)
                {
                        const auto i = index / (sizeof(T) << 3);
                        const T mask = (T)1U << (index & ((sizeof(T) * 8) - 1));

                        bm[i] &= ~mask;
                }

                static inline bool IsSet(T *const bm, const uint32_t index)
                {
                        const auto i = index / (sizeof(T) << 3);
                        const T mask = (T)1U << (index & ((sizeof(T) * 8) - 1));

                        return bm[i] & mask;
                }
        };
}

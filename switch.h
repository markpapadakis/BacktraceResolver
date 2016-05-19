#pragma once
#include <stdint.h>
#include <ctype.h>
#include <type_traits>
#include <unistd.h>
#include <assert.h>

namespace detail
{
        template <typename T, size_t N>
        char(&SIZEOF_ARRAY_REQUIRES_ARRAY_ARGUMENT(T(&)[N]))[N];
}

#define sizeof_array(x) sizeof(detail::SIZEOF_ARRAY_REQUIRES_ARRAY_ARGUMENT(x))

#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#include "switch_common.h"
#include "switch_ranges.h"

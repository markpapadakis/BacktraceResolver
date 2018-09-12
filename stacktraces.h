#pragma once

#ifdef SWITCH_PHAISTOS
#include <switch.h>
#else
// Not using Phaistos's Switch
#include <cstdint>
#include <cstddef>
#include <cstring>
struct str_view32 {
        const char *p;
        size_t      len;

        str_view32(const char *ptr, const size_t l)
            : p{ptr}, len{l} {
        }

        str_view32(const char *ptr)
            : p{ptr}, len(ptr ? strlen(ptr) : 0) {
        }

        str_view32()
            : p{nullptr}, len{0} {
        }

        void set(const char *ptr, const size_t l) {
                p   = ptr;
                len = l;
        }

        void set(const char *ptr) {
                p   = ptr;
                len = ptr ? strlen(ptr) : 0;
        }

        inline bool operator==(const str_view32 &o) const noexcept {
                return len == o.len && !memcmp(p, o.p, len);
        }

        auto CopyTo(char *out) {
                memcpy(out, p, len);
                return out += len;
        }

        operator bool() const noexcept {
                return len;
        }

        void reset() {
                p   = nullptr;
                len = 0;
        }

        auto size() const noexcept {
                return len;
        }

        const char *data() const noexcept {
                return p;
        }

        inline bool Eq(const char *ptr, const size_t l) const noexcept {
                return l == len && !memcmp(ptr, p, l);
        }
};

#define _S(p) (p), static_cast<uint32_t>(sizeof(p) - 1)

template <typename T>
static inline T decode_pod(const uint8_t *&p) noexcept {
        const auto res = *(T *)p;

        p += sizeof(T);
        return res;
}

namespace std {
        namespace detail {
                template <typename T, size_t N>
                char (&SIZEOF_ARRAY_REQUIRES_ARRAY_ARGUMENT(T (&)[N]))[N];
        }
} // namespace std

#define sizeof_array(x) sizeof(std::detail::SIZEOF_ARRAY_REQUIRES_ARRAY_ARGUMENT(x))

template <typename VT = uint32_t, typename LT = uint32_t>
struct range_base final {
        using value_type  = VT;
        using length_type = LT;

        VT offset;
        LT len;

	range_base()
		: offset{0}, len{0} {

	}

        constexpr bool Contains(const VT o) const noexcept {
                return sizeof(VT) == 8
                           ? o >= offset && o < stop()
                           : uint32_t(o - offset) < len; // o in [offset, offset+len)
        }

        constexpr void set(const VT _o, const LT _l) noexcept {
                offset = _o;
                len    = _l;
        }

        constexpr VT stop() const noexcept {
                return offset + len;
        }

        constexpr range_base(const range_base &o)
            : offset(o.offset), len(o.len) {
        }

        constexpr range_base(const VT _o, const LT _l)
            : offset(_o), len(_l) {
        }

        constexpr operator bool() const noexcept {
                return len;
        }

        constexpr auto size() const noexcept {
                return len;
        }

        constexpr auto empty() const noexcept {
                return 0 == len;
        }
};

using range8_t  = range_base<uint8_t, uint8_t>;
using range16_t = range_base<uint16_t, uint16_t>;
using range32_t = range_base<uint32_t, uint32_t>;
using range64_t = range_base<uint64_t, uint64_t>;
#endif

namespace Switch {
        enum StackResolverErrors : int {
                OutOfMemory = 1,
                Sys,
                UnexpectedStruct,
                NoSupport,
        };

        struct stack_frame final {
                size_t     line;
                size_t     column;
                str_view32 filename;
                str_view32 func;
        };

        int stacktrace(void **frames, const size_t depth, stack_frame *out, const size_t stack_frames_capacity, uint8_t *storage, size_t storage_size);

        int stacktrace(stack_frame *out, const size_t stack_frames_capacity, uint8_t *storage, const size_t storage_size);
} // namespace Switch

// according to bactrace (3), it makes some assumptions about how a functions' return address is stored on the stack. Note the following
// - Omission of the frame pointers (as implied by any of compiler's nonzero optimization levels) may cause these assumptions to be violated
// - Inlined functions do not have stack frames
// - Tail-call optimization causes on stack frame to replace another
// 	> -foptimize-sibling-calls (Optimize sibling and tail recurisve calls, enabled at levels -O2, -O3, -Os)
// 	> -fno-optimize-sibling-calls disables it
//
// According to https://code.google.com/p/google-glog/source/browse/trunk/INSTALL
// > If you link binaries statically, make sure you add
// > -Wl,--eh-frame-hdr to your linker options.
//
// Also, according to GCC's man page
// > Starting with GCC version 4.6, the default setting (when not optimizing for size) for 32-bit GNU/Linux x86 and 32-bit Darwin x86 targets 
// > has been changed to -fomit-frame-pointer.  The default can be reverted to -fno-omit-frame-pointer by configuring GCC with 
// > the --enable-frame-pointer configure option.
#pragma once
#include "switch.h"
#include "switch_mallocators.h"
#include <execinfo.h>

namespace Switch
{
        namespace Stacktraces
        {
                enum class FuncType : uint8_t
                {
                        Inline = 0,
                        Func,
                        Entry,
                        Unknown
                };

                struct Frame
                {
                        strwlen32_t fileName;
                        strwlen32_t funcName;
                        FuncType funcType;
                        uint32_t line;
			uint32_t declLine; // may be come in handy
                };

		int32_t captureFrames(void **PCs, size_t pcsCnt, simple_allocator &, Frame *const framesOut, const size_t maxFrames);
        }
}

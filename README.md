This is very fast stacktraces resolver for x86-64(possibly working on i386 architecture as well, but hasn't been tested on it).
This is a new major release that fixes all outstanding issues with the older implementation. It comes with a new design and implements new heuristics for even faster stacktraces generation.

There are no dependencies on any non-standard, external libraries (e.g it does not depend on binutils libBFD, which is what most other such implementations rely on). LibBFD is very powerful, but it always allocates memory and is not very fast.

For example, if you are interested in the first 4 frames and those frames belong to the same DSO, it can take as little as 400us to generate the stacktrace.

# Features Include
- High performance stacktraces generation
- Accurate resolution: inline functions source code resolution works as expected
- Very memory efficient: it does not allocate any memory on the heap, which makes it ideal for memory-constrained environments and execution contexts(see below)
- Simple to use: it is implemented in a single module(stacktraces.cpp), and all you need to use is #include "stacktraces.h" and link against stacktraces.cpp

# Memory Contraints
While the resolver does not allocate memory on the heap, if you are going to use backtrace(), you should know that that it always allocates memory.
There are alternative means to walking the stack (I mean to provide one such function soon -- it's a simple matter of looking into EBP, etc), but for now
know that if you plan to use the resolver in the context of a signal handlerr that may not allocate memory, backtrace() may be unsuitable for that purpose.
Furthermore, `abi::__cxa_demangle()` also allocates memory; an alternative will be implemented soon.


# Installing
1. You need libdward include files for the various definitions/macros.

```bash
apt-get install -y libdwarf-dev
```

2. Copy stacktraces.{h,cpp} somewhere so that you can access it later. You may also want to build a library out of it(e.g `ar rcs libstacktraces.a stacktraces.o`)


# Using the Resolver
```cpp
#include "stacktraces.h"
#include <cstdio>

void fun_with_stacks() {
        // provide a buffer allocated on the stack for stacktrace()
        // you could also use e.g
        // auto stacktrace_buf = reinterpret_cast<uint8_t *>(alloca(128 * 1024));
        uint8_t             stacktrace_buf[128 * 1024];
        Switch::stack_frame frames[4];
        const auto          frames_cnt = Switch::stacktrace(frames, sizeof(frames) / sizeof(frames[0]), stacktrace_buf, sizeof(stacktrace_buf));

        if (frames_cnt < 0) {
                // check Switch::StackResolverErrors
        } else {
                for (int i{0}; i < frames_cnt; ++i) {
                        const auto &frame = frames[i];

                        if (frame.filename) {
                                // we were able to resolve the filename (or the dso/dll library path)
                                if (frame.func) {
                                        // we were able to resolve the function name
                                        if (frame.line) {
                                                // line number was also resolved
                                                std::printf(R"(%.*s at %.*s:%zu)" "\n", static_cast<int>(frame.func.size()), frame.func.data(), static_cast<int>(frame.filename.size()), frame.filename.data(), frame.line);
                                        } else {
                                                std::printf(R"(%.*s at %.*s:??)" "\n", static_cast<int>(frame.func.size()), frame.func.data(), static_cast<int>(frame.filename.size()), frame.filename.data());
                                        }
                                } else {
                                        std::printf(R"(?? at %.*s:??)" "\n", static_cast<int>(frame.filename.size()), frame.filename.data());
                                }
                        } else {
                                std::printf(R"(??)" "\n");
                        }
                }
        }
}

int main(int argc, char *argv[]) {
        fun_with_stacks();
        return 0;
}
```

```bash
clang++ -std=c++1z example.cpp stacktraces.cpp -ldl
```


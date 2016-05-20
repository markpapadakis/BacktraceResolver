This is a very fast backtrace resolver for the x86-64 architecture, although it probably works fine on i386, although it hasn't been put to the test.

It does not require any external non-standard libraries (in particular, binutils libBFD, which is what most alternative implementations use, including the various binutils programs, gdb, etc). 
LibBFD is very powerful, but it always allocate memory and it's not very fast, and this contradicts with the two main goals of this small project:

1. High Performance
2. No memory allocations(interface with the allocator)

[We](http://phaistosnetworks.gr) need to generate backtraces very often, and our previous implementation which was based on libBFD would often take upto 0.5 seconds to resolve a stack trace, which was very high. 
This resolver takes about 10ms to do that, so generating and resolving backtraces becomes very cheap.

Furthermore, we need to generate and resolve backtraces in the execution context of signal handlers. 
The problem with that is that if the handler's configured for e.g an abort signal, and e.g a SIGSEGV is raised within the allocator exec. context (where a lock is usually held), and your resolver also needs to allocate memory in the handler, then it will deadlock because of the allocator lock is already held and won't be released.
We have had a few such situations, and making sure the resolver does not allocate any memory at all, and thus not having to interface with the allocator, become an important feature.

It supports inline functions, although currently it may not be able to properly identify the line or file because apparently the information required to trace that is not encoded in any of the ELF DWARF sections, but I will look into alternative ideas and will update the repo when I come up with a different strategy that yields better results.

It hasn't been tested thoroughly (this is 2 day's worth of work), and it may not be able to always accurately resolve a backtrace, but, again, if I find any issues, I will try to find sometime to improve it and will update this repo accordingly. If you use it and find any issues, please open a GH issue and describe the problem.

This is probably the fastest backtrace resolver  - at least from what I 'vee seen on GH, and one of the very few that does not rely on libBFD and other unwind libraries to accomplish the task. There's still room for improvements, and I expect performance to improve further in future updates.

`Switch` is our core library - hence the name. It comes from the Matrix films ([Switch was a character in the first movie](http://matrix.wikia.com/wiki/Switch)). 
The various switch files found are from our Switch library repository, albeit stripped down so that only what's required for this project is there.


### Allocations
Unfortunately, `backtrace()` and `abi::__cxa_demangle()` both may allocate memory(a few bytes each). 
In practice this will not be a problem, but because they are the only real functions that may interface with the allocator in the exec. context of a signal handler function, I will probably implement alternatives to both of them that do not require any allocations and will update the repo when that's in.


### Setup
This is a C++ project, because C++ is my language of choice and the language we use for our projects, but it should be pretty trivial to 'port' this to C.

```
clang++ -Wall -std=c++14 switch_stacktraces.cpp  -c -O3 -funroll-loops  && ar rc libbtresolve.a switch_stacktraces.o
```

### Use
Make sure you `#include <switch_stacktraces.h>` and you link against libbtresolve and libdl  (i.e `-lbtresolve -ldl`). 

You can use it like so:

```cpp
void *trace[64];
const auto depth = backtrace(trace, sizeof_array(trace));
Switch::Stacktraces::Frame frames[128];
simple_allocator allocator;
const auto framesCnt = Switch::Stacktraces::captureFrames(trace, depth, allocator, frames, sizeof_array(frames));

for (uint32_t i0}; i != framesCnt; ++i)
{
	const auto frame = frames + i;
	
	// use frame
}
```

If the compiler can't find `link.h`, please install binutils-dev which includes that header file (i.e `apt-get install binutils-dev`). You won't need any libraries or programs from that package, just this include file.

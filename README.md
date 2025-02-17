# BOF-PE

## Description
Beacon Object File (BOF) support has been at the cornerstone of capability for any modern C2 platform since its inception by Cobalt Strike 4.1 back in 2020. It was a major step forward towards integrating a modular and extensible design whilst still being able to interact with the C2 platform itself via the Beacon API.

After five years of development using this approach, cracks in the design have begun to show. Complex BOFs become difficult to maintain and the lack of higher level language support (such as the C++ STL library and exceptions) can make source code bloated. So why can we not use uber new C++20 features but also execute from memory in a native fashion whilst maintaining integration with the Beacon API?

Well, this proposal will hopefully allow just that. In this article, I propose a reference design for a new BOF portable executable (PE) concept that will hopefully solve some of the current constraints and issues faced by BOF developers. Features include:

*	The ability to run the same linked EXE standalone or within a C2 environment
*	Full support for C++ and exceptions are possible
*	Symbol resolution issues disappear 
*	Code will be easier to maintain vs the traditional BOF design

## Isn't this just another in memory PE loader?

Not quite. In memory PE executors are unaware that they are executing within the confines of a C2 agent. This increases the complexity of loaders as they attempt to capture program output and feed arguments to the executable run from memory. Solutions such as Fortra's No-Consolation have worked towards resolving some of these issues, but at a cost of loader complexity. 

Unlike in memory PE execution modules, BOF PE files would have full use of the Beacon API, therefore, no special output capture or argument processing would need to be performed. Developers would simply use the BeaconPrintf or BeaconOutput APIs to send output and data to the C2 server and leverage the C2 solution's argument packing format as before. 
 
### How would it work?
BOF PE source will include the `beacon.h` header as normal, but there will now be an additional import library, `beacon.lib` that developers will be required to link during compilation. This will create a dependency on `beacon.dll` for the linked BOF PE. For standalone execution, this DLL acts as the beacon compatibility layer. Both `beacon.dll` and the BOF PE executable will be required in the same folder to execute. Typically, the compatibility layer will write program output to stdout instead of writing the data over the C2 channel.

When executing under a C2 agent, this beacon compatibility layer is no longer required. During processing of the BOF PE DLL imports, whenever functions imported from `beacon.dll` are found, they are plugged into that specific C2 provider's API calls directly as would typically happen under traditional BOF execution. The `beacon.dll` file is not resolved or loaded from disk at all.  All other DLLs are processed as normal imports and are resolved accordingly.

## Standalone execution

Traditional BOFs are not easily executable as standalone programs. This can often lead to duplicated efforts to create standalone tools and BOF's that perform the same task. 

The BOF PE design will allow execution of the fully linked PE using a beacon compatibility layer. This is useful for PEs which support execution over a SOCKS proxy.  Whilst standalone execution would also be possible from within the target environment, dropping BOF PE files to disk would not be recommended for opsec purposes.

```
c:\bofs\mybof.exe "String arg" 12345 c:\files\binary.bin
```
The same EXE file could be used for execution within the C2 environment.
```
bof-pe c:\bofs\mybof.exe "String arg" 12345 c:\files\binary.bin
```

This functionality would be implemented by a new beacon API which I have named `BeaconInvokeStandalone` which could be called from the program's main function.

```c
int BeaconInvokeStandalone(int argc, const char* argv[], const char* bof_args_def, BeaconEntryPtr entry);
```

The `bof_args_def` argument defines the format expected for the BOF argument packing format, so for example, a BOF that requires two arguments, a string and a short would be defined using `zs`. This allows the beacon compatibility layer to convert the arguments to beacon's internal packed format prior to calling the BOF entry point function defined via the entry argument.

## Exception support
Traditional BOFs do not support SEH/C++ exceptions. This often results in verbose code and “nested if hell” where each function is checked for failure.

Since BOF PE files will be fully linked executables, handling both SEH/C++ exceptions  would be possible. BOF PE loaders will have all the information necessary inside the compiled PE to update the runtime or inverted function tables. This will be the more complex element to the new loader design for any C2 provider that chooses to implement the BOF PE proposal. 

Within ntdll, a non-exported table exists called the `LdrpInvertedFunctionTables`. The inverted function table contains a sorted listed of memory regions that have exception handlers within each region.  This table is usually modified when a module is loaded by ntdll, including the main executable itself.  But because our PE is reflectively loaded, we need to find this table from ntdll so that we can insert a new entry for our memory mapped BOF PE.

RiskInsight released a great [blog](https://www.riskinsight-wavestone.com/en/2024/10/loadlibrary-madness-dynamically-load-winhttp-dll/) on how loaders can find this table without using static signatures for various versions of ntdll.dll. Well worth the read. A similar technique has been implemented within the reference design but additional guards have been added to ensure that the memory being queried is more likely to be the `LdrpInvertedFunctionTables` region we are searching for.  These additional guards were required to add support for x86. 
  
### x64
For x64 PE files, support for exceptions is generally easy. Any x64 PE that makes use of exception handlers will have the exception directory populated within the data directories array. These are typically hosted inside the `.edata` and `.pdata` sections.  A single call to the `RtlAddFunctionTable` API with information on the location of the exception tables from the BOF PE will be all that is needed. Voila, you have exception support in your reflectively loaded PE.

### x86
On the other hand, x86 is a different beast altogether. Exception handlers and unwind information is pushed to the stack for each frame that leverages exceptions. Because of this, in theory, x86 exceptions should work without any special considerations.  But exception information pushed to the stack introduces a form of stack overflow vulnerability where the exception handler for a particular frame can be overwritten.  To combat this, Microsoft introduced Structured Exception Handling Overwrite Protection (SEHOP) after the release of Visa SP1/Server 2008.  This introduced a new compiler option for Visual Studio called `/SAFESEH` that inserted valid exception handlers inside the PE’s load config directory.  So if you are reflectively loading a BOF PE inside an executable that was compiled with `/SAFESEH`, then any exception raised is expected to be found within the inverted function table.  If the exception handler is not found, the program is terminated immediately.

Different compilers can implement exception support differently for x86 too. GCC for example does not use SEH and can either use DWARF2 EH or the setjump-longjump (sjlj) model. I won’t go into too much detail on the internals of both models, but typically they require initialization during startup of the PE prior to the execution of `main`. Therefore our design needs to accommodate this by calling `__main()` before any exceptions are thrown by BOF PE files compiled with GCC.

Modern day MSVC/Clang compilers on the other hand use SAFESEH. But for x86, we still need to make a call to `__scrt_initialize_crt` for some of this magic to work.

## Standard import format for Windows APIs
BOFs are required to import Windows APIs using a non-standard import format, for example: 

```c
__declspec(dllimport) KERNEL32$GetCommandLineW
```

This can often lead to the creation of macros or hacks to be able to use the API as they should be called, `GetCommandLineW`. The BOF PE design will solve this issue as the BOF will be a fully linked EXE file with imports from dependent DLL's. 

## Single object file
Traditional BOFs are single compilation units. A compilation unit is typically a single `.cpp` or `.c` file compiled into an COFF file. This can lead to difficulties with code reuse. Multiple c/cpp file support can be simulated through `#include` of a c file as opposed to the typical header file, but again, this is not the norm for traditional software development practices. 

Since the BOF PE design is a fully linked executable. Multiple c/cpp files can be used along with precompiled static libraries that include common code often used across multiple BOFs.

## Simpler loader design
Whilst a fully linked PE and COFF file are both COFF formats, the latter is a little more complex to deal with when loading for execution purposes. COFF files can end up with hundreds of sections as code complexity grows. Some are special. COMDAT sections for example can be duplicated, and it’s the linkers job to pick just one.  Flags for the section will determine how one of those duplicates are chosen. Fully compatible linkers will deal with the various complexities as expected and discard and optimize unreferenced sections.

Current C2 COFF loaders do not handle these edge cases very well. This can often lead to unresolved symbols at the time of execution. With BOF PE, all symbols will be resolved at compile time, therefore any truly unresolved symbols can be resolved during compilation and linkers will correctly resolve internal symbols as expected.

## But what about BOF PE size?

I already hear the voices of the true purists that love to write their BOF code in native assembly language so that their compiled object file is 100 bytes less than the C equivalent.

Fear not, the reference design includes three sample PE files along with a sample loader and beacon compatibility layer.

| Name       | Description                                                                                    | Size   |
| ---------- | ---------------------------------------------------------------------------------------------- | ------ |
| tiny-pe    | A bare bones BOF PE that has no dependencies on the c runtime library at all                   | ~3KB   |
| c-pe       | Typical Hello World C PE that links to the C runtime statically                                | ~180KB |
| cpp-pe     | A C++ Hello World PE that uses the C++ STL library also throws and catches exception           | ~400KB |
| loader.exe | This can be used as a sample C2 BOF PE loader                                                  |        |
| beacon.dll | The beacon compatibility layer that will be loaded when sample BOF PEs are executed standalone |        |


If overall size is important, the tiny-pe template is of similar size to a traditional Hello World BOF. On the flip side, the cpp-pe is considerably larger, but includes the flexibility of using the C++ STL library, exceptions, etc.  A minimal C++ example that catches an exception will be around 80KB.

I know which I prefer, but you do you. Either way, I hope the design is flexible enough to support the true purist or those who prefer to use the more feature rich capabilities of modern C++.

## Example Hello World BOF C++ PE with exceptions

```c
#include <beacon.h>
#include <string>
#include <format>
#include <exception>
#include <chrono>

// The cpp-pe is in my option the best part to come out of the BOF PE design.
// The benefits of the C++ BOF PE is full use of the C++ runtime, including classes
// with virtual functions, templates, the C++ STL library and more importantly
// exceptions.  This will enable BOF PE developers to create much cleaner code that
// is not if/else heavy which is typical of C based code which often checks for error
// codes during each function call.
//
// The drawback of this form of development is size.  The example below with Clang
// will compile to an PE that is roughly 400KB in size.  Keep in mind this sample is using std::format,
// std::string, std::chrono and exceptions. If we just make use of std::exception alone, it compiles to 80KB 

void throw_message(const char* message) {
    throw std::exception(message);
}

void print_message(const char* arg) {

    auto message = std::format("Hello from Beacon C++ PE {}, the time is now {}\n",
        arg == nullptr ? "unknown" : arg, std::chrono::system_clock::now());
    BeaconOutput(CALLBACK_OUTPUT, message.data(), message.length());

    throw_message("Hello from Beacon C++ exception handler");
}

// We need to export one function that will be used for finding the entry point under C2 execution.
// The name is not important.
extern "C" __declspec(dllexport) void go(const char* data, int len){

    // This takes care of initializing the C runtime if needed.
    // For SEH exception to work the CRT initialization function must be called for x86
    // If the BOF PE is invoked via C2, the program entry point hasn't been
    // called, we must therefore invoke it directly.  The macro below takes care making the
    // necessary calls if needed
    BEACON_INIT;

    try{
        datap args = { 0 };
        BeaconDataParse(&args, (char*)data, len);
        print_message(BeaconDataExtract(&args, nullptr));
    }
    catch (const std::exception& ex) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", ex.what());;
    }
}

// A helper macro that will declare main inside the .discard section
// and invoke BeaconInvokeStandalone with the expected packed argument format 
// when executing the BOF PE standalone
BEACON_MAIN("z", go)
```

## Building

CMake is required to build the samples.  You can build with either MSVC, Clang or the MinGW compiler providing they can be found on the path.  MSVC or Clang is recommended over MinGW, since MinGW does not support SEH for x86 builds. 

### MSVC

```cmd
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=dist/ ..
cmake --install . --config Release
cd ..
```

### Clang

A Linux Docker image has been created to leverage Clang.  Check out the `.github/workflow` folder for examples on how to cross compile for Windows using Clang targeting msvc runtime.

Once compilation has finished, all binaries should be present in the dist folder.

### Prebuilt

The samples are also built as part of a [GitHub action](https://github.com/NetSPI/BOF-PE/actions) for those that would prefer prebuilt binaries.

## Running

### Standalone Execution

```
cpp-pe.exe CCob
Hello from Beacon C++ PE CCob, the time is now 2025-02-19 16:23:33.7138258 UTC
Hello from Beacon C++ exception handler
```

### C2 Loader POC Execution

The example C2 loader would be typical of your in-memory reflective loader that would be performed over C2.  The loader takes the packed formats of the args followed by the arguments themselves.  This
argument packing would typically be done via C2 scripting engines likes cna or python. 

```
loader.exe cpp-pe.exe z CCob
Allocated image @ 0x0000000140000000
Copied section .text @ 0x0000000140001000
Copied section . @ 0x0000000140043000
Skipped .discard section @ 0x0000000140083000
Copied section .reloc @ 0x0000000140084000
Skipped relocations
Processed imports
Set section permissions
Added exception function tables
Finished calling TLS callbacks
Calling BOF PE entry @ 0000000140001230 with arguments @ 00000075A0D7FBE0 and size 9
Hello from Beacon C++ PE CCob, the time is now 2025-02-20 11:36:59.2342945 UTC
Hello from Beacon C++ exception handler
```

## Thanks

The POC loader makes use of a modified version of [formatPE](https://github.com/HoShiMin/formatPE) for a zero copy PE parser for C++.  The modifications are generally around support for compiling against the GCC compiler 

## References
* http://www.uninformed.org/index.cgi?v=8&a=2&p=20
* [LoadLibrary madness: dynamically load WinHTTP.dll - RiskInsight](https://www.riskinsight-wavestone.com/en/2024/10/loadlibrary-madness-dynamically-load-winhttp-dll/)
* https://github.com/DarthTon/Blackbone/
* [trustedsec/COFFLoader](https://github.com/trustedsec/COFFLoader)





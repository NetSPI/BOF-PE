
#include <beacon.h>
#include <string>
#include <format>
#include <exception>
#include <chrono>

// The cpp-pe is in my option the best part to come out of the BOF PE design.
// The benefits of the C++ BOF PE is full use of the C++ runtime, including classes
// with virtual fuctions, templates, the C++ STL library and more importantly
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

    auto message = std::format("Hello from Beacon C++ PE {}, the time is now {:%F %T %Z}\n",
        arg == nullptr ? "unknown" : arg, std::chrono::system_clock::now());
    BeaconOutput(CALLBACK_OUTPUT, message.data(), message.length());

    throw_message("Hello from Beacon C++ exception handler");
}

extern "C" __declspec(dllexport) void go(const char* data, int len){

    // This takes care of initializing the C runtime if needed
    // For SEH exception to work the CRT initializaton function must be called for x86
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
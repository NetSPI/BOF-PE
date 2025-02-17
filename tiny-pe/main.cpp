
#include <beacon.h>
#include <shellapi.h>

// The tiny-pe example does not rely on the standard libraries of the compiler at all.
// This is the closest mapping to the original BOF design.
//
// All Windows API's can be used as is, just by importing the correct Windows header
// and making the necessary API calls.  You'll also need to link to to the correct
// import library exactly how you would with a normal PE file, kernel32.lib/user32.lib,etc...

// If you want to import C stdlib functions from msvcrt.dll that is available from XP onwards,
// I'd recommend you compile your tiny-pe with MinGW.  MinGW by default uses the system msvcrt.dll. 
// When compiling under modern MSVC/Clang compilers, stdlib include headers will be defined in 
// a way that is compatible with the ucrt library.  Now you could "borrow" the msvcrt import library from MinGW
// to try an resolve stdlib functions, but there is a good chance of incompatibility between the ucrt headers
// and the msvcrt.lib import library.
// The official way to use msvcrt import libraries is to use the Windows WDK.  See the below SO answer for an
// indepth overview.
// https://stackoverflow.com/questions/10166412/how-to-link-against-msvcrt-dll-instead-of-msvcr100-dll-in-vc-10-0
//
// Personally I think the easiest approach is just to statically link the ucrt library as shown in the c-pe example

extern "C" __declspec(dllexport) void go(const char* data, int len){
    BeaconPrintf(CALLBACK_OUTPUT, "Hello from Beacon C Tiny PE\n");
    MessageBoxA(nullptr, "Hello from Beacon C Tiny PE", "Beacon PE", MB_OK);    
}

// Because we are not linking the standard libraries, we wont have the
// helper code present that will parse the commandline and covert to argc/argv and invoke main.
// Therefore we have to override the program entry point.  So the function below will be executed
// directly by ntdll after dependent DLL's mappings have completed.
//
// If you are purist enough that you want to use the tiny-pe example as a starting point
// and you also want to support arguments for standalone execution, then you will be required to parse the
// commandline manually after calling GetCommandLine windows API.
extern "C"
BEACON_DISCARD void  entry(){
    BeaconInvokeStandalone(0, nullptr, nullptr, go);
}


#include <beacon.h>
#include <stdio.h>

//The c-pe example does not exclude the standard libraries and will link
//any dependencies statically within the target process.  This is often
//the easiest development approach for C based BOF PE's, but will increase
//the size of your final EXE in comparison to the tiny-pe example.


//We export a single function from our BOF PE file, this will allow
//the BOF PE loader to resolve the entry point when executing under a C2
//environment.  Naming of the function is not important as the BOF PE loader
//will use the first exported function from the BOF PE file as the entry point
extern "C" __declspec(dllexport) void go(const char* data, int len){

    //This takes care of initializing the C runtime if needed
    BEACON_INIT;

    //Use the beacon API to unpack arguments, no different to
    //traditional BOF design
    char message[256] = {0};
    datap args = {0};
    BeaconDataParse(&args, (char*)data,len);
    const char* name = BeaconDataExtract(&args, nullptr);

    //No special naming conventions needed for imported API's
    if(name != nullptr){
        sprintf_s(message, sizeof(message), "%s", name);
    }else{
        strcpy(message, "unknown");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Hello from Beacon C PE %s\n", message);
    MessageBoxA(nullptr, "Hello from Beacon C PE", "Beacon PE", MB_OK);
}

//A helper macro that will declare main inside the .discard section
//and invoke BeaconInvokeStandalone with the expected packed argument format  
BEACON_MAIN("z", go)
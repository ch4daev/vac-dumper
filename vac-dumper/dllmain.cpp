#include "dumper.hpp"

#include <Windows.h>

bool __stdcall DllMain( void * hModule,
                       int  ul_reason_for_call,
                       void * lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(dumper::init), nullptr, NULL, nullptr);
    }

    return true;
}


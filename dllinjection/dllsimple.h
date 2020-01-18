#ifndef _DLL_H_
#define _DLL_H_

#ifdef BUILD_DLL
    #define DLL_EXPORT __declspec(dllexport)
#else
    #define DLL_EXPORT __declspec(dllimport)
#endif

#define DLL_MSG __cdecl

#ifdef __cplusplus
extern "C"
{
#endif

DLL_EXPORT void MsgDll();

#ifdef __cplusplus
} // __cplusplus defined.
#endif
#endif

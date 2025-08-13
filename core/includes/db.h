#ifndef DATABASE_H
#define DATABASE_H

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#define BUFFER_SIZE 4096
#define MAX_INFO 999999999

struct db_agents {
    char implant_id[65];
    char os[50];
    char ip[50];
    char hostname[255];
    char arch[50];
};

struct db_tasks {
    char implant_id[65];
    char command[1024];
    char response[BUFFER_SIZE];
};

struct db_logs {
    char implant_id[65];
    char log_type[16];
    char message[BUFFER_SIZE];
};

extern MYSQL *con;

// open connection to database
int db_conn(const char *dbserver, const char *user, const char *pass, const char *db);

// close connection to database
void db_close();


// check if agent id exits in database
int check_implant_id(char *implant_id);


// get tasks
char *get_task(int task_id);

// store beacon response
void store_task_response(char *response, int task_id);

// check for available tasks 
int check_tasks_queue(char *implant_id);

// insert New Agent
void new_implant(struct db_agents args);

void update_last_seen(char *implant_id);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OPERATOR CONSOLE

// insert task
void TasksTable(struct db_tasks args);

// 
void LogsTable(struct db_logs args);

// get all data from a table
// used to view all implants, all tasks, all logs
char *GetData(char *table);

// authenticated operator
int authenticate_operator(char *username, char *password);

// get all tasks per agent
char *tasks_per_implant(char *implant_id);

// get command and response for specific task
char *cmd_and_response(int task_id);


// insert new tasks
void new_tasks(char *implant_id, char *command);



#endif

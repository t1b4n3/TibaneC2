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
    char agent_id[65];
    char os[50];
    char ip[50];
    char mac[50];
    char hostname[255];
    char arch[50];
};

struct db_tasks {
    char agent_id[65];
    char command[1024];
    char response[BUFFER_SIZE];
};

struct db_logs {
    char agent_id[65];
    char log_type[16];
    char message[BUFFER_SIZE];
};

static MYSQL *con;

// open connection to database
int db_conn(const char *dbserver, const char *user, const char *pass, const char *db);

// close connection to database
void db_close();


// check if agent id exits in database
int check_agent_id(char *agent_id);


// get tasks
char *get_task(int task_id);

// store beacon response
void store_task_response(char *response, int task_id);

// check for available tasks 
int check_tasks_queue(char *agent_id);

// insert New Agent
void new_agent(struct db_agents args);

void update_last_seen(char *agent_id);

void TasksTable(struct db_tasks args);


void LogsTable(struct db_logs args);


char *info_view(char *table);


int authenticate_operator(char *username, char *password);



// get all tasks per agent
char *tasks_per_agent(char *agent_id);


void new_tasks(char *agent_id, char *command);


#endif

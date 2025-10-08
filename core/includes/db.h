#ifndef DATABASE_H
#define DATABASE_H

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
//#include "./cJSON/cJSON.h"
#include <cjson/cJSON.h>
#include "common.h"


#define DB_POOL_SIZE 50

extern MYSQL *db_pool[DB_POOL_SIZE];
extern pthread_mutex_t db_pool_mutex;
extern int db_pool_index;



int init_db_pool(struct DBConf db_conf);

MYSQL* get_db_connection();

void cleanup_db_pool();

// check if agent id exits in database
int check_implant_id(MYSQL* con, char *implant_id);


// get tasks
char *get_task(MYSQL* con, int task_id);

// store beacon response
void store_task_response(MYSQL* con, char *response, int task_id);

// check for available tasks 
int check_tasks_queue(MYSQL* con, char *implant_id);

// insert New Agent
void new_implant(MYSQL* con, struct db_agents args);

void update_last_seen(MYSQL* con, char *implant_id);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OPERATOR CONSOLE

// insert task
void TasksTable(MYSQL* con, struct db_tasks args);

// 
void LogsTable(MYSQL* con, struct db_logs args);

// get all data from a table
// used to view all implants, all tasks, all logs
char *GetData(MYSQL* con, char *table);

// authenticated operator
int authenticate_operator(MYSQL* con, char *username, char *password);

// get all tasks per agent
char *tasks_per_implant(MYSQL* con, char *implant_id);

// get command and response for specific task
char *cmd_and_response(MYSQL* con, int task_id);


// insert new tasks
void new_tasks(MYSQL* con, char *implant_id, char *command);

bool update_task(MYSQL* con,int task_id, char*command);

bool batch_tasks(MYSQL* con, char *command, char *os);

#endif

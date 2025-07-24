#include "db.h"

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

MYSQL *con = NULL;

int db_conn(const char *dbserver, const char *user, const char *pass, const char *db) {
    con = mysql_init(NULL);
    if (con == NULL) return -1;
    if (mysql_real_connect(con, dbserver, user, pass, db, 0, NULL, 0) == NULL) return -1;
    return 0;
}

void db_close() {
    mysql_close(con);
}

int check_agent_id(char *agent_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, agent_id, strlen(agent_id));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT * FROM Agents WHERE agent_id = '%s'", esc);
    if (mysql_query(con, query)) return 0;
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return 0;
    int num_rows = mysql_num_rows(result);
    mysql_free_result(result);
    return (num_rows > 0);
}

char *get_task(int task_id) {
    char query[1024];
    snprintf(query, sizeof(query), "SELECT command FROM Tasks WHERE task_id = %d;", task_id);
    if (mysql_query(con, query)) return NULL;
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return NULL;
    MYSQL_ROW row = mysql_fetch_row(result);
    char *cmd = NULL;
    if (row && row[0]) cmd = strdup(row[0]);
    mysql_free_result(result);
    return cmd;
}

void store_task_response(char *response, int task_id) {
    char esc[BUFFER_SIZE * 2];
    mysql_real_escape_string(con, esc, response, strlen(response));
    char *query = malloc(strlen(esc) + 256);
    snprintf(query, strlen(esc) + 256, "UPDATE Tasks SET status = TRUE, response = '%s' WHERE task_id = %d;", esc, task_id);
    mysql_query(con, query);
    free(query);
}

int check_tasks_queue(char *agent_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, agent_id, strlen(agent_id));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT task_id, status FROM Tasks WHERE agent_id = '%s';", esc);
    if (mysql_query(con, query)) return -1;
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return -1;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        if (row[1] != NULL && atoi(row[1]) == 0) {
            int task_id = atoi(row[0]);
            mysql_free_result(result);
            return task_id;
        }
    }
    mysql_free_result(result);
    return -1;
}

void new_agent(struct db_agents args) {
    char query[2048];
    snprintf(query, sizeof(query), "INSERT INTO Agents (agent_id, os, ip, mac, arch, hostname) VALUES ('%s', '%s', '%s', '%s', '%s', '%s');",
             args.agent_id, args.os, args.ip, args.mac, args.arch, args.hostname);
    mysql_query(con, query);
}

void update_last_seen(char *agent_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, agent_id, strlen(agent_id));
    char query[1024];
    snprintf(query, sizeof(query), "UPDATE Agents SET last_seen = CURRENT_TIMESTAMP() WHERE agent_id = '%s';", esc);
    mysql_query(con, query);

}

void TasksTable(struct db_tasks args) {
    char query[4096 + 4096];
    snprintf(query, sizeof(query), "INSERT INTO Tasks (agent_id, command, response) VALUES ('%s', '%s', '%s');",
             args.agent_id, args.command, args.response);
    mysql_query(con, query);
}

void new_tasks(char *agent_id, char *command) {
    char esc_id[130];
    char esc_cmd[1024];
    mysql_real_escape_string(con, esc_id, agent_id, strlen(agent_id));
    mysql_real_escape_string(con, esc_cmd, command, strlen(command));
    char *query = malloc(1024 + 130);
    snprintf(query, 1024 + 256, "INSERT INTO Tasks (agent_id, command) VALUES ('%s', '%s');", esc_id, esc_cmd);
    mysql_query(con, query);
    free(query);
}

char *tasks_per_agent(char *agent_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, agent_id, strlen(agent_id));
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT task_id, command, response, status FROM Tasks WHERE agent_id = '%s';", esc);
    if (mysql_query(con, query)) return NULL;
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return NULL;
    int num_fields = mysql_num_fields(result);
    MYSQL_FIELD *fields = mysql_fetch_fields(result);
    cJSON *column_arrays[num_fields];
    for (int i = 0; i < num_fields; i++) column_arrays[i] = cJSON_CreateArray();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        for (int i = 0; i < num_fields; i++) {
            if (row[i]) cJSON_AddItemToArray(column_arrays[i], cJSON_CreateString(row[i]));
            else cJSON_AddItemToArray(column_arrays[i], cJSON_CreateNull());
        }
    }
    cJSON *root = cJSON_CreateObject();
    for (int i = 0; i < num_fields; i++) cJSON_AddItemToObject(root, fields[i].name, column_arrays[i]);
    char *json_output = cJSON_Print(root);
    cJSON_Delete(root);
    mysql_free_result(result);
    free(query);
    return json_output;
}

int authenticate_operator(char *username, char *password) {
    char esc_user[128];
    char esc_pass[128];
    mysql_real_escape_string(con, esc_user, username, strlen(username));
    mysql_real_escape_string(con, esc_pass, password, strlen(password));
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT * FROM Operators WHERE username='%s' AND password='%s';", esc_user, esc_pass);
    if (mysql_query(con, query)) return -1;
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return -1;
    int num_rows = mysql_num_rows(result);
    mysql_free_result(result);
    free(query);
    return (num_rows > 0) ? 0 : -1;
}

char *info_view(char *table) {
    char esc[256];
    mysql_real_escape_string(con, esc, table, strlen(table));
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT * FROM %s;", esc);
    if (mysql_query(con, query)) return NULL;
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return NULL;
    int num_fields = mysql_num_fields(result);
    MYSQL_FIELD *fields = mysql_fetch_fields(result);
    cJSON *column_arrays[num_fields];
    for (int i = 0; i < num_fields; i++) column_arrays[i] = cJSON_CreateArray();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {
        for (int i = 0; i < num_fields; i++) {
            if (row[i]) cJSON_AddItemToArray(column_arrays[i], cJSON_CreateString(row[i]));
            else cJSON_AddItemToArray(column_arrays[i], cJSON_CreateNull());
        }
    }
    cJSON *root = cJSON_CreateObject();
    for (int i = 0; i < num_fields; i++) cJSON_AddItemToObject(root, fields[i].name, column_arrays[i]);
    char *json_output = cJSON_Print(root);
    cJSON_Delete(root);
    mysql_free_result(result);
    free(query);
    return json_output;
}

void LogsTable(struct db_logs args) {
    char query[4096+1028];
    snprintf(query, sizeof(query), "INSERT INTO Logs (agent_id, log_type, message) VALUES ('%s', '%s', '%s');",
             args.agent_id, args.log_type, args.message);
    mysql_query(con, query);
}
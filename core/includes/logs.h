#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

void log_message(LogLevel level, const char *format, ...);

#endif
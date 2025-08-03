#include "logs.h"

#include <stdarg.h>
#include <time.h>

static const char* level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

void log_message(LogLevel level, const char *format, ...) {
    FILE *log_file = fopen("c2_server.log", "a");
    if (!log_file) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    fprintf(log_file, "[%02d-%02d-%04d %02d:%02d:%02d] [%s] ",
        t->tm_mday, t->tm_mon+1, t->tm_year+1900,
        t->tm_hour, t->tm_min, t->tm_sec,
        level_strings[level]);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fclose(log_file);
}
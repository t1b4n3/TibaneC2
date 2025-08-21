#include "logs.h"

#include <stdarg.h>
#include <time.h>

#include "logs.h"
#include <stdarg.h>
#include <time.h>


static const char* level_strings[] = { "DEBUG", "INFO", "WARN", "ERROR" };
static const char* level_colors[] = {
    "\x1b[36m", // DEBUG - Cyan
    "\x1b[32m", // INFO  - Green
    "\x1b[33m", // WARN  - Yellow
    "\x1b[31m"  // ERROR - Red
};

#define COLOR_RESET "\x1b[0m"

void log_message(LogLevel level, const char *format, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // --- log to file (with colors too) ---
    FILE *log_file = fopen("c2_server.log", "a");
    if (log_file) {
        va_list args;
        va_start(args, format);

        fprintf(log_file,
            "%s[%02d-%02d-%04d %02d:%02d:%02d] [%s]%s ",
            level_colors[level],
            t->tm_mday, t->tm_mon+1, t->tm_year+1900,
            t->tm_hour, t->tm_min, t->tm_sec,
            level_strings[level],
            COLOR_RESET);

        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");

        va_end(args);
        fclose(log_file);
    }

}

/*
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
*/
#include "logs.h"

#include <stdarg.h>
#include <time.h>

#include "logs.h"
#include <stdarg.h>
#include <time.h>
#include "common.h"

static const char* level_strings[] = { "DEBUG", "INFO", "WARN", "ERROR" };
static const char* level_colors[] = {
    "\x1b[36m", // DEBUG - Cyan
    "\x1b[32m", // INFO  - Green
    "\x1b[33m", // WARN  - Yellow
    "\x1b[31m"  // ERROR - Red
};

#define COLOR_RESET "\x1b[0m"


char log_path[BUFFER_SIZE];

// set log_file
void set_logfile_path(char *path) {
    strncpy(log_path, path, BUFFER_SIZE - 1);
}

void log_message(LogLevel level, const char *format, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // --- log to file (with colors too) ---
    FILE *log_file = fopen(log_path, "a");
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

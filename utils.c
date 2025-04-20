#include "utils.h"

#include <time.h>
#include <stdarg.h>
#include <stdio.h>

const char*
log_level_to_str(int log_level)
{
	switch (log_level) {
	case INFO: return "INFO";
	case WARNING: return "WARN";
	case ERROR: return "ERROR";
	default: return "INVALID";
	}

	UNREACHABLE;
}

void
log_msg(FILE* f, int level, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	time_t now = time(NULL);
	struct tm* now_tm = localtime(&now);

	fprintf(f, "[%02d:%02d:%02d] [%s] ",
       	now_tm->tm_hour, now_tm->tm_min, now_tm->tm_sec,
       	log_level_to_str(level));

	vfprintf(f, fmt, args);
	fprintf(f, "\n");

	return;
}

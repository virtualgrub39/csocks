#include "utils.h"
#include "csocks.h"

#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

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

void
daemonize(void) // TODO: Does this even work? Haven't tested it.
{
	pid_t pid;
	int x;

	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}

	pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	umask(0);
	chdir("/");

	for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
		close(x);
	}
}

ssize_t
recv_full(int fd, void *buf, size_t len, int flags) {
	uint8_t *p = buf;
	size_t got = 0;
	while (got < len) {
		ssize_t n = recv(fd, p + got, len - got, flags);
		if (n <= 0) return n;
		got += n;
	}
	return got;
}

char*
get_addr_printable(int atype, uint8_t* addr)
{
    static _Thread_local char addrstring[INET6_ADDRSTRLEN + 1];
    
    switch (atype) {
        case IPV4: {
            snprintf(addrstring, sizeof(addrstring), "%d.%d.%d.%d",
                     addr[0], addr[1], addr[2], addr[3]);
            break;
        }
        case IPV6: {
            snprintf(addrstring, sizeof(addrstring),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     addr[0], addr[1], addr[2], addr[3],
                     addr[4], addr[5], addr[6], addr[7],
                     addr[8], addr[9], addr[10], addr[11],
                     addr[12], addr[13], addr[14], addr[15]);
            break;
        }
        case DOMAINNAME: {
            strncpy(addrstring, (char*)addr, sizeof(addrstring) - 1);
            addrstring[sizeof(addrstring) - 1] = '\0';
            break;
        }
        default:
            snprintf(addrstring, sizeof(addrstring), "<unknown address type>");
            break;
    }
    
    return addrstring;
}

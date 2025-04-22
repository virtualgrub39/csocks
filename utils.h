#ifndef _CSOCKS_UTILS_H
#define _CSOCKS_UTILS_H

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#define UNREACHABLE 									\
	do { 												\
		assert(!"Entered unreachable block of code"); 	\
		abort();										\
	} while (0)

#define TODO(msg)									\
	do {											\
		assert("TODO: " && !msg);					\
		abort();									\
	} while (0)

#define EVER ;;

enum {
	INFO,
	WARNING,
	ERROR
};

void log_msg(FILE* f, int level, const char* fmt, ...);
void daemonize(void);
ssize_t recv_full(int fd, void *buf, size_t len, int flags);
char* get_addr_printable(int atype, uint8_t* addr);

#endif

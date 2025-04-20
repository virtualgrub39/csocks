#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>

#include "utils.h"
#include "config.h"

FILE* log_file;
FILE* auth_file = NULL;
bool daemonized = false;
unsigned long bind_port = 1080;

void
usage(const char* progname)
{
	fprintf(log_file, "%s - SOCKS5/4a/4 proxy server\n", progname);
	fprintf(log_file, "USAGE:\n\t%s <FLAGS>\n", progname);
	fprintf(log_file, "FLAGS:\n");
	fprintf(log_file, "\t-h - display this message\n");
	fprintf(log_file, "\t-n <port> - set port to listen on. [default = 1080]\n");
	fprintf(log_file, "\t-a <auth file path> - read docs :) [deafult = NULL]\n");
	fprintf(log_file, "\t-l <log file path> - set file for logging output. [default = log_file]\n");

	exit(EXIT_FAILURE);
}

void
daemonize(void)
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

void
serv_loop(void)
{
	TODO("Everything?");
}

int
main(int argc, char* argv[])
{
	int retval = 0;
	log_file = stderr;

	while ((retval = getopt(argc, argv, "n:l:a:hd")) != -1) {
		switch (retval) {
		case 'd': {
			daemonized = true;
			daemonize();
		} break;
		case 'n': {
			char* p = NULL;
			bind_port = strtoul(optarg, &p, 10);

			if (*p != 0 || bind_port > 0xffff) {
				fprintf(log_file, "Invalid port number\n");
				exit(EXIT_FAILURE);
			}
		} break;
		case 'l': {
			freopen(optarg, "wa", log_file);
			if (log_file == NULL) {
				perror("Failed to open log file");
				exit(EXIT_FAILURE);
			}
		} break;
		case 'a': {
			freopen(optarg, "r", auth_file);
			if (auth_file == NULL) {
				perror("Failed to open auth file");
				exit(EXIT_FAILURE);
			}
		} break;
		case 'h':
		default: usage(argv[0]);
		}
	}

	if (auth_file) {
		log_msg(log_file, INFO, "Using auth file for USERPASS credentials");
	} else {
		log_msg(log_file, WARNING, "No auth file provided");
		log_msg(log_file, INFO, "username: %s", auth_default_username);
		log_msg(log_file, INFO, "password: %s", auth_default_passwd);
	}
	log_msg(log_file, INFO, "Server listening on :%lu", bind_port);

	serv_loop();

	return 0;
}

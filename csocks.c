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

void*
client_conn_handler(void* arg)
{
	int client_sockfd = (int)(intptr_t)arg;

	log_msg(log_file, INFO, "Nyaa ~~ <3 %d", client_sockfd);
	close(client_sockfd);
	return NULL;
}

void
serv_loop(void)
{
	int serv_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serv_sockfd < 0) {
		log_msg(log_file, ERROR, "socket(): %u", errno);
		exit(1);
	}

	int optval = 1;

	if (setsockopt(serv_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		log_msg(log_file, ERROR, "setsockopt(SO_REUSEADDR): %u", errno);
		goto sock_err;
	}

	// TODO: ipv6 mode?
	struct sockaddr_in bind_addr = { 0 };
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(bind_port);
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(serv_sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
		log_msg(log_file, ERROR, "bind(): %u", errno);
		goto sock_err;
	}

	if (listen(serv_sockfd, LISTEN_BACKLOG_SIZE) < 0) {
		log_msg(log_file, ERROR, "listen(): %u", errno);
		goto sock_err;
	}

	log_msg(log_file, INFO, "Server listening on :%lu", bind_port);

	for (EVER) {
		struct sockaddr_in remote_addr = { 0 };
		socklen_t remote_len = 0;

		int client_sockfd = accept(serv_sockfd, (struct sockaddr*)&remote_addr, &remote_len);
		if (client_sockfd < 0) {
			log_msg(log_file, ERROR, "Failed to accept client connection: %s", strerror(errno));
			continue;
		}

		optval = 1;
		if (setsockopt(serv_sockfd, SOL_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
			log_msg(log_file, ERROR, "setsockopt(TCP_NODELAY): %u", errno);
			close(client_sockfd);
			goto sock_err;
		}

		pthread_t t;
		if (pthread_create(&t, NULL, &client_conn_handler, (void*)&client_sockfd) == 0) {
			pthread_detach(t);
		} else {
			log_msg(log_file, ERROR, "pthread_detach(): %u", errno);
		}
	}

	return;

sock_err:
	close(serv_sockfd);
	exit(1);
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
		if (!auth_default_username || !auth_default_passwd) {
			log_msg(log_file, ERROR, "You have to either provide auth file or set default username and password.");
		}
		log_msg(log_file, INFO, "Username: %s", auth_default_username);
		log_msg(log_file, INFO, "Password: %s", auth_default_passwd);
	}

	serv_loop();

	return 0;
}

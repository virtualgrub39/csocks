#define _GNU_SOURCE // TODO: get rid of this shit
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
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>

#include "utils.h"
#include "config.h"

FILE* log_file;
FILE* auth_file = NULL;
bool daemonized = false;
unsigned long bind_port = 1080;

enum sockserrcode {
	SUCCESS,
	GENERAL_FAILURE,
	CONNECTION_NO_ALLOWED,
	NETWORK_UNREACHABLE,
	HOST_UNREACHABLE,
	CONNECTION_REFUSED,
	TTL_EXPIRED,
	COMMAND_NOT_SUPPORTED,
	ADDRESS_TYPE_NOT_SUPPORTED,
};

enum socksaddrtype {
	IPV4 = 0x01,
	DOMAINNAME = 0x03,
	IPV6 = 0x04,
};

void
usage(const char* progname)
{
	fprintf(log_file, "%s - SOCKS5/4a/4 proxy server\n", progname);
	fprintf(log_file, "USAGE:\n\t%s <FLAGS>\n", progname);
	fprintf(log_file, "FLAGS:\n");
	fprintf(log_file, "\t-h - display this message\n");
	fprintf(log_file, "\t-n <port> - set port to listen on. [default = 1080]\n");
	fprintf(log_file, "\t-a <auth file path> - read docs :) [deafult = NULL]\n");
	fprintf(log_file, "\t-l <log file path> - set file for logging output. [default = stderr]\n");

	exit(EXIT_SUCCESS);
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

// to prevent partial recv()'s
static ssize_t
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

bool
socks_identifier(int sockfd, uint8_t* version, uint8_t* nmethods, uint8_t methods[255])
{
	ssize_t n = recv(sockfd, version, 1, 0);
	if (n <= 0) goto socks_identifier_failure;
	n = recv(sockfd, nmethods, 1, 0);
	if (n <= 0) goto socks_identifier_failure;
	n = recv_full(sockfd, methods, *nmethods, 0);
	if (n <= 0) goto socks_identifier_failure;
	if (n != *nmethods) {
		// malformed request
		return false;
	}
	return true;

socks_identifier_failure:
	if (n < 0) {
		log_msg(log_file, ERROR, "recv failed: %s", strerror(errno));
	}
	return false;
}

bool
socks_auth_userpass(int sockfd)
{
	(void)sockfd;

	TODO("socks_auth_userpass()");

	return false;
}

bool
socks_parse_addr(int atype, uint8_t* addr, uint16_t port, struct sockaddr_storage* sa, socklen_t* sa_len)
{
	switch (atype) {
	case IPV4: {
		struct sockaddr_in* sa4 = (struct sockaddr_in*)sa;

		sa4->sin_family = AF_INET;
		sa4->sin_port = htons(port);
		memcpy(&sa4->sin_addr.s_addr, addr, 4);
		*sa_len = sizeof(struct sockaddr_in);
	} break;
	case IPV6: {
		struct sockaddr_in6* sa6 = (struct sockaddr_in6*)sa;

		sa6->sin6_family = AF_INET6;
		sa6->sin6_port = htons(port);
		memcpy(&sa6->sin6_addr.s6_addr, addr, 16);
		*sa_len = sizeof(struct sockaddr_in6);
	} break;
	case DOMAINNAME: {
		struct sockaddr_in* sa4 = (struct sockaddr_in*)sa;

		struct hostent* he = gethostbyname((char*)addr);
		if (!he) return false;

		sa4->sin_family = AF_INET;
		sa4->sin_port = htons(port);
		memcpy(&sa4->sin_addr, he->h_addr, he->h_length);
		*sa_len = sizeof(he->h_length);

	    break;
	}
	default: UNREACHABLE;
	}

	return true;
}

static char*
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

int
socks_connect(int client_sockfd, int atype, uint8_t* addr, uint16_t port)
{
	enum sockserrcode errval = SUCCESS;
	uint8_t reply[10] = {
		5,
		(uint8_t) errval,
		0x00,
		IPV4,
		0, 0, 0, 0,
		0, 0
	};

	int netsockfd = -1;
	struct sockaddr_storage sa = { 0 };
	socklen_t sa_len = 0;
	// I love IPv6, such a useful protocol :)

	log_msg(log_file, INFO, "Request: CONNECT %s:%u", get_addr_printable(atype, addr), port);

	if (!socks_parse_addr(atype, addr, port, &sa, &sa_len)) {
		errval = GENERAL_FAILURE;
		goto socks_connect_error;
	}

	switch (atype) {
	case IPV4: {
		netsockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	} break;
	case IPV6: {
		netsockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	} break;
	case DOMAINNAME: {
	    netsockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	} break;
	default: UNREACHABLE;
	}

	if (connect(netsockfd, (struct sockaddr*)&sa, sa_len) < 0) {
		errval = GENERAL_FAILURE;
		goto socks_connect_error;
	}

	if (getsockname(netsockfd, (struct sockaddr*)&sa, &sa_len) < 0) {
		close(netsockfd);
		errval = GENERAL_FAILURE;
		goto socks_connect_error;
	}

	switch (sa_len) {
	case sizeof(struct sockaddr_in): {
		reply[1] = SUCCESS;
		memcpy(reply + 4, &((struct sockaddr_in*)&sa)->sin_addr.s_addr, 4);
		memcpy(reply + 8, &((struct sockaddr_in*)&sa)->sin_port, 2);

		write(client_sockfd, reply, 10);
	} break;
	case sizeof(struct sockaddr_in6): {
		TODO("socks_connect() IPv6");
	} break;
	default:
		errval = GENERAL_FAILURE;
		goto socks_connect_error;
	}

	return netsockfd;

socks_connect_error:
 	reply[1] = errval;
	write(client_sockfd, reply, 10);

	log_msg(log_file, WARNING, "Connect request failed with errval: %u", errval);

	return -1;
}

int
socks_bind(int client_sockfd, int atype, uint8_t* addr, uint16_t port)
{
	(void)client_sockfd;
	(void)atype;
	(void)addr;
	(void)port;

	TODO("socks_bind()");

	return -1;
}

int
socks_udp_associate(int client_sockfd, int atype, uint8_t* addr, uint16_t port)
{
	(void)client_sockfd;
	(void)atype;
	(void)addr;
	(void)port;

	TODO("socks_udp_associate()");

	return -1;
}

void
socks_tcp_pipe(int Afd, int Bfd)
{
	log_msg(log_file, INFO, "Piping TCP sockets %d <-> %d", Afd, Bfd);

    int pipeAB[2], pipeBA[2];
    struct pollfd fds[2] = {
        { .fd = Afd, .events = POLLIN  },
        { .fd = Bfd, .events = POLLIN  }
    };
    if (pipe(pipeAB) < 0 || pipe(pipeBA) < 0) {
        log_msg(log_file, ERROR, "pipe() Failed: %s", strerror(errno));
        return;
    }

    for (EVER) {
        int ret = poll(fds, 2, -1);
        if (ret < 0 && errno == EINTR) continue;
        if (ret <= 0) break;

        /* A → B */
        if (fds[0].revents & POLLIN) {
            ssize_t n = splice(Afd, NULL,
                               pipeAB[1], NULL,
                               SPLICE_SIZE,
                               SPLICE_F_MOVE | SPLICE_F_MORE);
            if (n <= 0) break;
            if (splice(pipeAB[0], NULL,
                       Bfd,     NULL,
                       n,
                       SPLICE_F_MOVE | SPLICE_F_MORE) <= 0)
                break;
        }

        /* B → A */
        if (fds[1].revents & POLLIN) {
            ssize_t n = splice(Bfd, NULL,
                               pipeBA[1], NULL,
                               SPLICE_SIZE,
                               SPLICE_F_MOVE | SPLICE_F_MORE);
            if (n <= 0) break;
            if (splice(pipeBA[0], NULL,
                       Afd,     NULL,
                       n,
                       SPLICE_F_MOVE | SPLICE_F_MORE) <= 0)
                break;
        }

        if ((fds[0].revents | fds[1].revents) &
            (POLLERR|POLLHUP|POLLNVAL))
            break;
    }

    close(pipeAB[0]); close(pipeAB[1]);
    close(pipeBA[0]); close(pipeBA[1]);

	log_msg(log_file, INFO, "Stopped piping TCP sockets %d <-> %d", Afd, Bfd);
}

void
socks_udp_relay(int sockfd)
{
	(void)sockfd;

	TODO("socks_udp_relay()");
}

void
socks_handle_request_default(int sockfd)
{
	uint8_t version = 0x05;
	
	enum {
		CONNECT = 0x01,
		BIND = 0x02,
		UDP_ASSOCIATE = 0x03,
	} command;
	
	uint8_t rsv = 0x00;
	enum socksaddrtype atype;

	uint8_t addr_buffer[256] = { 0 };
	uint8_t addr_len = 0;
	uint16_t addr_port = 0;
	
	enum sockserrcode errval = SUCCESS;
	uint8_t erreply[10] = {
		version,
		(uint8_t) errval,
		0x00,
		IPV4,
		0, 0, 0, 0,
		0, 0
	};

	ssize_t n = recv(sockfd, &version, 1, 0);
	if (n <= 0) {
		errval = GENERAL_FAILURE;
		goto handle_request_default_error;
	}

	n = recv(sockfd, (uint8_t*)&command, 1, 0);
	if (n <= 0) {
		errval = GENERAL_FAILURE;
		goto handle_request_default_error;
	}

	n = recv(sockfd, &rsv, 1, 0);
	if (n <= 0) {
		errval = GENERAL_FAILURE;
		goto handle_request_default_error;
	}

	n = recv(sockfd, (uint8_t*)&atype, 1, 0);
	if (n <= 0) {
		errval = GENERAL_FAILURE;
		goto handle_request_default_error;
	}

	// FIXME: Golang-ass code smh my head

	switch (atype) {
	case IPV4:
		addr_len = 4;
		break;
	case DOMAINNAME: 
		n = recv(sockfd, &addr_len, 1, 0);
		if (n <= 0 || addr_len == 0) {
			errval = GENERAL_FAILURE;
			goto handle_request_default_error;
		}
		break;
	case IPV6:
		addr_len = 16;
		break;
	default:
		errval = ADDRESS_TYPE_NOT_SUPPORTED;
		goto handle_request_default_error;
	}

	n = recv_full(sockfd, addr_buffer, addr_len, 0);
	if (n != addr_len) {
		errval = GENERAL_FAILURE;
		goto handle_request_default_error;
	}

	n = recv_full(sockfd, &addr_port, 2, 0);
	if (n != 2) {
		errval = GENERAL_FAILURE;
		goto handle_request_default_error;
	}
	addr_port = htons(addr_port);

	int netsockfd = -1;

	switch (command) {
	case CONNECT:
		netsockfd = socks_connect(sockfd, atype, addr_buffer, addr_port); break;
	case BIND:
		netsockfd = socks_bind(sockfd, atype, addr_buffer, addr_port); break;
	case UDP_ASSOCIATE:
		netsockfd = socks_udp_associate(sockfd, atype, addr_buffer, addr_port); break;
	default:
		errval = COMMAND_NOT_SUPPORTED;
		goto handle_request_default_error;
	}

	if (netsockfd < 0) goto handle_request_default_end; // error message sent by command-specific function

	if (command == CONNECT || command == BIND)
		socks_tcp_pipe(sockfd, netsockfd);
	else if (command == UDP_ASSOCIATE)
		socks_udp_relay(netsockfd);

handle_request_default_end:
	return;

handle_request_default_error:
	erreply[1] = errval;

	write(sockfd, erreply, 10);
}

void*
client_conn_handler(void* arg)
{
	int client_sockfd = (int)(intptr_t)arg;

	uint8_t version;
	uint8_t nmethods;
	uint8_t methods[256];

	if (!socks_identifier(client_sockfd, &version, &nmethods, methods)) {
		// invalid socks request
		goto client_handler_end;
	}

	if (version != 4 && version != 5) {
		log_msg(log_file, WARNING, "Client requested unsupported SOCKS version: %u", version);
		goto client_handler_end;
	}

	enum {
		NOAUTH = 0x00,
		GSSAPI = 0x01, // see readme.md
		USERPASS = 0x02,
		METHOD_NOT_ACCEPTABLE = 0xFF,
	} method = METHOD_NOT_ACCEPTABLE;

	for (uint8_t i = 0; i < nmethods; ++i) {
		if (methods[i] == USERPASS) {
			if ((auth_default_username && auth_default_passwd) || auth_file) {
				method = USERPASS;
				break;
			}
		}
		if (methods[i] == NOAUTH) {
			if (auth_allow_noauth) {
				method = NOAUTH;
				break;
			}
		}
	}

	write(client_sockfd, &version, 1);
	write(client_sockfd, &method, 1);

	switch (method) {
	case USERPASS: 
		if (!socks_auth_userpass(client_sockfd)) {
			// authentication failed
			goto client_handler_end;
		}
		socks_handle_request_default(client_sockfd);
		break; // implicit falling through is forbidden with -Wextra apparently.
	case NOAUTH:
		socks_handle_request_default(client_sockfd);
		break;
	default:
		log_msg(log_file, ERROR, "Unsupported authentication method: %02X", method);
	case METHOD_NOT_ACCEPTABLE:
		goto client_handler_end;
	}

client_handler_end:
	close(client_sockfd);
	return NULL;
}

void
serv_loop(void)
{
	signal(SIGPIPE, SIG_IGN);

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
		if (pthread_create(&t, NULL, &client_conn_handler, (void*)(intptr_t)client_sockfd) == 0) {
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
			log_msg(log_file, WARNING, "USERNAME/PASSWORD authentication disabled");
		}
		log_msg(log_file, INFO, "Username: %s", auth_default_username);
		log_msg(log_file, INFO, "Password: %s", auth_default_passwd);
	}

	serv_loop();

	return 0;
}

// TODO: auth file format definition and parsing
// TODO: non-blocking sockets?
// TODO: workers / thread pool instead of thread per connection?
// TODO: other authentication methods
// TODO: ipv6 support
// TODO: GSSAPI support?

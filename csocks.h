#ifndef _CSOCKS_H
#define _CSOCKS_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

enum socks_error_code {
	SUCCESS,
	GENERAL_FAILURE,
	CONNECTION_NOT_ALLOWED,
	NETWORK_UNREACHABLE,
	HOST_UNREACHABLE,
	CONNECTION_REFUSED,
	TTL_EXPIRED,
	COMMAND_NOT_SUPPORTED,
	ADDRESS_TYPE_NOT_SUPPORTED,
};

enum socks_address_type {
	IPV4 = 0x01,
	DOMAINNAME = 0x03,
	IPV6 = 0x04,
};

enum socks_command {
	CONNECT = 0x01,
	BIND = 0x02,
	UDP_ASSOCIATE = 0x03,
};

void usage(const char* progname);
bool socks_identifier(int sockfd, uint8_t* version, uint8_t* nmethods, uint8_t methods[255]);
bool socks_auth_userpass(int sockfd);
int socks_parse_addr(uint8_t atype, const char* addr, uint16_t port, struct sockaddr_storage* sa, socklen_t* sa_len);
int socks_connect(int client_sockfd, struct sockaddr_storage* addr, socklen_t addr_len);
int socks_bind(int client_sockfd, struct sockaddr_storage* addr, socklen_t addr_len);
int socks_udp_associate(int client_sockfd, int atype, uint8_t* addr, uint16_t port);
void socks_tcp_pipe(int Afd, int Bfd);
void socks_udp_relay(int sockfd);
void socks_request_handle_default(int sockfd);
void* socks_client_connection_handler(void* arg);
void socks_serv_loop(void);
int socks_reply(int sockfd, struct sockaddr_storage* addr, socklen_t addr_len);

#endif

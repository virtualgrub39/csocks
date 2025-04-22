#ifndef _CSOCKS_CONFIG_H
#define _CSOCKS_CONFIG_H

#include <stdbool.h>

#define LISTEN_BACKLOG_SIZE 10
#define SPLICE_SIZE 64 * 1024

/* SET BOTH TO NULL TO DISABLE DEFAULTS */
const char* auth_default_username = "hatsune";
const char* auth_default_passwd = "miku";

/* Allow 'NO AUTHENTICATION' requests */
const bool auth_allow_noauth = true;

#endif

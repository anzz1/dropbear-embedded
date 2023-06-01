/* Dropbear SSH
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved. See LICENSE for the license. */

#ifndef DROPBEAR_OPTIONS_H_
#define DROPBEAR_OPTIONS_H_

#ifndef DROPBEAR_DEFPORT
#define DROPBEAR_DEFPORT "22"
#endif

#ifndef DROPBEAR_DEFADDRESS
/* Listen on all interfaces */
#define DROPBEAR_DEFADDRESS ""
#endif

/* Default hostkey paths - these can be specified on the command line */
#ifndef DSS_PRIV_FILENAME
#define DSS_PRIV_FILENAME "/etc/dropbear/dropbear_dss_host_key"
#endif
#ifndef RSA_PRIV_FILENAME
#define RSA_PRIV_FILENAME "/etc/dropbear/dropbear_rsa_host_key"
#endif

#define NON_INETD_MODE

#define DROPBEAR_AES128
#define DROPBEAR_3DES
#define DROPBEAR_BLOWFISH
#define DROPBEAR_ENABLE_CBC_MODE
#define DROPBEAR_ENABLE_CTR_MODE
#define DROPBEAR_NONE_CIPHER

#define DROPBEAR_SHA1_HMAC
#define DROPBEAR_SHA1_96_HMAC
#define DROPBEAR_MD5_HMAC
#define DROPBEAR_NONE_INTEGRITY

#define DROPBEAR_RSA
#define DROPBEAR_DSS

#define DROPBEAR_DELAY_HOSTKEY

#define DROPBEAR_DH_GROUP1 1
#define DROPBEAR_DH_GROUP14 1

#define ENABLE_SVR_PASSWORD_AUTH

#define DROPBEAR_URANDOM_DEV "/dev/urandom"

/* Specify the number of clients we will allow to be connected but
 * not yet authenticated. After this limit, connections are rejected */
/* The first setting is per-IP, to avoid denial of service */
#ifndef MAX_UNAUTH_PER_IP
#define MAX_UNAUTH_PER_IP 5
#endif

/* And then a global limit to avoid chewing memory if connections 
 * come from many IPs */
#ifndef MAX_UNAUTH_CLIENTS
#define MAX_UNAUTH_CLIENTS 30
#endif

/* Maximum number of failed authentication tries (server option) */
#ifndef MAX_AUTH_TRIES
#define MAX_AUTH_TRIES 10
#endif

/* The default file to store the daemon's process ID, for shutdown
   scripts etc. This can be overridden with the -P flag */
#ifndef DROPBEAR_PIDFILE
#define DROPBEAR_PIDFILE "/var/run/dropbear.pid"
#endif

/* if you want to enable running an sftp server (such as the one included with
 * OpenSSH), set the path below. If the path isn't defined, sftp will not
 * be enabled */
// #ifndef SFTPSERVER_PATH
// #define SFTPSERVER_PATH "sftp-server"
// #endif

/* Window size limits. These tend to be a trade-off between memory
   usage and network performance: */
/* Size of the network receive window. This amount of memory is allocated
   as a per-channel receive buffer. Increasing this value can make a
   significant difference to network performance. 24kB was empirically
   chosen for a 100mbit ethernet network. The value can be altered at
   runtime with the -W argument. */
#ifndef DEFAULT_RECV_WINDOW
#define DEFAULT_RECV_WINDOW 24576
#endif
/* Maximum size of a received SSH data packet - this _MUST_ be >= 32768
   in order to interoperate with other implementations */
#ifndef RECV_MAX_PAYLOAD_LEN
#define RECV_MAX_PAYLOAD_LEN 32768
#endif
/* Maximum size of a transmitted data packet - this can be any value,
   though increasing it may not make a significant difference. */
#ifndef TRANS_MAX_PAYLOAD_LEN
#define TRANS_MAX_PAYLOAD_LEN 16384
#endif

/* Ensure that data is transmitted every KEEPALIVE seconds. This can
be overridden at runtime with -K. 0 disables keepalives */
#define DEFAULT_KEEPALIVE 0

/* If this many KEEPALIVES are sent with no packets received from the
other side, exit. Not run-time configurable - if you have a need
for runtime configuration please mail the Dropbear list */
#define DEFAULT_KEEPALIVE_LIMIT 3

/* Ensure that data is received within IDLE_TIMEOUT seconds. This can
be overridden at runtime with -I. 0 disables idle timeouts */
#define DEFAULT_IDLE_TIMEOUT 0

/* The default path. This will often get replaced by the shell */
// #define DEFAULT_PATH "/usr/bin:/bin"

/* Some other defines (that mostly should be left alone) are defined
 * in sysoptions.h */
#include "sysoptions.h"

#endif /* DROPBEAR_OPTIONS_H_ */

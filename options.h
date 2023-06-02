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

//#define INETD_MODE
#define NON_INETD_MODE

/* Encryption
 * Protocol RFC requires 3DES and recommends AES128 for interoperability */
#define DROPBEAR_AES128
#define DROPBEAR_3DES
#define DROPBEAR_BLOWFISH

/* Enable CBC mode for ciphers */
#define DROPBEAR_ENABLE_CBC_MODE

/* Enable "Counter Mode" for ciphers */
#define DROPBEAR_ENABLE_CTR_MODE

/* Enable "None" cipher
 * Allows unencrypted traffic if requested by client.*/
#define DROPBEAR_NONE_CIPHER

/* Message Integrity - at least one required.
 * Protocol RFC requires sha1 and recommends sha1-96 */
#define DROPBEAR_SHA1_HMAC
#define DROPBEAR_SHA1_96_HMAC
#define DROPBEAR_MD5_HMAC

/* Allow "None" integrity if requested by client */
#define DROPBEAR_NONE_INTEGRITY

/* Private / Public Key algorithms */
#define DROPBEAR_RSA
#define DROPBEAR_DSS

/* Enable "-R" command line argument to automatically generate hostkeys as-needed */
#define DROPBEAR_DELAY_HOSTKEY

/* Key exchange algorithms */
#define DROPBEAR_DH_GROUP1 1
#define DROPBEAR_DH_GROUP14 1

/* Allow password authentication */
#define ENABLE_SVR_PASSWORD_AUTH

/* Enable /etc/shadow support */
//#define ENABLE_SHADOW

/* Enable master password support "-Y" */
#define ENABLE_MASTER_PASSWORD

/* Enable syslog support */
//#define ENABLE_SYSLOG

/* Enable fake root user */
//#define FAKE_ROOT

/* Enable multi-user support */
//#define ENABLE_MULTI_USER

/* Force shell for all users instead of getusershell() */
#define FORCE_SHELL "/bin/sh"

/* Force chdir for all users */
//#define FORCE_DIR "/"

/* Use a interactive shell (login shell) */
//#define ENABLE_INTERACTIVE_SHELL

/* The default path. This will often get replaced by the shell */
#define DEFAULT_PATH "/usr/bin:/bin"

/* Source for randomness. This must be able to provide hundreds of bytes per SSH
 * connection without blocking. In addition /dev/random is used for seeding
 * rsa/dss key generation */
#define DROPBEAR_URANDOM_DEV "/dev/urandom"

/* Specify the number of clients we will allow to be connected but
 * not yet authenticated. After this limit, connections are rejected */
/* The first setting is per-IP, to avoid denial of service */
#define MAX_UNAUTH_PER_IP 5

/* And then a global limit to avoid chewing memory if connections 
 * come from many IPs */
#define MAX_UNAUTH_CLIENTS 30

/* Maximum number of failed authentication tries (server option) */
#define MAX_AUTH_TRIES 10

/* The default file to store the daemon's process ID, for shutdown
   scripts etc. This can be overridden with the -P flag */
#define DROPBEAR_PIDFILE "/var/run/dropbear.pid"

/* if you want to enable running an sftp server (such as the one included with
 * OpenSSH), set the path below. If the path isn't defined, sftp will not
 * be enabled */
//#define SFTPSERVER_PATH "sftp-server"

/* Ensure that data is transmitted every KEEPALIVE seconds. This can
be overridden at runtime with -K. 0 disables keepalives */
#define DEFAULT_KEEPALIVE 0

/* If this many KEEPALIVES are sent with no packets received from the
other side, exit. Not run-time configurable */
#define DEFAULT_KEEPALIVE_LIMIT 3

/* Ensure that data is received within IDLE_TIMEOUT seconds. This can
be overridden at runtime with -I. 0 disables idle timeouts */
#define DEFAULT_IDLE_TIMEOUT 0

/* Some other defines (that mostly should be left alone) are defined
 * in sysoptions.h */
#include "sysoptions.h"

#endif /* DROPBEAR_OPTIONS_H_ */

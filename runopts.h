/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#ifndef DROPBEAR_RUNOPTS_H_
#define DROPBEAR_RUNOPTS_H_

#include "includes.h"
#include "signkey.h"
#include "buffer.h"
#include "auth.h"

typedef struct runopts {

	unsigned int recv_window;
	time_t keepalive_secs; /* Time between sending keepalives. 0 is off */
	time_t idle_timeout_secs; /* Exit if no traffic is sent/received in this time */
	int usingsyslog;

#ifdef ENABLE_USER_ALGO_LIST
	char *cipher_list;
	char *mac_list;
#endif

} runopts;

extern runopts opts;

int readhostkey(const char * filename, sign_key * hostkey, 
	enum signkey_type *type);
void load_all_hostkeys(void);

typedef struct svr_runopts {

	char * bannerfile;
#if defined(ENABLE_SVR_PASSWORD_AUTH) && defined(ENABLE_MASTER_PASSWORD)
	char * master_password;
#endif

	int forkbg;

	/* ports and addresses are arrays of the portcount 
	listening ports. strings are malloced. */
	char *ports[DROPBEAR_MAX_PORTS];
	unsigned int portcount;
	char *addresses[DROPBEAR_MAX_PORTS];

	int inetdmode;

	/* Flags indicating whether to use ipv4 and ipv6 */
	/* not used yet
	int ipv4;
	int ipv6;
	*/

#ifdef DO_MOTD
	/* whether to print the MOTD */
	int domotd;
#endif

	int norootlogin;

	int noauthpass;
	int norootpass;
	int allowblankpass;

	sign_key *hostkey;

	int delay_hostkey;

	char *hostkey_files[MAX_HOSTKEYS];
	int num_hostkey_files;

	buffer * banner;
	char * pidfile;

} svr_runopts;

extern svr_runopts svr_opts;

void svr_getopts(int argc, char ** argv);
void loadhostkeys(void);

void print_version(void);

#endif /* DROPBEAR_RUNOPTS_H_ */

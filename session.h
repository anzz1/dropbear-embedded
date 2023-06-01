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

#ifndef DROPBEAR_SESSION_H_
#define DROPBEAR_SESSION_H_

#include "includes.h"
#include "options.h"
#include "buffer.h"
#include "signkey.h"
#include "kex.h"
#include "auth.h"
#include "channel.h"
#include "queue.h"
#include "packet.h"
#include "chansession.h"
#include "dbutil.h"
#include "netio.h"
#include "list.h"

extern int sessinitdone; /* Is set to 0 somewhere */
extern int exitflag;

void common_session_init(int sock_in, int sock_out);
void session_loop(void(*loophandler)()) ATTRIB_NORETURN;
void session_cleanup(void);
void send_session_identification(void);
void send_msg_ignore(void);
void ignore_recv_response(void);

void update_channel_prio(void);

const char* get_user_shell(void);
void fill_passwd(const char* username);

/* Server */
void svr_session(int sock, int childpipe) ATTRIB_NORETURN;
void svr_dropbear_exit(int exitcode, const char* format, va_list param) ATTRIB_NORETURN;
void svr_dropbear_log(int priority, const char* format, va_list param);

/* crypto parameters that are stored individually for transmit and receive */
struct key_context_directional {
	const struct dropbear_cipher *algo_crypt;
	const struct dropbear_cipher_mode *crypt_mode;
	const struct dropbear_hash *algo_mac;
	int hash_index; /* lookup for libtomcrypt */
	int algo_comp; /* compression */
	/* actual keys */
	union {
		symmetric_CBC cbc;
#ifdef DROPBEAR_ENABLE_CTR_MODE
		symmetric_CTR ctr;
#endif
	} cipher_state;
	unsigned char mackey[MAX_MAC_LEN];
	int valid;
};

struct key_context {

	struct key_context_directional recv;
	struct key_context_directional trans;

	const struct dropbear_kex *algo_kex;
	int algo_hostkey;

	int allow_compress; /* whether compression has started (useful in 
							zlib@openssh.com delayed compression case) */
};

struct packetlist;
struct packetlist {
	struct packetlist *next;
	buffer * payload;
};

struct sshsession {

	/* Is it a client or server? */
	unsigned char isserver;

	time_t connect_time; /* time the connection was established
							(cleared after auth once we're not
							respecting AUTH_TIMEOUT any more).
							A monotonic time, not realworld */

	int sock_in;
	int sock_out;

	/* remotehost will be initially NULL as we delay
	 * reading the remote version string. it will be set
	 * by the time any recv_() packet methods are called */
	char *remoteident;

	int maxfd; /* the maximum file descriptor to check with select() */


	/* Packet buffers/values etc */
	buffer *writepayload; /* Unencrypted payload to write - this is used
							 throughout the code, as handlers fill out this
							 buffer with the packet to send. */
	struct Queue writequeue; /* A queue of encrypted packets to send */
	unsigned int writequeue_len; /* Number of bytes pending to send in writequeue */
	buffer *readbuf; /* From the wire, decrypted in-place */
	buffer *payload; /* Post-decompression, the actual SSH packet. 
						May have extra data at the beginning, will be
						passed to packet processing functions positioned past
						that, see payload_beginning */
	unsigned int payload_beginning;
	unsigned int transseq, recvseq; /* Sequence IDs */

	/* Packet-handling flags */
	const packettype * packettypes; /* Packet handler mappings for this
										session, see process-packet.c */

	unsigned dataallowed : 1; /* whether we can send data packets or we are in
								 the middle of a KEX or something */

	unsigned char requirenext; /* byte indicating what packets we require next, 
									 or 0x00 for any.  */

	unsigned char ignorenext; /* whether to ignore the next packet,
								 used for kex_follows stuff */

	unsigned char lastpacket; /* What the last received packet type was */
	
	int signal_pipe[2]; /* stores endpoints of a self-pipe used for
						   race-free signal handling */

	m_list conn_pending;
						
	/* time of the last packet send/receive, for keepalive. Not real-world clock */
	time_t last_packet_time_keepalive_sent;
	time_t last_packet_time_keepalive_recv;
	time_t last_packet_time_any_sent;

	time_t last_packet_time_idle; /* time of the last packet transmission or receive, for
								idle timeout purposes so ignores SSH_MSG_IGNORE
								or responses to keepalives. Not real-world clock */


	/* KEX/encryption related */
	struct KEXState kexstate;
	struct key_context *keys;
	struct key_context *newkeys;
	buffer *session_id; /* this is the hash from the first kex */
	/* The below are used temporarily during kex, are freed after use */
	mp_int * dh_K; /* SSH_MSG_KEXDH_REPLY and sending SSH_MSH_NEWKEYS */
	buffer *hash; /* the session hash */
	buffer* kexhashbuf; /* session hash buffer calculated from various packets*/
	buffer* transkexinit; /* the kexinit packet we send should be kept so we
							 can add it to the hash when generating keys */

	/* Enables/disables compression */
	algo_type *compress_algos;
							
	/* a list of queued replies that should be sent after a KEX has
	   concluded (ie, while dataallowed was unset)*/
	struct packetlist *reply_queue_head, *reply_queue_tail;

	void(*remoteclosed)(void); /* A callback to handle closure of the
									  remote connection */

	void(*extra_session_cleanup)(void); /* client or server specific cleanup */

	struct AuthState authstate; /* Common amongst client and server, since most
								   struct elements are common */

	/* Channel related */
	struct Channel ** channels; /* these pointers may be null */
	unsigned int chansize; /* the number of Channel*s allocated for channels */
	unsigned int chancount; /* the number of Channel*s in use */
	const struct ChanType **chantypes; /* The valid channel types */
	int channel_signal_pending; /* Flag set by sigchld handler */

	/* TCP priority level for the main "port 22" tcp socket */
	enum dropbear_prio socket_prio;

	/* Whether to allow binding to privileged ports (<1024). This doesn't
	 * really belong here, but nowhere else fits nicely */
	int allowprivport;

};

struct serversession {

	/* Server specific options */
	int childpipe; /* kept open until we successfully authenticate */
	/* userauth */

	struct ChildPid * childpids; /* array of mappings childpid<->channel */
	unsigned int childpidsize;

	/* Used to avoid a race in the exit returncode handling - see
	 * svr-chansession.c for details */
	struct exitinfo lastexit;

	/* The numeric address they connected from, used for logging */
	char * addrstring;

	/* The resolved remote address, used for lastlog etc */
	char *remotehost;

#ifdef USE_VFORK
	pid_t server_pid;
#endif

};

/* Global structs storing the state */
extern struct sshsession ses;
extern struct serversession svr_ses;

#endif /* DROPBEAR_SESSION_H_ */

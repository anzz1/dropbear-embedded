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

#include "includes.h"
#include "dbutil.h"
#include "signkey.h"
#include "buffer.h"
#include "ssh.h"

static const char * const signkey_names[DROPBEAR_SIGNKEY_NUM_NAMED] = {
#ifdef DROPBEAR_RSA
	"ssh-rsa",
#endif
#ifdef DROPBEAR_DSS
	"ssh-dss",
#endif
};

/* malloc a new sign_key and set the dss and rsa keys to NULL */
sign_key * new_sign_key() {

	sign_key * ret;

	ret = (sign_key*)m_malloc(sizeof(sign_key));
	ret->type = DROPBEAR_SIGNKEY_NONE;
	ret->source = SIGNKEY_SOURCE_INVALID;
	return ret;
}

/* Returns key name corresponding to the type. Exits fatally
 * if the type is invalid */
const char* signkey_name_from_type(enum signkey_type type, unsigned int *namelen) {
	if (type >= DROPBEAR_SIGNKEY_NUM_NAMED) {
		dropbear_exit("Bad key type %d", type);
	}

	if (namelen) {
		*namelen = strlen(signkey_names[type]);
	}
	return signkey_names[type];
}

/* Returns DROPBEAR_SIGNKEY_NONE if none match */
enum signkey_type signkey_type_from_name(const char* name, unsigned int namelen) {
	int i;
	for (i = 0; i < DROPBEAR_SIGNKEY_NUM_NAMED; i++) {
		const char *fixed_name = signkey_names[i];
		if (namelen == strlen(fixed_name)
			&& memcmp(fixed_name, name, namelen) == 0) {
			return (enum signkey_type)i;
		}
	}

	TRACE(("signkey_type_from_name unexpected key type."))

	return DROPBEAR_SIGNKEY_NONE;
}

/* Returns a pointer to the key part specific to "type" */
void **
signkey_key_ptr(sign_key *key, enum signkey_type type) {
	switch (type) {
#ifdef DROPBEAR_RSA
		case DROPBEAR_SIGNKEY_RSA:
			return (void**)&key->rsakey;
#endif
#ifdef DROPBEAR_DSS
		case DROPBEAR_SIGNKEY_DSS:
			return (void**)&key->dsskey;
#endif
		default:
			return NULL;
	}
}

/* returns DROPBEAR_SUCCESS on success, DROPBEAR_FAILURE on fail.
 * type should be set by the caller to specify the type to read, and
 * on return is set to the type read (useful when type = _ANY) */
int buf_get_pub_key(buffer *buf, sign_key *key, enum signkey_type *type) {

	char *ident;
	unsigned int len;
	enum signkey_type keytype;
	int ret = DROPBEAR_FAILURE;

	TRACE2(("enter buf_get_pub_key"))

	ident = buf_getstring(buf, &len);
	keytype = signkey_type_from_name(ident, len);
	m_free(ident);

	if (*type != DROPBEAR_SIGNKEY_ANY && *type != keytype) {
		TRACE(("buf_get_pub_key bad type - got %d, expected %d", keytype, *type))
		return DROPBEAR_FAILURE;
	}
	
	TRACE2(("buf_get_pub_key keytype is %d", keytype))

	*type = keytype;

	/* Rewind the buffer back before "ssh-rsa" etc */
	buf_incrpos(buf, -len - 4);

#ifdef DROPBEAR_DSS
	if (keytype == DROPBEAR_SIGNKEY_DSS) {
		dss_key_free(key->dsskey);
		key->dsskey = m_malloc(sizeof(*key->dsskey));
		ret = buf_get_dss_pub_key(buf, key->dsskey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->dsskey);
		}
	}
#endif
#ifdef DROPBEAR_RSA
	if (keytype == DROPBEAR_SIGNKEY_RSA) {
		rsa_key_free(key->rsakey);
		key->rsakey = m_malloc(sizeof(*key->rsakey));
		ret = buf_get_rsa_pub_key(buf, key->rsakey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->rsakey);
		}
	}
#endif

	TRACE2(("leave buf_get_pub_key"))

	return ret;
	
}

/* returns DROPBEAR_SUCCESS on success, DROPBEAR_FAILURE on fail.
 * type should be set by the caller to specify the type to read, and
 * on return is set to the type read (useful when type = _ANY) */
int buf_get_priv_key(buffer *buf, sign_key *key, enum signkey_type *type) {

	char *ident;
	unsigned int len;
	enum signkey_type keytype;
	int ret = DROPBEAR_FAILURE;

	TRACE2(("enter buf_get_priv_key"))

	ident = buf_getstring(buf, &len);
	keytype = signkey_type_from_name(ident, len);
	m_free(ident);

	if (*type != DROPBEAR_SIGNKEY_ANY && *type != keytype) {
		TRACE(("wrong key type: %d %d", *type, keytype))
		return DROPBEAR_FAILURE;
	}

	*type = keytype;

	/* Rewind the buffer back before "ssh-rsa" etc */
	buf_incrpos(buf, -len - 4);

#ifdef DROPBEAR_DSS
	if (keytype == DROPBEAR_SIGNKEY_DSS) {
		dss_key_free(key->dsskey);
		key->dsskey = m_malloc(sizeof(*key->dsskey));
		ret = buf_get_dss_priv_key(buf, key->dsskey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->dsskey);
		}
	}
#endif
#ifdef DROPBEAR_RSA
	if (keytype == DROPBEAR_SIGNKEY_RSA) {
		rsa_key_free(key->rsakey);
		key->rsakey = m_malloc(sizeof(*key->rsakey));
		ret = buf_get_rsa_priv_key(buf, key->rsakey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->rsakey);
		}
	}
#endif

	TRACE2(("leave buf_get_priv_key"))

	return ret;
	
}

/* type is either DROPBEAR_SIGNKEY_DSS or DROPBEAR_SIGNKEY_RSA */
void buf_put_pub_key(buffer* buf, sign_key *key, enum signkey_type type) {

	buffer *pubkeys;

	TRACE2(("enter buf_put_pub_key"))
	pubkeys = buf_new(MAX_PUBKEY_SIZE);
	
#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_pub_key(pubkeys, key->dsskey);
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_pub_key(pubkeys, key->rsakey);
	}
#endif
	if (pubkeys->len == 0) {
		dropbear_exit("Bad key types in buf_put_pub_key");
	}

	buf_putbufstring(buf, pubkeys);
	buf_free(pubkeys);
	TRACE2(("leave buf_put_pub_key"))
}

/* type is either DROPBEAR_SIGNKEY_DSS or DROPBEAR_SIGNKEY_RSA */
void buf_put_priv_key(buffer* buf, sign_key *key, enum signkey_type type) {

	TRACE(("enter buf_put_priv_key"))
	TRACE(("type is %d", type))

#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_priv_key(buf, key->dsskey);
		TRACE(("leave buf_put_priv_key: dss done"))
		return;
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_priv_key(buf, key->rsakey);
		TRACE(("leave buf_put_priv_key: rsa done"))
		return;
	}
#endif
	dropbear_exit("Bad key types in put pub key");
}

void sign_key_free(sign_key *key) {

	TRACE2(("enter sign_key_free"))

#ifdef DROPBEAR_DSS
	dss_key_free(key->dsskey);
	key->dsskey = NULL;
#endif
#ifdef DROPBEAR_RSA
	rsa_key_free(key->rsakey);
	key->rsakey = NULL;
#endif

	m_free(key->filename);

	m_free(key);
	TRACE2(("leave sign_key_free"))
}

void buf_put_sign(buffer* buf, sign_key *key, enum signkey_type type, 
	buffer *data_buf) {
	buffer *sigblob;
	sigblob = buf_new(MAX_PUBKEY_SIZE);

#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_sign(sigblob, key->dsskey, data_buf);
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_sign(sigblob, key->rsakey, data_buf);
	}
#endif
	if (sigblob->len == 0) {
		dropbear_exit("Non-matching signing type");
	}
	buf_putbufstring(buf, sigblob);
	buf_free(sigblob);

}

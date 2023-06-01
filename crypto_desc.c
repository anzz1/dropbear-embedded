#include "includes.h"
#include "dbutil.h"
#include "crypto_desc.h"

/* Register the compiled in ciphers.
 * This should be run before using any of the ciphers/hashes */
void crypto_init() {

	const struct ltc_cipher_descriptor *regciphers[] = {
#ifdef DROPBEAR_AES
		&aes_desc,
#endif
#ifdef DROPBEAR_BLOWFISH
		&blowfish_desc,
#endif
#ifdef DROPBEAR_3DES
		&des3_desc,
#endif
		NULL
	};

	const struct ltc_hash_descriptor *reghashes[] = {
		/* we need sha1 for hostkey stuff regardless */
		&sha1_desc,
#ifdef DROPBEAR_MD5_HMAC
		&md5_desc,
#endif
		NULL
	};	
	int i;
	
	for (i = 0; regciphers[i] != NULL; i++) {
		if (register_cipher(regciphers[i]) == -1) {
			dropbear_exit("Error registering crypto");
		}
	}

	for (i = 0; reghashes[i] != NULL; i++) {
		if (register_hash(reghashes[i]) == -1) {
			dropbear_exit("Error registering crypto");
		}
	}
}


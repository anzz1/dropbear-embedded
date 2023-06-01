# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver

# The version
VERSION=1.16

srcdir=.

# Compilation flags. Note the += does not write over the user's CFLAGS!
# The rest of the flags come from the parent Dropbear makefile
CFLAGS += -c -Isrc/headers/ -I$(srcdir)/src/headers/ -I../ -I$(srcdir)/../ -DLTC_SOURCE -I../libtommath/ -I$(srcdir)/../libtommath/

ifndef LIBNAME
   LIBNAME=libtomcrypt.a
endif

#List of objects to compile.
OBJECTS=src/ciphers/aes/aes_enc.o src/ciphers/aes/aes.o src/ciphers/blowfish.o src/ciphers/des.o \
src/hashes/helper/hash_memory.o src/hashes/md5.o src/hashes/sha1.o \
src/mac/hmac/hmac_done.o src/mac/hmac/hmac_init.o src/mac/hmac/hmac_memory.o src/mac/hmac/hmac_process.o \
src/misc/crypt/crypt_argchk.o src/misc/crypt/crypt_cipher_descriptor.o \
src/misc/crypt/crypt_cipher_is_valid.o src/misc/crypt/crypt_find_cipher.o \
src/misc/crypt/crypt_find_hash.o \
src/misc/crypt/crypt_hash_descriptor.o src/misc/crypt/crypt_hash_is_valid.o \
src/misc/crypt/crypt_register_cipher.o src/misc/crypt/crypt_register_hash.o \
src/misc/zeromem.o \
src/modes/cbc/cbc_decrypt.o src/modes/cbc/cbc_done.o src/modes/cbc/cbc_encrypt.o \
src/modes/cbc/cbc_getiv.o src/modes/cbc/cbc_setiv.o src/modes/cbc/cbc_start.o \
src/modes/ctr/ctr_decrypt.o src/modes/ctr/ctr_done.o src/modes/ctr/ctr_encrypt.o \
src/modes/ctr/ctr_getiv.o src/modes/ctr/ctr_setiv.o src/modes/ctr/ctr_start.o 

#The default rule for make builds the libtomcrypt library.
default:library

#ciphers come in two flavours... enc+dec and enc 
src/ciphers/aes/aes_enc.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
	$(CC) $(CFLAGS) -DENCRYPT_ONLY -c $< -o src/ciphers/aes/aes_enc.o

#These are the rules to make certain object files.
src/ciphers/aes/aes.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c

#This rule makes the libtomcrypt library.
library: $(LIBNAME)

$(LIBNAME): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS) 
	$(RANLIB) $@

clean:
	-rm -f $(OBJECTS)
	-rm -f libtomcrypt.a


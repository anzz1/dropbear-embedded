ifeq (,$(CROSS_COMPILE))
$(error missing CROSS_COMPILE for this toolchain)
endif

CFLAGS  += -marm -march=armv7ve+simd -mtune=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard

STATIC_LTC=libtomcrypt/libtomcrypt.a
STATIC_LTM=libtommath/libtommath.a

LIBTOM_LIBS=

ifeq (1, 1)
LIBTOM_DEPS=$(STATIC_LTC) $(STATIC_LTM) 
CFLAGS+=-I$(srcdir)/libtomcrypt/src/headers/
LIBTOM_LIBS=$(STATIC_LTC) $(STATIC_LTM) 
endif

COMMONOBJS=dbutil.o buffer.o dbhelpers.o \
		dss.o bignum.o \
		signkey.o rsa.o dbrandom.o \
		queue.o \
		atomicio.o compat.o \
		crypto_desc.o \
		gensignkey.o gendss.o genrsa.o

SVROBJS=svr-kex.o svr-auth.o sshpty.o \
		svr-authpasswd.o svr-session.o svr-service.o \
		svr-chansession.o svr-runopts.o svr-main.o
		

CLISVROBJS=common-session.o packet.o common-algo.o common-kex.o \
			common-channel.o common-chansession.o termcodes.o \
			process-packet.o dh_groups.o \
			common-runopts.o circbuffer.o list.o netio.o

HEADERS=options.h dbutil.h session.h packet.h algo.h ssh.h buffer.h kex.h \
		dss.h bignum.h signkey.h rsa.h dbrandom.h service.h auth.h \
		debug.h channel.h chansession.h config.h queue.h sshpty.h \
		termcodes.h gendss.h genrsa.h runopts.h includes.h \
		atomicio.h compat.h

dropbearobjs=$(COMMONOBJS) $(CLISVROBJS) $(SVROBJS)

srcdir=.

ifneq (,$(CROSS_COMPILE))
	CC       = $(CROSS_COMPILE)gcc
	AR       = $(CROSS_COMPILE)gcc-ar
	RANLIB   = $(CROSS_COMPILE)gcc-ranlib
	STRIP    = $(CROSS_COMPILE)strip
	SYSROOT  = $(shell ${CC} --print-sysroot)
else
	CC      ?= cc
	AR      ?= ar
	RANLIB  ?= ranlib
	STRIP   ?= strip
endif

OPTIMIZE ?= -Ofast

CFLAGS  += -I. -I$(srcdir) $(CPPFLAGS) $(OPTIMIZE) -Wall -std=gnu99
CFLAGS  += -ffunction-sections -fdata-sections -fmerge-all-constants -fno-stack-protector -fno-ident -fomit-frame-pointer  
CFLAGS  += -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-unroll-loops -fno-math-errno -ffast-math
CFLAGS  += -flto -fipa-pta -fipa-ra -fwhole-program -fuse-linker-plugin -Wl,--gc-sections 
LIBS    += -lc -L${SYSROOT}/usr/lib -Wl,-Bstatic,-lutil,-Bdynamic 
LDFLAGS += -flto -fipa-pta -fipa-ra -fwhole-program -fuse-linker-plugin -Wl,--gc-sections -s
# CPPFLAGS=

EXEEXT=

CFLAGS+= -DDROPBEAR_SERVER

# these are exported so that libtomcrypt's makefile will use them
export CC
export CFLAGS
export RANLIB AR STRIP

ifeq ($(STATIC), 1)
	LDFLAGS+=-static
endif

TARGETS=dropbear

all: $(TARGETS)

strip: $(TARGETS)
	$(STRIP) $(addsuffix $(EXEEXT), $(TARGETS))

# for some reason the rule further down doesn't like $($@objs) as a prereq.
dropbear: $(dropbearobjs)

dropbear: $(HEADERS) $(LIBTOM_DEPS)
	$(CC) $(LDFLAGS) -o $@$(EXEEXT) $($@objs) $(LIBTOM_LIBS) $(LIBS) -lcrypt

$(STATIC_LTC): options.h
	cd libtomcrypt && $(MAKE)

$(STATIC_LTM): options.h
	cd libtommath && $(MAKE)

.PHONY : clean sizes thisclean ltc-clean ltm-clean

ltc-clean:
	cd libtomcrypt && $(MAKE) clean

ltm-clean:
	cd libtommath && $(MAKE) clean

sizes: dropbear
	objdump -t dropbear|grep ".text"|cut -d "." -f 2|sort -rn

clean: ltc-clean ltm-clean thisclean

thisclean:
	-rm -f dropbear *.o

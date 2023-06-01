#Makefile for GCC
#
#Tom St Denis

#version of library 
VERSION=0.40


srcdir=.

# So that libtommath can include Dropbear headers for options and m_burn()
CFLAGS += -I. -I$(srcdir) -I../libtomcrypt/src/headers/ -I$(srcdir)/../libtomcrypt/src/headers/ -I../ -I$(srcdir)/../

#default files to install
ifndef LIBNAME
   LIBNAME=libtommath.a
endif

default: ${LIBNAME}

HEADERS=tommath.h tommath_class.h tommath_superclass.h

OBJECTS=bncore.o bn_mp_init.o bn_mp_init_size.o bn_mp_clear.o bn_mp_zero.o bn_mp_read_unsigned_bin.o \
bn_mp_grow.o bn_mp_mul.o bn_mp_mul_2.o bn_mp_clamp.o bn_mp_cmp.o bn_mp_cmp_d.o bn_mp_sub_d.o \
bn_mp_gcd.o bn_mp_add_d.o bn_mp_mul_2d.o bn_mp_unsigned_bin_size.o bn_mp_count_bits.o \
bn_mp_exptmod_fast.o bn_mp_exptmod.o bn_mp_clear_multi.o bn_mp_set.o bn_mp_mod.o bn_mp_copy.o \
bn_mp_reduce_2k.o bn_mp_reduce_2k_setup.o bn_fast_mp_montgomery_reduce.o bn_mp_montgomery_reduce.o \
bn_mp_cmp_mag.o bn_s_mp_sub.o bn_mp_dr_reduce.o bn_mp_dr_setup.o bn_mp_sqr.o bn_fast_s_mp_sqr.o \
bn_fast_s_mp_mul_digs.o bn_mp_add.o bn_mp_sub.o bn_mp_exch.o bn_s_mp_sqr.o bn_mp_2expt.o bn_mp_mulmod.o \
bn_mp_dr_is_modulus.o bn_mp_abs.o bn_mp_reduce_is_2k.o bn_mp_mul_d.o bn_mp_invmod.o bn_s_mp_exptmod.o \
bn_mp_init_copy.o bn_mp_div_2d.o bn_mp_lshd.o bn_mp_prime_next_prime.o bn_mp_rshd.o bn_mp_reduce_2k_l.o \
bn_mp_reduce.o bn_prime_tab.o bn_fast_mp_invmod.o bn_mp_invmod_slow.o bn_mp_lcm.o bn_s_mp_add.o bn_mp_div.o \
bn_mp_prime_is_prime.o bn_mp_addmod.o bn_mp_to_unsigned_bin.o bn_mp_set_int.o bn_s_mp_mul_digs.o bn_mp_init_multi.o \
bn_mp_div_2.o bn_mp_prime_miller_rabin.o bn_mp_prime_is_divisible.o bn_mp_mod_2d.o bn_reverse.o bn_mp_cnt_lsb.o \
bn_mp_sqrmod.o bn_mp_reduce_setup.o bn_mp_mod_d.o bn_s_mp_mul_high_digs.o bn_mp_reduce_is_2k_l.o bn_mp_div_d.o \
bn_mp_montgomery_setup.o bn_mp_reduce_2k_setup_l.o bn_mp_div_3.o bn_mp_montgomery_calc_normalization.o \
bn_fast_s_mp_mul_high_digs.o 

$(LIBNAME):  $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS)
	$(RANLIB) $@

clean:
	rm -f *.o *.a

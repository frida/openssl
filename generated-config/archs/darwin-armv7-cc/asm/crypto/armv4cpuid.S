#include "arm_arch.h"

#if defined(__thumb2__) && !defined(__APPLE__)
.syntax	unified
.thumb
#else
.code	32
#undef	__thumb2__
#endif

.text

.align	5
.globl	_OPENSSL_atomic_add
#ifdef __thumb2__
.thumb_func	_OPENSSL_atomic_add
#endif
_OPENSSL_atomic_add:
#if __ARM_ARCH__>=6
Ladd:	ldrex	r2,[r0]
	add	r3,r2,r1
	strex	r2,r3,[r0]
	cmp	r2,#0
	bne	Ladd
	mov	r0,r3
	bx	lr
#else
	stmdb	sp!,{r4,r5,r6,lr}
	ldr	r2,Lspinlock
	adr	r3,Lspinlock
	mov	r4,r0
	mov	r5,r1
	add	r6,r3,r2	@ &spinlock
	b	.+8
Lspin:	bl	sched_yield
	mov	r0,#-1
	swp	r0,r0,[r6]
	cmp	r0,#0
	bne	Lspin

	ldr	r2,[r4]
	add	r2,r2,r5
	str	r2,[r4]
	str	r0,[r6]		@ release spinlock
	ldmia	sp!,{r4,r5,r6,lr}
	tst	lr,#1
	moveq	pc,lr
.word	0xe12fff1e	@ bx	lr
#endif


.globl	_OPENSSL_cleanse
#ifdef __thumb2__
.thumb_func	_OPENSSL_cleanse
#endif
_OPENSSL_cleanse:
	eor	ip,ip,ip
	cmp	r1,#7
#ifdef	__thumb2__
	itt	hs
#endif
	subhs	r1,r1,#4
	bhs	Lot
	cmp	r1,#0
	beq	Lcleanse_done
Little:
	strb	ip,[r0],#1
	subs	r1,r1,#1
	bhi	Little
	b	Lcleanse_done

Lot:	tst	r0,#3
	beq	Laligned
	strb	ip,[r0],#1
	sub	r1,r1,#1
	b	Lot
Laligned:
	str	ip,[r0],#4
	subs	r1,r1,#4
	bhs	Laligned
	adds	r1,r1,#4
	bne	Little
Lcleanse_done:
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
.word	0xe12fff1e	@ bx	lr
#endif


.globl	_CRYPTO_memcmp
#ifdef __thumb2__
.thumb_func	_CRYPTO_memcmp
#endif
.align	4
_CRYPTO_memcmp:
	eor	ip,ip,ip
	cmp	r2,#0
	beq	Lno_data
	stmdb	sp!,{r4,r5}

Loop_cmp:
	ldrb	r4,[r0],#1
	ldrb	r5,[r1],#1
	eor	r4,r4,r5
	orr	ip,ip,r4
	subs	r2,r2,#1
	bne	Loop_cmp

	ldmia	sp!,{r4,r5}
Lno_data:
	rsb	r0,ip,#0
	mov	r0,r0,lsr#31
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
.word	0xe12fff1e	@ bx	lr
#endif


#if __ARM_MAX_ARCH__>=7



.align	5
.globl	__armv7_neon_probe
#ifdef __thumb2__
.thumb_func	__armv7_neon_probe
#endif
__armv7_neon_probe:
	vorr	q0,q0,q0
	bx	lr


.globl	__armv7_tick
#ifdef __thumb2__
.thumb_func	__armv7_tick
#endif
__armv7_tick:
#ifdef	__APPLE__
	mrrc	p15,0,r0,r1,c14		@ CNTPCT
#else
	mrrc	p15,1,r0,r1,c14		@ CNTVCT
#endif
	bx	lr


.globl	__armv8_aes_probe
#ifdef __thumb2__
.thumb_func	__armv8_aes_probe
#endif
__armv8_aes_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
.byte	0xb0,0xff,0x00,0x03	@ aese.8	q0,q0
#else
.byte	0x00,0x03,0xb0,0xf3	@ aese.8	q0,q0
#endif
	bx	lr


.globl	__armv8_sha1_probe
#ifdef __thumb2__
.thumb_func	__armv8_sha1_probe
#endif
__armv8_sha1_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
.byte	0x00,0xef,0x40,0x0c	@ sha1c.32	q0,q0,q0
#else
.byte	0x40,0x0c,0x00,0xf2	@ sha1c.32	q0,q0,q0
#endif
	bx	lr


.globl	__armv8_sha256_probe
#ifdef __thumb2__
.thumb_func	__armv8_sha256_probe
#endif
__armv8_sha256_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
.byte	0x00,0xff,0x40,0x0c	@ sha256h.32	q0,q0,q0
#else
.byte	0x40,0x0c,0x00,0xf3	@ sha256h.32	q0,q0,q0
#endif
	bx	lr

.globl	__armv8_pmull_probe
#ifdef __thumb2__
.thumb_func	__armv8_pmull_probe
#endif
__armv8_pmull_probe:
#if defined(__thumb2__) && !defined(__APPLE__)
.byte	0xa0,0xef,0x00,0x0e	@ vmull.p64	q0,d0,d0
#else
.byte	0x00,0x0e,0xa0,0xf2	@ vmull.p64	q0,d0,d0
#endif
	bx	lr

#endif

.globl	_OPENSSL_wipe_cpu
#ifdef __thumb2__
.thumb_func	_OPENSSL_wipe_cpu
#endif
_OPENSSL_wipe_cpu:
#if __ARM_MAX_ARCH__>=7
	ldr	r0,LOPENSSL_armcap
	adr	r1,LOPENSSL_armcap
	ldr	r0,[r1,r0]
#ifdef	__APPLE__
	ldr	r0,[r0]
#endif
#endif
	eor	r2,r2,r2
	eor	r3,r3,r3
	eor	ip,ip,ip
#if __ARM_MAX_ARCH__>=7
	tst	r0,#1
	beq	Lwipe_done
	veor	q0, q0, q0
	veor	q1, q1, q1
	veor	q2, q2, q2
	veor	q3, q3, q3
	veor	q8, q8, q8
	veor	q9, q9, q9
	veor	q10, q10, q10
	veor	q11, q11, q11
	veor	q12, q12, q12
	veor	q13, q13, q13
	veor	q14, q14, q14
	veor	q15, q15, q15
Lwipe_done:
#endif
	mov	r0,sp
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
.word	0xe12fff1e	@ bx	lr
#endif


.globl	_OPENSSL_instrument_bus
#ifdef __thumb2__
.thumb_func	_OPENSSL_instrument_bus
#endif
_OPENSSL_instrument_bus:
	eor	r0,r0,r0
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
.word	0xe12fff1e	@ bx	lr
#endif


.globl	_OPENSSL_instrument_bus2
#ifdef __thumb2__
.thumb_func	_OPENSSL_instrument_bus2
#endif
_OPENSSL_instrument_bus2:
	eor	r0,r0,r0
#if __ARM_ARCH__>=5
	bx	lr
#else
	tst	lr,#1
	moveq	pc,lr
.word	0xe12fff1e	@ bx	lr
#endif


.align	5
#if __ARM_MAX_ARCH__>=7
LOPENSSL_armcap:
.word	OPENSSL_armcap_P-.
#endif
#if __ARM_ARCH__>=6
.align	5
#else
Lspinlock:
.word	atomic_add_spinlock-Lspinlock
.align	5

.data
.align	2
atomic_add_spinlock:
.word	0
#endif

.comm	_OPENSSL_armcap_P,4
.non_lazy_symbol_pointer
OPENSSL_armcap_P:
.indirect_symbol	_OPENSSL_armcap_P
.long	0
.private_extern	_OPENSSL_armcap_P

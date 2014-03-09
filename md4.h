/*
 * md4.h        Structures and prototypes for md4.
 *
 * Version:     $Id$
 * License:		LGPL, but largely derived from a public domain source.
 *
 */

#ifndef _FR_MD4_H
#define _FR_MD4_H

#include "ident.h"
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void fr_md4_calc (unsigned char *, const unsigned char *, unsigned int);
/*
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 * Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

/*#ifndef _MD4_H_*/
/*#define _MD4_H_*/

#define	MD4_BLOCK_LENGTH		64
#define	MD4_DIGEST_LENGTH		16
#define	MD4_DIGEST_STRING_LENGTH	(MD4_DIGEST_LENGTH * 2 + 1)

typedef struct FR_MD4Context {
	uint32_t state[4];			/* state */
	uint32_t count[2];			/* number of bits, mod 2^64 */
	uint8_t buffer[MD4_BLOCK_LENGTH];	/* input buffer */
} FR_MD4_CTX;

/*__BEGIN_DECLS*/
void	 fr_MD4Init(FR_MD4_CTX *);
void	 fr_MD4Update(FR_MD4_CTX *, const uint8_t *, size_t)
/*		__attribute__((__bounded__(__string__,2,3)))*/;
void	 fr_MD4Final(uint8_t [MD4_DIGEST_LENGTH], FR_MD4_CTX *)
/*		__attribute__((__bounded__(__minbytes__,1,MD4_DIGEST_LENGTH)))*/;
void	 fr_MD4Transform(uint32_t [4], const uint8_t [MD4_BLOCK_LENGTH])
/*		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD4_BLOCK_LENGTH)))*/;
/*__END_DECLS*/

#ifdef __cplusplus
}
#endif

#endif /* _FR_MD4_H */

#ifndef _FR_MISSING_H
#define _FR_MISSING_H

/*
 * missing.h	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 */

#include "ident.h"
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FR_DIR_SEP '/'
#define FR_DIR_IS_RELATIVE(p) ((*p) != '/')

#ifndef offsetof
#define offsetof(TYPE,MEMBER) ((size_t) &((TYPE*)0)->MEMBER)
#endif
void timeval2ntp(const struct timeval *tv, uint8_t *ntp);
void ntp2timeval(struct timeval *tv, const char *ntp);

#ifdef __cplusplus
}
#endif

#endif /* _FR_MISSING_H */

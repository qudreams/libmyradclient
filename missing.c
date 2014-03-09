/*
 * missing.c	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

#include	"ident.h"

#include	"libradius.h"

#include	<ctype.h>


#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *inp)
{
	int	a1, a2, a3, a4;

	if (sscanf(cp, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) != 4)
		return 0;

	inp->s_addr = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + a4);
	return 1;
}
#endif

#ifndef HAVE_STRSEP
/*
 *	Get next token from string *stringp, where tokens are
 *	possibly-empty strings separated by characters from delim.
 *
 *	Writes NULs into the string at *stringp to end tokens.
 *	delim need not remain constant from call to call.  On
 *	return, *stringp points past the last NUL written (if there
 *	might be further tokens), or is NULL (if there are
 *	definitely no more tokens).
 *
 *	If *stringp is NULL, strsep returns NULL.
 */
char *
strsep(char **stringp, const char *delim)
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);

	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}

	return NULL;		/* NOTREACHED, but the compiler complains */
}
#endif



#ifndef HAVE_GETTIMEOFDAY
#ifdef WIN32
/*
 * Number of micro-seconds between the beginning of the Windows epoch
 * (Jan. 1, 1601) and the Unix epoch (Jan. 1, 1970).
 *
 * This assumes all Win32 compilers have 64-bit support.
 */
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS) || defined(__WATCOMC__)
#define DELTA_EPOCH_IN_USEC  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_USEC  11644473600000000ULL
#endif

static uint64_t filetime_to_unix_epoch (const FILETIME *ft)
{
	uint64_t res = (uint64_t) ft->dwHighDateTime << 32;

	res |= ft->dwLowDateTime;
	res /= 10;                   /* from 100 nano-sec periods to usec */
	res -= DELTA_EPOCH_IN_USEC;  /* from Win epoch to Unix epoch */
	return (res);
}

int gettimeofday (struct timeval *tv, UNUSED void *tz)
{
	FILETIME  ft;
	uint64_t tim;

	if (!tv) {
		errno = EINVAL;
		return (-1);
	}
        GetSystemTimeAsFileTime (&ft);
        tim = filetime_to_unix_epoch (&ft);
        tv->tv_sec  = (long) (tim / 1000000L);
        tv->tv_usec = (long) (tim % 1000000L);
        return (0);
}
#endif
#endif

#define NTP_EPOCH_OFFSET	2208988800ULL

/*
 *	Convert 'struct timeval' into NTP format (32-bit integer
 *	of seconds, 32-bit integer of fractional seconds)
 */
void
timeval2ntp(const struct timeval *tv, uint8_t *ntp)
{
	uint32_t sec, usec;

	sec = tv->tv_sec + NTP_EPOCH_OFFSET;
	usec = tv->tv_usec * 4295; /* close enough to 2^32 / USEC */
	usec -= ((tv->tv_usec * 2143) >> 16); /*  */

	sec = htonl(sec);
	usec = htonl(usec);

	memcpy(ntp, &sec, sizeof(sec));
	memcpy(ntp + sizeof(sec), &usec, sizeof(usec));
}

/*
 *	Inverse of timeval2ntp
 */
void
ntp2timeval(struct timeval *tv, const char *ntp)
{
	uint32_t sec, usec;

	memcpy(&sec, ntp, sizeof(sec));
	memcpy(&usec, ntp + sizeof(sec), sizeof(usec));

	sec = ntohl(sec);
	usec = ntohl(usec);

	tv->tv_sec = sec - NTP_EPOCH_OFFSET;
	tv->tv_usec = usec / 4295; /* close enough */
}

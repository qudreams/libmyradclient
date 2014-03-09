/*
 * module.h	Interface to the RADIUS module system.
 *
 * Version:	$Id$
 *
 */

#ifndef RADIUS_MODULES_H
#define RADIUS_MODULES_H

#include "ident.h"


#ifdef __cplusplus
extern "C" {
#endif
enum {
	RLM_MODULE_REJECT,	/* immediately reject the request */
	RLM_MODULE_FAIL,	/* module failed, don't reply */
	RLM_MODULE_OK,		/* the module is OK, continue */
	RLM_MODULE_HANDLED,	/* the module handled the request, so stop. */
	RLM_MODULE_INVALID,	/* the module considers the request invalid. */
	RLM_MODULE_USERLOCK,	/* reject the request (user is locked out) */
	RLM_MODULE_NOTFOUND,	/* user not found */
	RLM_MODULE_NOOP,	/* module succeeded without doing anything */
	RLM_MODULE_UPDATED,	/* OK (pairs modified) */
	RLM_MODULE_NUMCODES	/* How many return codes there are */
};

#ifdef __cplusplus
}
#endif

#endif /* RADIUS_MODULES_H */

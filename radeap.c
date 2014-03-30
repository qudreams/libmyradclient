/*
 * radeap.c	EAP-MD5 proxy specific radius packet.
 *Note:
 * we just support EAP-MD5 proxy,not support EAP-SIM.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include "ident.h"


#include <ctype.h>
#include <assert.h>
#include <getopt.h>
#include <netdb.h>
#include <errno.h>

#include "radeap.h"
#include "libradius.h"
#include "md5.h"
#include "eap_types.h"


static void map_eap_types(RADIUS_PACKET *req);
static void unmap_eap_types(RADIUS_PACKET *rep);
static void cleanresp(RADIUS_PACKET *resp);
static int respond_eap_md5(RADIUS_PACKET *req,RADIUS_PACKET *rep,const char* pwd);

#define R_RECV (0)
#define R_SENT (1)

static void 
debug_packet(RADIUS_PACKET *packet, int direction)
{
	VALUE_PAIR *vp;
	char buffer[1024];
	const char *received, *from;
	const fr_ipaddr_t *ip;
	int port;

	if (!packet) return;

	if (direction == 0) {
		received = "Received";
		from = "from";	/* what else? */
		ip = &packet->src_ipaddr;
		port = packet->src_port;

	} else {
		received = "Sending";
		from = "to";	/* hah! */
		ip = &packet->dst_ipaddr;
		port = packet->dst_port;
	}
	
	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
		printf("%s %s packet %s host %s port %d, id=%d, length=%d\n",
		       received, fr_packet_codes[packet->code], from,
		       inet_ntop(ip->af, &ip->ipaddr, buffer, sizeof(buffer)),
		       port, packet->id, packet->data_len);
	} else {
		printf("%s packet %s host %s port %d code=%d, id=%d, length=%d\n",
		       received, from,
		       inet_ntop(ip->af, &ip->ipaddr, buffer, sizeof(buffer)),
		       port,
		       packet->code, packet->id, packet->data_len);
	}

	for (vp = packet->vps; vp != NULL; vp = vp->next) {
		vp_prints(buffer, sizeof(buffer), vp);
		printf("\t%s\n", buffer);
	}
	fflush(stdout);
}

void debug_reply_packet(RADIUS_PACKET *packet)
{
	debug_packet(packet,R_RECV);	
}

void debug_request_packet(RADIUS_PACKET *packet)
{
	debug_packet(packet,R_SENT);	
}

static void 
cleanresp(RADIUS_PACKET *resp)
{
	VALUE_PAIR *vpnext, *vp, **last;


	/*
	 * maybe should just copy things we care about, or keep
	 * a copy of the original input and start from there again?
	 */
	pairdelete(&resp->vps, PW_EAP_MESSAGE);
	pairdelete(&resp->vps, ATTRIBUTE_EAP_BASE+PW_EAP_IDENTITY);

	last = &resp->vps;
	for(vp = *last; vp != NULL; vp = vpnext)
	{
		vpnext = vp->next;

		if(vp->attribute > ATTRIBUTE_EAP_BASE &&
		    vp->attribute <= ATTRIBUTE_EAP_BASE+256)
		{
			*last = vpnext;
			pairbasicfree(vp);
		} else {
			last = &vp->next;
		}
	}
}

static int 
respond_eap_md5(RADIUS_PACKET *req,
			   RADIUS_PACKET *rep,const char* pwd)
{
	VALUE_PAIR *vp, *id, *state;
	size_t valuesize;
	uint8_t identifier;
	uint8_t *value;
	FR_MD5_CTX	context;
	uint8_t    response[16];

	cleanresp(rep);

	if ((state = paircopy2(req->vps, PW_STATE)) == NULL)
	{
		fr_strerror_printf("radeapclient: no state attribute found");
		return 0;
	}

	if ((id = paircopy2(req->vps, ATTRIBUTE_EAP_ID)) == NULL)
	{
		fr_strerror_printf("radeapclient: no EAP-ID attribute found");
		return 0;
	}
	identifier = id->vp_integer;

	if ((vp = pairfind(req->vps, ATTRIBUTE_EAP_BASE+PW_EAP_MD5)) == NULL)
	{
		fr_strerror_printf("radeapclient: no EAP-MD5 attribute found");
		return 0;
	}

	/* got the details of the MD5 challenge */
	valuesize = vp->vp_octets[0];
	value = &vp->vp_octets[1];

	/* sanitize items */
	if(valuesize > vp->length)
	{
		fr_strerror_printf("radeapclient: md5 valuesize if too big (%u > %u)\n",
			(unsigned int) valuesize, (unsigned int) vp->length);
		return 0;
	}

	/* now do the CHAP operation ourself, rather than build the
	 * buffer. We could also call rad_chap_encode, but it wants
	 * a CHAP-Challenge, which we don't want to bother with.
	 */
	fr_MD5Init(&context);
	fr_MD5Update(&context, &identifier, 1);
	fr_MD5Update(&context, (uint8_t *) pwd, strlen(pwd));
	fr_MD5Update(&context, value, valuesize);
	fr_MD5Final(response, &context);

	vp = paircreate(ATTRIBUTE_EAP_BASE+PW_EAP_MD5, PW_TYPE_OCTETS);
	vp->vp_octets[0]=16;
	memcpy(&vp->vp_strvalue[1], response, 16);
	vp->length = 17;

	pairreplace(&(rep->vps), vp);

	pairreplace(&(rep->vps), id);

	/* copy the state object in */
	pairreplace(&(rep->vps), state);

	return 1;
}

int 
rad_set_eap_id(RADIUS_PACKET* rp)
{
	VALUE_PAIR* vp = NULL;
	char eap_id[8] = {0};

	
    bzero(eap_id,sizeof(eap_id));
    snprintf(eap_id,sizeof(eap_id),"%d",rp->id);
    vp = pairmake("EAP-Id",eap_id,T_OP_SET);
    if(vp == NULL) {
		return -1;
    }
    pairadd(&rp->vps,vp);
	return 0;
}

/*
 * rad_create_eap_response
 * create a eap-radius-response packet
 */
RADIUS_PACKET* 
rad_create_eap_response(const char* username,size_t len)
{
    VALUE_PAIR* vp;
    VALUE_PAIR* vps;
	RADIUS_PACKET* rep;

	rep = NULL;
	vps = NULL;

    rep = rad_alloc(1); 
    if(rep == NULL) {
		goto failed;
	}

    rep->id = -1;
    
    vp = NULL; 
    //vp = pairmake("User-Name",username,T_OP_SET);
	vp = paircreate(PW_USER_NAME,PW_TYPE_OCTETS);
    if(vp == NULL) {
		goto failed;
    }
	vp->length = len;
	memcpy(vp->vp_strvalue,username,len);
    pairadd(&vps,vp);

    vp = NULL;
    vp = pairmake("Service-Type","17",T_OP_SET);
    if(vp == NULL) {
		goto failed;
    }
    pairadd(&vps,vp);
    
    vp = NULL;
    vp = pairmake("Message-Authenticator","0",T_OP_SET);
    if(vp == NULL) {
		goto failed;
    }
    pairadd(&vps,vp);

    vp = NULL;
    vp = pairmake("EAP-Code","Response",T_OP_SET);
    if(vp == NULL) {
		goto failed;
    }
    pairadd(&vps,vp);

    vp = NULL;
	vp = paircreate(ATTRIBUTE_EAP_BASE + PW_EAP_IDENTITY,PW_TYPE_OCTETS);
    //vp = pairmake("EAP-Type-Identity",username,T_OP_SET);    
    if(vp == NULL) {
		goto failed;
    }
	vp->length = len;
	memcpy(vp->vp_strvalue,username,len);
    pairadd(&vps,vp);

    rep->vps = vps;

    rep->sockfd = -1;
    rep->code = PW_AUTHENTICATION_REQUEST;
    rep->src_ipaddr.af = AF_UNSPEC;
    rep->src_port = 0;

	return rep;
failed:
	if(vps) pairfree(&vps);
	if(rep) rad_free(&rep);
	return NULL;
}

/*Note:
 * We just support EAP proxy.
 * rad_send_eap_response
 * send a EAP response to radius server
 */
int 
rad_send_eap_response(RADIUS_PACKET* rep,const char* secret,const char* pwd)
{
    VALUE_PAIR* vp;
	int rc;
	int old_debug_flag;

	vp = NULL;
	rc = 0;
	old_debug_flag = 0;

	/*
	 * if there are EAP types, encode them into an EAP-Message
	 *
	 */
	map_eap_types(rep);

	/*
	 *  Fix up Digest-Attributes issues
	 */
	for (vp = rep->vps; vp != NULL; vp = vp->next) {
		switch (vp->attribute) {
		default:
			break;

		case PW_DIGEST_REALM:
		case PW_DIGEST_NONCE:
		case PW_DIGEST_METHOD:
		case PW_DIGEST_URI:
		case PW_DIGEST_QOP:
		case PW_DIGEST_ALGORITHM:
		case PW_DIGEST_BODY_DIGEST:
		case PW_DIGEST_CNONCE:
		case PW_DIGEST_NONCE_COUNT:
		case PW_DIGEST_USER_NAME:
			/* overlapping! */
			memmove(&vp->vp_strvalue[2], &vp->vp_octets[0], vp->length);
			vp->vp_octets[0] = vp->attribute - PW_DIGEST_REALM + 1;
			vp->length += 2;
			vp->vp_octets[1] = vp->length;
			vp->attribute = PW_DIGEST_ATTRIBUTES;
			break;
		}
	}
	fr_md5_calc(rep->vector, rep->vector,
			sizeof(rep->vector));

	if ((pwd != NULL) && (*pwd != '\0')) {
		if ((vp = pairfind(rep->vps, PW_CLEARTEXT_PASSWORD)) != NULL) {
			strncpy((char *)vp->vp_strvalue, pwd, sizeof(vp->vp_strvalue) - 1);
			vp->length = strlen(pwd);

		} else if ((vp = pairfind(rep->vps, PW_USER_PASSWORD)) != NULL) {
			strncpy((char *)vp->vp_strvalue, pwd, sizeof(vp->vp_strvalue) - 1);
			vp->length = strlen(pwd);

		} else if ((vp = pairfind(rep->vps, PW_CHAP_PASSWORD)) != NULL) {
			strncpy((char *)vp->vp_strvalue, pwd, sizeof(vp->vp_strvalue) - 1);
			vp->length = strlen(pwd);

			rad_chap_encode(rep, vp->vp_octets, rep->id, vp);
			vp->length = 17;
		}
	} /* there WAS a password */

	/* send the response*/
    if(fr_debug_flag) {
        debug_packet(rep,R_SENT);
		old_debug_flag = fr_debug_flag;
		fr_debug_flag = 0; /*just turn off the debug-flag to avoid rad_send debug out agin*/
	}
	if(rad_send(rep,NULL,secret) < 0)
		rc = -1;
	else
		rc = 0;
	if(old_debug_flag)
		fr_debug_flag = old_debug_flag;

	return rc;
}

void 
rad_unmap_eap_types(RADIUS_PACKET* rep)
{
	unmap_eap_types(rep);                                     	
}

/*
 * process EAP request from radius server
 * parameters:
 * eap_rep: the original eap-response that we have been sent to radius server
 * eap_req: the eap-request from radius server
 * return-value:
 * 0--->success,and we send a radius-request again
 * 1--->success,and we don't need to process the eap-request agin.
 * -1-->error
 */
int 
rad_process_eap_request(RADIUS_PACKET* eap_rep,RADIUS_PACKET* eap_req,const char* secret,const char* pwd)
{
	assert(eap_req != NULL && eap_req != NULL);
	int rc;
    VALUE_PAIR* vp,*vpnext;

    vp = NULL;
    vpnext = NULL;
	rc = 0;

	/* okay got back the packet, go and decode the EAP-Message. */
    if(eap_req->code != PW_ACCESS_CHALLENGE)
        return 1;
                                                                
    /* now look for the code type. */
    for (vp = eap_req->vps; vp != NULL; vp = vpnext) {
    	vpnext = vp->next;
                                                                   
    	switch (vp->attribute) {
    	default:
    		break;
                                                                   
    	case ATTRIBUTE_EAP_BASE+PW_EAP_MD5:
    		if(respond_eap_md5(eap_req,eap_rep,pwd) <= 0)
				rc = -1;
    		break;
    	}
    }

	if(rc == 0) {
		/*
         *	If we've already sent a packet, free up the old
         *	one, and ensure that the next packet has a unique
         *	ID and authentication vector.
         */
        if (eap_rep->data) {
        	free(eap_rep->data);
        	eap_rep->data = NULL;
        }

		/*now send a eap response again*/
		rc = rad_send_eap_response(eap_rep,secret,NULL);
	}
	return rc;
}


/*
 * given a radius request with some attributes in the EAP range, build
 * them all into a single EAP-Message body.
 *
 * Note that this function will build multiple EAP-Message bodies
 * if there are multiple eligible EAP-types. This is incorrect, as the
 * recipient will in fact concatenate them.
 *
 * XXX - we could break the loop once we process one type. Maybe this
 *       just deserves an assert?
 *
 */
static void 
map_eap_types(RADIUS_PACKET *req)
{
	VALUE_PAIR *vp, *vpnext;
	int id, eapcode;
	EAP_PACKET ep;
	int eap_type;

	vp = pairfind(req->vps, ATTRIBUTE_EAP_ID);
	if(vp == NULL) {
		id = req->id;
	} else {
		id = vp->vp_integer;
	}

	vp = pairfind(req->vps, ATTRIBUTE_EAP_CODE);
	if(vp == NULL) {
		eapcode = PW_EAP_REQUEST;
	} else {
		eapcode = vp->vp_integer;
	}


	for(vp = req->vps; vp != NULL; vp = vpnext) {
		/* save it in case it changes! */
		vpnext = vp->next;

		if(vp->attribute >= ATTRIBUTE_EAP_BASE &&
		   vp->attribute < ATTRIBUTE_EAP_BASE+256) {
			break;
		}
	}

	if(vp == NULL) {
		return;
	}

	eap_type = vp->attribute - ATTRIBUTE_EAP_BASE;

	switch(eap_type) {
	case PW_EAP_IDENTITY:
	case PW_EAP_NOTIFICATION:
	case PW_EAP_NAK:
	case PW_EAP_MD5:
	case PW_EAP_OTP:
	case PW_EAP_GTC:
	case PW_EAP_TLS:
	case PW_EAP_LEAP:
	case PW_EAP_TTLS:
	case PW_EAP_PEAP:
	default:
		/*
		 * no known special handling, it is just encoded as an
		 * EAP-message with the given type.
		 */
		/* nuke any existing EAP-Messages */
		pairdelete(&req->vps, PW_EAP_MESSAGE);

		memset(&ep, 0, sizeof(ep));
		ep.code = eapcode;
		ep.id   = id;
		ep.type.type = eap_type;
		ep.type.length = vp->length;
		ep.type.data = malloc(vp->length);
		memcpy(ep.type.data,vp->vp_octets, vp->length);
		eap_basic_compose(req, &ep);
		//Note: we must free the ep.packet,or not we will lose the memory
		if(ep.packet) {
			free(ep.packet);
			ep.packet = NULL;
		}
	}
}

/*
 * given a radius request with an EAP-Message body, decode it specific
 * attributes.
 */
static void 
unmap_eap_types(RADIUS_PACKET *rep)
{
	VALUE_PAIR *eap1;
	eap_packet_t *e;
	int len;
	int type;

	/* find eap message */
	e = eap_vp2packet(rep->vps);

	/* nothing to do! */
	if(e == NULL) return;

	/* create EAP-ID and EAP-CODE attributes to start */
	eap1 = paircreate(ATTRIBUTE_EAP_ID, PW_TYPE_INTEGER);
	eap1->vp_integer = e->id;
	pairadd(&(rep->vps), eap1);

	eap1 = paircreate(ATTRIBUTE_EAP_CODE, PW_TYPE_INTEGER);
	eap1->vp_integer = e->code;
	pairadd(&(rep->vps), eap1);

	switch(e->code)
	{
	default:
	case PW_EAP_SUCCESS:
	case PW_EAP_FAILURE:
		/* no data */
		break;

	case PW_EAP_REQUEST:
	case PW_EAP_RESPONSE:
		/* there is a type field, which we use to create
		 * a new attribute */

		/* the length was decode already into the attribute
		 * length, and was checked already. Network byte
		 * order, just pull it out using math.
		 */
		len = e->length[0]*256 + e->length[1];

		/* verify the length is big enough to hold type */
		if(len < 5)
		{
			free(e);
			return;
		}

		type = e->data[0];

		type += ATTRIBUTE_EAP_BASE;
		len -= 5;

		if(len > MAX_STRING_LEN) {
			len = MAX_STRING_LEN;
		}

		eap1 = paircreate(type, PW_TYPE_OCTETS);
		memcpy(eap1->vp_strvalue, &e->data[1], len);
		eap1->length = len;
		pairadd(&(rep->vps), eap1);
		break;
	}

	free(e);
	return;
}



/*
 * radclient.c	General radius packet debug tool.
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
#include "radius.h"
#include "libradius.h"
#include "packet.h"
/*Microsoft CHAP*/
#include "mschap.h"
#include "smbdes.h"
/*end Microsoft*/
#include "radeap.h"
 
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>


//Microsoft CHAP,we don't need it
static VALUE_PAIR* mschapv1_encode(VALUE_PAIR **request, const char *password,size_t pwdlen)
{
	unsigned int i;
	VALUE_PAIR *challenge, *response;
	uint8_t nthash[16];

	challenge = paircreate(PW_MSCHAP_CHALLENGE, PW_TYPE_OCTETS);
	if (!challenge) {
		fr_strerror_printf("failed to create MSCHAP-Challenge attribute,because out of memory at line: %d", __LINE__);
		return NULL;
	}

	pairadd(request, challenge);
	challenge->length = 8;
	for (i = 0; i < challenge->length; i++) {
		challenge->vp_octets[i] = fr_rand();
	}

	response = paircreate(PW_MSCHAP_RESPONSE, PW_TYPE_OCTETS);
	if (!response) {
		fr_strerror_printf("failed to create MSCHAP-Response attribute,because out of memory at line: %d", __LINE__);
		return NULL;
	}

	pairadd(request, response);
	response->length = 50;
	memset(response->vp_octets, 0, response->length);

	response->vp_octets[1] = 0x01; // NT hash

	mschap_ntpwdhash(nthash, password,pwdlen);

	smbdes_mschap(nthash, challenge->vp_octets,
		      response->vp_octets + 26);
	return *request;
}

/*
 * RFC 2875 defined
 *Microsoft CHAP v2 encode
 */
static void generate_ntresponse(uint8_t* authchallenge,uint8_t* peerchallenge,
        const char* username,size_t len1,const char* pwd,size_t len2,uint8_t* response)
{
    uint8_t challenge[8] = {0};
    uint8_t nthash[16] = {0};

    mschap_challenge_hash(peerchallenge,authchallenge,username,len1,challenge);
    mschap_ntpwdhash(nthash,pwd,len2); 
    smbdes_mschap(nthash,challenge,response);
}

static VALUE_PAIR* mschapv2_encode(VALUE_PAIR **request,const char* username,size_t len1,
	const char *password,size_t pwdlen)
{
	unsigned int i = 0;
	VALUE_PAIR *challenge = NULL;
	VALUE_PAIR *response = NULL;

	challenge = paircreate(PW_MSCHAP_CHALLENGE, PW_TYPE_OCTETS);
	if (!challenge) {
		fr_strerror_printf("out of memory at line %d", __LINE__);
		return NULL;
	}

	pairadd(request, challenge);
	challenge->length = 16;
	for (i = 0; i < challenge->length; i++) {
		challenge->vp_octets[i] = fr_rand();
	}

	response = paircreate(PW_MSCHAP2_RESPONSE, PW_TYPE_OCTETS);
	if (!response) {
		fr_strerror_printf("out of memory at line %d",__LINE__);	
		return NULL;
	}
    pairadd(request, response);
    response->length = 50;
    memset(response->vp_octets, 0, response->length);
    for(i = 0;i < 16;i++) { //peer challenge
        response->vp_octets[i + 2] = fr_rand();
    }
    
	response->vp_octets[49] = 0x00; // Flag
	generate_ntresponse(challenge->vp_octets,response->vp_octets + 2,
		username,len1,password,pwdlen,response->vp_octets + 26);

	return *request;
}

static RADIUS_PACKET*
rad_request_packet_create_noeapmd5(const char* username,size_t len1,
	const char* password,size_t len2,uint8_t auth_type) {
	RADIUS_PACKET* request = NULL;
	VALUE_PAIR* vps = NULL;
	VALUE_PAIR* vp = NULL;

	request = rad_alloc(1);
	if (!request) {
		perror("out of memory");
		goto failed;
	}
	request->id = -1; 

	/*
	 *create the VP's.
	 */
	request->vps = NULL;

	vp = paircreate(PW_USER_NAME,PW_TYPE_STRING);
	if(vp == NULL)
		goto failed;
	pairadd(&vps,vp);
	vp->length = len1;
	strncpy(vp->vp_strvalue,username,len1);

	vp = NULL;
	if(auth_type == CHAP) {
		vp = paircreate(PW_CHAP_PASSWORD,PW_TYPE_OCTETS);
		if(vp) {
			strncpy(vp->vp_strvalue,password,len2);
			vp->length = len2;

            rad_chap_encode(request,vp->vp_octets,request->id, vp);
            vp->length = 17;

			pairadd(&vps,vp);
		}
	} else if(auth_type == PAP) {
		vp = paircreate(PW_USER_PASSWORD,PW_TYPE_STRING);
		if(vp) {
			strncpy(vp->vp_strvalue,password,len2);
			vp->length = len2;
			pairadd(&vps,vp);
		}
	} else if(auth_type == MSCHAP) {
		/*
		 *Note:
		 *Here,we don't need to add the value pair agin,because we have done it.
		 */
		vp = mschapv1_encode(&vps,password,len2);
	} else if(auth_type == MSCHAPV2) {
		/*
		 * RFC-2759 for Microsoft CHAP V2
		 */ 
		vp = mschapv2_encode(&vps,username,len1,password,len2);
	} else {
		/*unknow auth-type*/
		vp = NULL;
	}
	if(vp == NULL)
		goto failed;
	
	vp = paircreate(PW_SERVICE_TYPE,PW_TYPE_INTEGER);
	if(vp == NULL)
		goto failed;
	pairadd(&vps,vp);
	vp->lvalue = 17;/*Authentication*/

	vp = paircreate(PW_MESSAGE_AUTHENTICATOR,PW_TYPE_OCTETS);
	if(vp == NULL)
		goto failed;
	pairadd(&vps,vp);
	/*RFC-2869:
	 * The length of Message-Authenticator is 16 octets
	 */
	vp->length = 16;


	request->vps = vps;

	request->sockfd = -1;
	request->code = PW_AUTHENTICATION_REQUEST;
	request->src_ipaddr.af = AF_UNSPEC;
	request->src_port = 0;

	return request;

failed:
	if(vps) pairfree(&vps);
	if(request) rad_free(&request);

	return NULL;
}

RADIUS_PACKET* 
rad_request_packet_create(const char* username,size_t len1,
	const char* password,size_t len2,uint8_t auth_type)
{
	RADIUS_PACKET* rp = NULL;

	if(auth_type == EAPMD5) {
		rp = rad_create_eap_response(username,len1);
	} else {
		rp = rad_request_packet_create_noeapmd5(username,len1,
			password,len2,auth_type);
	}

	return rp;
}

int 
rad_send_request(RADIUS_PACKET* request,const char* secret,const char* password)
{
	if(rad_send(request,NULL,secret) < 0)
		return -1;
	else
		return 0;
}


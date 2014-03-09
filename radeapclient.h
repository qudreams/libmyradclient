#ifndef RADEAPCLIENT_H
#define RADEAPCLIENT_H

#include "libradius.h"
#ifdef __cplusplus
extern "C" {
#endif

RADIUS_PACKET* rad_create_eap_response(const char* username,size_t len);
int rad_send_eap_response(RADIUS_PACKET* rep,const char* secret,const char* pwd);
int rad_process_eap_request(RADIUS_PACKET*eap_rep,RADIUS_PACKET* eap_req,const char* secret,const char* pwd);
void debug_reply_packet(RADIUS_PACKET* packet);
void rad_unmap_eap_types(RADIUS_PACKET* rep);
int rad_set_eap_id(RADIUS_PACKET* rp);

#ifdef __cplusplus
}
#endif

#endif

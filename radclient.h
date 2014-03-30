#ifndef RADCLIENT_H
#define RADCLIENT_H
#include "libradius.h"
#include "radeap.h"

#ifdef __cplusplus
extern "C" {
#endif
int rad_send_request(RADIUS_PACKET* request,const char* secret,const char* password);
RADIUS_PACKET* rad_request_packet_create(const char* username,size_t len1,const char* password,size_t len2,uint8_t auth_type);
void radclient_free(radclient_t *radclient);
int radclient_init(radclient_t** _radclient,const char* username,const char* password,
	const fr_ipaddr_t* server,int serv_port);
int radsend_one_request(radclient_t* client,const char* secret);
int radrecv_one_packet(int sockfd,radclient_t* radclient,const char* secret);
#ifdef __cplusplus
}
#endif

#endif //

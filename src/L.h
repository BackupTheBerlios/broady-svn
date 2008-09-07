#ifndef _L_H_
#define _L_H_

#include "utils.h"

extern int L_sendPacket( client_t* client, const char* packet, unsigned int len, unsigned short port );
extern int L_sendBroadcast( client_t* client, const char* packet, unsigned int len, unsigned short port );
extern int L_nodeCreate( unsigned long* ip, unsigned short* port, int* node );
extern int L_read( client_t* client, unsigned int len );

#endif /* _L_H_ */

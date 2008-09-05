#include "L.h"
#include "N.h"

int L_sendPacket( client_t* client, const char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	if( packet == NULL || len == 0 ) {
		return 0;
	}

	if( !N_sendto( client->node, packet, len, ip, port ) ) {
		return 0;
	}

	return 1;
}

int L_sendBroadcast( client_t* client, const char* packet, unsigned int len, unsigned short port ) {
	if( packet == NULL || len == 0 ) {
		return 0;
	}

	if( !N_sendto( client->node, packet, len, 0xFFFFFFFF, port ) ) {
		return 0;
	}

	return 1;
}

int L_nodeCreate( unsigned long* ip, unsigned short* port, int* node ) {
	if( ip == NULL || port == NULL || node == NULL ) {
		return 0;
	}

	if( !N_socket( node ) ) {
		*node = -1;

		return 0;
	}

	if( !N_bind( *node, *ip, *port ) ) {
		N_close( *node );
		*node = -1;

		return 0;
	}

	if( !N_getLAddr( *node, ip, port ) ) {
		/* NOTE: Ignore the error for now... */
	}

	return 1;
}

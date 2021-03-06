#include "L.h"
#include "N.h"
#include "M.h"
#include "E.h"

int L_sendPacket( client_t* client, const char* packet, unsigned int len, unsigned short port ) {
	ip_address ipaddr = *( ip_address* ) &client->node_ip;

	if( packet == NULL || len == 0 ) {
		printf( "%s failed: length is null...\n", __FUNCTION__ );
		return 0;
	}

	#if DEBUG
	printf( "L >> Transmitting broadcast to %u.%u.%u.%u:%u\n", ipaddr.byte1, ipaddr.byte2, ipaddr.byte3, ipaddr.byte4, port );
	#endif

	if( !N_sendto( client->node, packet, &len, client->node_ip, port ) ) {
		if( N_lastError( ) == WSAEADDRNOTAVAIL ) {
			return 1;
		}

		return 0;
	}

	return 1;
}

int L_sendBroadcast( client_t* client, const char* packet, unsigned int len, unsigned short port ) {
	if( packet == NULL || len == 0 ) {
		printf( "%s failed: length is null...\n", __FUNCTION__ );
		return 0;
	}

	#if DEBUG
	printf( "L >> Transmitting broadcast to 255.255.255.255:%u\n", port );
	#endif

	if( !N_sendto( client->node, packet, &len, 0xFFFFFFFF, port ) ) {
		if( N_lastError( ) == WSAEADDRNOTAVAIL ) {
			return 1;
		}

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

	if( !N_setBroadcast( *node, 1 ) ) {
		N_close( *node );
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

static int L_parse( client_t* client, unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	int retval = 0;

	if( len == 0 ) {
		return 0;
	}

	retval = E_sendPacket( client, packet, len, port );
	M_free( packet );

	return retval;
}

int L_read( client_t* client, unsigned int len ) {
	unsigned char* buffer = NULL;
	unsigned long ip = 0;
	unsigned short port = 0;

	if( client == NULL ) {
		return 0;
	}

	buffer = M_alloc( len );

	if( !N_recvfrom( client->node, buffer, &len, &ip, &port ) ) {
		fprintf( stderr, "\nError receiving.\n" );
		M_free( buffer );

		return 0;
	}

	return L_parse( client, buffer, len, ip, port );
}

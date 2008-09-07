#include "E.h"
#include "N.h"
#include "L.h"
#include "T.h"
#include "M.h"
#include "C.h"
#include "utils.h"

#define E_PACKET_PING			1
#define E_PACKET_DATA			2
#define E_PACKET_BROADCAST		3
#define E_PACKET_QUIT			4
#define E_PACKET_SHAKE			5

typedef struct E_s {
	int init;
	ip_address ip;
	unsigned short port;
	int sck;
	client_t* clients;

} E_t;


static void E_clearClients( void );
static int E_read( unsigned int len );
static int E_parse( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port );
static client_t* E_getClient( unsigned long ip, unsigned short port );
static client_t* E_addClient( unsigned long ip, unsigned short port, int node, unsigned long node_ip, unsigned short node_port );
static void E_delClient( unsigned long ip, unsigned short port );
static int E_onShake( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port );
static int E_onBroadcast( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port );
static int E_onPing( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port );
static int E_onData( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port );
static int E_onQuit( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port );


static E_t E = { 0 };

int E_isInit( void ) {
	return E.init;
}

int E_init( pcap_if_t* dev ) {
	struct sockaddr_in* a;

	if( dev == NULL ) {
		return 0;
	}

	if( E_isInit( ) ) {
		return 0;
	}

	E.clients = NULL;
	memset( &E.ip, 0, sizeof( E.ip ) );
	E.port = 0;
	E.sck = -1;

	if( !N_isInit( ) ) {
		if( !N_init( ) ) {
			fprintf( stderr, "\nUnable to initialize N.\n" );

			return 0;
		}
	}

	a = ( struct sockaddr_in* ) dev->addresses->addr;

	if( !a ) {
		fprintf( stderr, "\nUnable to determine the address of the transmitting device.\n" );

		return 0;
	}

	memcpy( &E.ip, &a->sin_addr, sizeof( E.ip ) );

	printf( "Addr: %d.%d.%d.%d\n",
			E.ip.byte1,
			E.ip.byte2,
			E.ip.byte3,
			E.ip.byte4 );

	if( !N_socket( &E.sck ) ) {
		fprintf( stderr, "\nFailed to create socket.\n" );

		return 0;
	}

	if( !N_bind( E.sck, a->sin_addr.s_addr, 16788 ) ) {
		fprintf( stderr, "\nFailed to bind socket.\n" );
		N_close( E.sck );
		E.sck = -1;

		return 0;
	}

	E.init = 1;

	return 1;
}

void E_quit( void ) {
	E.init = 0;

	if( E.sck != -1 ) {
		N_close( E.sck );
		E.sck = -1;
	}

	memset( &E.ip, 0, sizeof( E.ip ) );
	E.port = 0;
	E_clearClients( );
}

static void E_clearClients( void ) {
	client_t* client;

	while( E.clients ) {
		client = E.clients->next;
		M_free( E.clients );
		E.clients = client;
	}
}

static client_t* E_getClient( unsigned long ip, unsigned short port ) {
	client_t* client = NULL;

	for( client = E.clients; client; client = client->next ) {
		if( client->ip == ip && client->port == port ) {
			break;
		}
	}

	return client;
}

static client_t* E_addClient( unsigned long ip, unsigned short port, int node, unsigned long node_ip, unsigned short node_port ) {
	client_t* client;

	client = M_alloc( sizeof( *client ) );
	client->next = E.clients;
	client->ip = ip;
	client->port = port;
	client->node = node;
	client->node_ip = node_ip;
	client->node_port = node_port;
	client->pingTimeout.interval = 10000;
	client->pingInterval.interval = 2000;
	T_init( &client->pingTimeout );
	T_init( &client->pingInterval );
	E.clients = client;

	return client;
}

static void E_delClient( unsigned long ip, unsigned short port ) {
	client_t* client = NULL;
	client_t* prev = NULL;

	for( client = E.clients; client; client = client->next ) {
		if( client->ip == ip && client->port == port ) {
			if( prev == NULL ) {
				client = client->next;
				M_free( E.clients );
				E.clients = client;
			} else {
				prev->next = client->next;
				M_free( client );
			}

			break;
		}
	}
}

static int E_sendPing( client_t* client, unsigned int id ) {
	char buffer[ 16 ];
	unsigned int len = 0;

	*buffer = E_PACKET_PING;
	len++;

	memcpy( buffer + len, &id, sizeof( id ) );
	len += sizeof( id );

	return N_sendto( E.sck, buffer, len, client->ip, client->port );
}

static int E_sendPacket( client_t* client, const unsigned char* packet, unsigned int plen, unsigned short port ) {
	char buffer[ 2048 ];
	unsigned int len = 0;

	*buffer = E_PACKET_DATA;
	len++;

	memcpy( buffer + len, &port, sizeof( port ) );
	len += sizeof( port );

	memcpy( buffer + len, packet, plen );
	len += plen;

	return N_sendto( E.sck, buffer, len, client->ip, client->port );
}

static int E_sendBroadcast( client_t* client, const unsigned char* packet, unsigned int plen, unsigned short port ) {
	char buffer[ 2048 ];
	unsigned int len = 0;

	*buffer = E_PACKET_BROADCAST;
	len++;

	memcpy( buffer + len, &port, sizeof( port ) );
	len += sizeof( port );

	memcpy( buffer + len, packet, plen );
	len += plen;

	return N_sendto( E.sck, buffer, len, client->ip, client->port );
}

static int E_sendGoodbye( client_t* client ) {
	char buffer[ 16 ];
	unsigned int len = 0;

	*buffer = E_PACKET_QUIT;
	len++;

	return N_sendto( E.sck, buffer, len, client->ip, client->port );
}

static int E_sendShake( unsigned int id, unsigned long ip, unsigned short port ) {
	char buffer[ 16 ];
	unsigned int len = 0;

	*buffer = E_PACKET_SHAKE;
	len++;

	memcpy( buffer + len, &id, sizeof( id ) );
	len += sizeof( id );

	return N_sendto( E.sck, buffer, len, ip, port );
}

static int E_onShake( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	client_t* client = NULL;
	unsigned int id = 0;

	/* TODO: Verify the length of the packet not to get a buffer overflow */
	client = E_getClient( ip, port );
	memcpy( &id, packet, 4 );
	packet += 4;
	len -= 4;

	if( client == NULL ) {
		int node = -1;
		unsigned long node_ip = 0;
		unsigned short node_port = 0;

		/* TODO: Bind it to the listener IP */
		if( !L_nodeCreate( &node_ip, &node_port, &node ) ) {
			return 0;
		}

		client = E_addClient( ip, port, node, node_ip, node_port );

		return E_sendShake( id, ip, port );
	} else {
		/* TODO */
		/* has the client replied yet? Y: then ignore this, N: now it has */
	}

	return 1;
}

static int E_onBroadcast( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	client_t* client = NULL;
	unsigned short bport = 0;
	ip_address ipaddr;

	client = E_getClient( ip, port );

	if( client == NULL ) {
		return 1;
	}

	memcpy( &bport, packet, sizeof( bport ) );
	packet += sizeof( bport );
	len -= sizeof( bport );

	L_sendBroadcast( client, packet, len, bport );
	printf( "Received %u bytes.\n", len );

	memcpy( &ipaddr, &client->ip, sizeof( client->ip ) );

	printf( "From %u.%u.%u.%u:%u\t",
		ipaddr.byte1,
		ipaddr.byte2,
		ipaddr.byte3,
		ipaddr.byte4,
		client->port );

	memcpy( &ipaddr, &client->node_ip, sizeof( client->node_ip ) );

	printf( "To %u.%u.%u.%u:%u\n",
		ipaddr.byte1,
		ipaddr.byte2,
		ipaddr.byte3,
		ipaddr.byte4,
		client->node_port );

	return 1;
}

static int E_onPing( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	client_t* client = NULL;
	unsigned int id = 0;

	client = E_getClient( ip, port );

	if( client == NULL ) {
		return 1;
	}

	memcpy( &id, packet, sizeof( id ) );
	packet += sizeof( id );
	len -= sizeof( id );

	if( client->lastPingID != id ) {
		if( !E_sendPing( client, id ) ) {
			return 0;
		}
	}

	T_init( &client->pingTimeout );
	T_init( &client->pingInterval );

	return 1;
}

static int E_onData( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	client_t* client = NULL;
	unsigned short sport = 0;

	client = E_getClient( ip, port );

	if( client == NULL ) {
		return 1;
	}

	memcpy( &sport, packet, sizeof( sport ) );
	packet += sizeof( sport );
	len -= sizeof( sport );

	return L_sendPacket( client, packet, len, sport );
}

static int E_onQuit( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	E_delClient( ip, port );

	return 1;
}

static int E_parse( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	int retval = 0;
	unsigned char* data = packet + 1;

	if( len == 0 ) {
		return 1;
	}

	len--;

	switch( *packet ) {
		default: {
			break;
		}

		case E_PACKET_PING: {
			retval = E_onPing( data, len, ip, port );

			break;
		}

		case E_PACKET_DATA: {
			retval = E_onData( data, len, ip, port );

			break;
		}

		case E_PACKET_BROADCAST: {
			retval = E_onBroadcast( data, len, ip, port );

			break;
		}

		case E_PACKET_QUIT: {
			retval = E_onQuit( data, len, ip, port );

			break;
		}

		case E_PACKET_SHAKE: {
			retval = E_onShake( data, len, ip, port );

			break;
		}
	}

	M_free( packet );

	return retval;
}

static int E_read( unsigned int len ) {
	unsigned char* buffer = NULL;
	unsigned long ip = 0;
	unsigned short port = 0;

	buffer = M_alloc( len );

	if( !N_recvfrom( E.sck, buffer, &len, &ip, &port ) ) {
		fprintf( stderr, "\nError receiving.\n" );
		M_free( buffer );

		return 0;
	}

	return E_parse( buffer, len, ip, port );
}

void E_preQuit( void ) {
	client_t* next = NULL;

	while( E.clients ) {
		next = E.clients->next;
		E_sendGoodbye( E.clients );
		free( E.clients );
		E.clients = next;
	}
}

void E_postInit( void ) {
	netNode_t* node = NULL;

	node = C_network;

	while( node ) {
		E_sendShake( 0 /* TODO */, node->ip, node->port );
		node = node->next;
	}
}

int E_step( void ) {
	unsigned int len = 0;
	client_t* client = NULL;
	client_t* prev = NULL;

	client = E.clients;

	while( client ) {
		T_update( &client->pingTimeout );

		if( T_fire( &client->pingTimeout ) ) {
			client_t* next = client->next;

			if( prev == NULL ) {
				E.clients = next;
			} else {
				prev->next = next;
			}

			M_free( client );
			client = next;

			continue;
		}

		T_update( &client->pingInterval );

		if( T_fire( &client->pingInterval ) ) {
			E_sendPing( client, client->pingInterval.current );
			T_init( &client->pingInterval );
		}

		do {
			if( !N_ioctl( client->node, &len ) ) {
				/* TODO: Process this error. */
				break;
			}

			if( len <= 0 ) {
				break;
			}

			L_read( client, len );

		} while( 0 );

		client = client->next;
	}

	if( !N_ioctl( E.sck, &len ) ) {
		return 0;
	}

	if( len <= 0 ) {
		return 1;
	}

	return E_read( len );
}

int E_in_S( const unsigned char* packet, unsigned int plen ) {
	const unsigned char* data = NULL;
	unsigned int len = 0;
	const ip_header* ih = NULL;
	const udp_header* uh = NULL;
	unsigned int ip_len = 0;
	unsigned short port = 0;
	client_t* client = NULL;

	ih = ( const ip_header* )( packet + 14 );
	ip_len = ( ih->ver_ihl & 0xF ) * 4;
	uh = ( const udp_header* )( ( const unsigned char* ) ih + ip_len );
	port = uh->dport;
	len = uh->len;
	data = ( const unsigned char* ) uh + sizeof( *uh );

	/*printf( "Transferring %u bytes\n", len );*/

	for( client = E.clients; client; client = client->next ) {
		/*if( !client->registered ) {
			continue;
		}*/

		if( !E_sendBroadcast( client, data, len, port ) ) {
			/* TODO: handle this error */
		}
	}

	return 1;
}

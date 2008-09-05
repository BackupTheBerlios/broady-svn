#include "E.h"
#include "N.h"
#include "L.h"
#include "T.h"
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
static client_t* E_addClient( unsigned long ip, unsigned short port, int node );
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
		free( E.clients );
		E.clients = client;
	}
}

static client_t* E_getClient( unsigned long ip, unsigned short port ) {
	client_t* client = NULL;

	for( client = E.clients; client; client = client->next ) {
		if( !memcpy( &client->ip, &ip, sizeof( client->ip ) ) && client->port == port ) {
			break;
		}
	}

	return client;
}

static client_t* E_addClient( unsigned long ip, unsigned short port, int node, unsigned long node_ip, unsigned short node_port ) {
	client_t* client;

	client = malloc( sizeof( *client ) );
	client->next = E.clients;
	memcpy( &client->ip, &ip, sizeof( client->ip ) );
	client->port = port;
	client->node = node;
	client->node_ip = node_ip;
	client->node_port = node_port;
	E.clients = client;

	return client;
}

static void E_delClient( unsigned long ip, unsigned short port ) {
	client_t* client = NULL;
	client_t* prev = NULL;

	for( client = E.clients; client; client = client->next ) {
		if( !memcpy( &client->ip, &ip, sizeof( client->ip ) ) && client->port == port ) {
			if( prev == NULL ) {
				client = client->next;
				free( E.clients );
				E.clients = client;
			} else {
				prev->next = client->next;
				free( client );
			}

			break;
		}
	}
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
	}

	return 1;
}

static int E_onBroadcast( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	client_t* client;

	client = E_getClient( ip, port );

	if( client == NULL ) {
		return 0;
	}

	L_sendBroadcast( client, packet, len );
	printf( "Received %u bytes.\n", len );

	printf( "From %d.%d.%d.%d:%d\tTo %d.%d.%d.%d:%d\n",
		client->ip.byte1,
		client->ip.byte2,
		client->ip.byte3,
		client->ip.byte4,
		client->port,
		client->node_ip.byte1,
		client->node_ip.byte2,
		client->node_ip.byte3,
		client->node_ip.byte4,
		client->node_port );

	return 1;
}

static int E_onPing( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	/* TODO */
	return 1;
}

static int E_onData( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	/* TODO */
	return 1;
}

static int E_onQuit( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	/* TODO */
	return 1;
}

static int E_parse( unsigned char* packet, unsigned int len, unsigned long ip, unsigned short port ) {
	int retval = 0;
	unsigned char* data = packet + 1;

	if( len == 0 ) {
		return 0;
	}

	switch( *packet ) {
		default: {
			break;
		}

		case E_PACKET_PING: {
			retval = E_onPing( data, len, ip, port );
		}

		case E_PACKET_DATA: {
			retval = E_onData( data, len, ip, port );
		}

		case E_PACKET_BROADCAST: {
			retval = E_onBroadcast( data, len, ip, port );
		}

		case E_PACKET_QUIT: {
			retval = E_onQuit( data, len, ip, port );
		}

		case E_PACKET_SHAKE: {
			retval = E_onShake( data, len, ip, port );
		}
	}

	free( packet );

	return retval;
}

static int E_read( unsigned int len ) {
	unsigned char* buffer = NULL;
	unsigned long ip = 0;
	unsigned short port = 0;

	buffer = malloc( len );

	if( !N_recvfrom( E.sck, buffer, &len, &ip, &port ) ) {
		fprintf( stderr, "\nError receiving.\n" );
		free( buffer );

		return 0;
	}

	return E_parse( buffer, len, ip, port );
}

int E_step( void ) {
	unsigned int len = 0;

	if( !N_ioctl( E.sck, &len ) ) {
		return 0;
	}

	if( len <= 0 ) {
		return 1;
	}

	return E_read( len );
}

int E_in_S( const unsigned char* packet, unsigned int len ) {
	unsigned char* buffer;
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;

	buffer = malloc( len );
	memcpy( buffer, packet, len );

	ih = ( ip_header* )( buffer + 14 );
	ip_len = ( ih->ver_ihl & 0xF ) * 4;
	uh = ( udp_header* )( ( unsigned char* ) ih + ip_len );

	memcpy( &ih->saddr, &E.ip, 4 );
	ih->crc = 0;
	ih->crc = ip_sum_calc( ip_len, ( void* ) ih );
	printf( "Transferring %u bytes\n", len );

	/*for( i = 0; i < sizeof( S.network_list ) / sizeof( *network_list ); i++ ) {
		if( memcmp( &emit_addr, &network_list[i], 4 ) == 0 ) {
			continue;
		}

		emit_send( sck, &network_list[i], buffer, len );
	}*/

	free( buffer );

	return 1;
}

#include "S.h"
#include "E.h"
#include "utils.h"

typedef struct S_s {
	pcap_t* handle;
	ip_address ip;

} S_t;

static void S_packet_handler( unsigned char* param, const struct pcap_pkthdr* header, const unsigned char* pkt_data );
static int S_filter_packet( ip_header* ih, udp_header* uh );

static S_t S;

int S_init( pcap_if_t* dev ) {
	char errbuf[ PCAP_ERRBUF_SIZE ];

	if( dev == NULL ) {
		return 0;
	}

	if( !dev->addresses->addr ) {
		fprintf( stderr, "\nUnable to determine the address of the sniffing device.\n" );

		return 0;
	}

	memcpy( &S.ip, &( ( struct sockaddr_in* ) dev->addresses->addr )->sin_addr, sizeof( S.ip ) );

	S.handle = open_iface( dev );

	if( S.handle == NULL ) {
		return 0;
	}

	if( pcap_setnonblock( S.handle, 0, errbuf ) == -1 ) {
		fprintf( stderr, "\nUnable to activate non-blocking mode: %s\n", errbuf );
	}

	return 1;
}

void S_quit( void ) {
	S.handle = NULL;
}

int S_step( void ) {
	if( pcap_dispatch( S.handle, 0, S_packet_handler, NULL ) == -1 ) {
		return 0;
	}

	return 1;
}

static int S_filter_packet( ip_header* ih, udp_header* uh ) {
	unsigned long daddr = 0xFFFFFFFF;

	if( memcmp( &S.ip, &ih->saddr, 4 ) != 0 ) {
		return 0;
	}

	if( memcmp( &ih->daddr, &daddr, 4 ) != 0 ) {
		return 0;
	}

	if( E_isLocalNode( htons( uh->sport ) ) ) {
		return 0;
	}

	return 1;
}

static void S_packet_handler( unsigned char* param, const struct pcap_pkthdr* header, const unsigned char* pkt_data ) {
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;

	ih = ( ip_header* )( pkt_data + 14 );
	ip_len = ( ih->ver_ihl & 0xF ) * 4;
	uh = ( udp_header* )( ( unsigned char* ) ih + ip_len );

	if( !S_filter_packet( ih, uh ) ) {
		return;
	}

	/*sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );*/

	/*printf( "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport );*/

	E_in_S( pkt_data, header->len );
}

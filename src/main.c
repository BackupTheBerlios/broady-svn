#include "utils.h"
#include "S.h"
#include "B.h"
#include "E.h"
#include "L.h"

const ip_address network_list[] = {
	{ 5, 76, 128, 83 },		/* Tide */
	{ 5, 23, 238, 188 },	/* Wolf */
};

int emit_receive( int sck );
int emit_transfer( int sck, const u_char* data, unsigned long len );

int main( void ) {
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* emit_dev;
	pcap_if_t* sniff_dev;

	if( pcap_findalldevs( &alldevs, errbuf ) == -1 ) {
		fprintf( stderr, "Error in pcap_findalldevs: %s\n", errbuf );
		exit( 1 );
	}

	if( alldevs == NULL ) {
		printf( "\nNo interfaces found! Make sure WinPcap is installed.\n" );

		return -1;
	}

	sniff_dev = get_iface( "SNIFFING", alldevs );

	if( sniff_dev == NULL ) {
		goto hell;
	}

	emit_dev = get_iface( "TRANSMITTING", alldevs );

	if( emit_dev == NULL ) {
		goto hell;
	}

	system( "cls" );

	printf( "Listening on %s\n", sniff_dev->description );
	printf( "Transmitting on %s\n\n", emit_dev->description );

	if( !S_init( sniff_dev ) ) {
		fprintf( stderr, "\nFailed to initialize S.\n" );

		goto hell;
	}

	if( !E_init( emit_dev ) ) {
		fprintf( stderr, "\nFailed to initialize E.\n" );

		goto hell;
	}

	pcap_freealldevs( alldevs );

	while( 1 ) {
		S_step( );
		E_step( );
	}

	return 0;

hell:
	pcap_freealldevs( alldevs );
	S_quit( );
	E_quit( );

	return -1;
}


int emit_send( int sck, const ip_address* to, const char* data, unsigned long len ) {
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons( 16788 );
	memcpy( &addr.sin_addr, to, sizeof( addr.sin_addr ) );

	return sendto( sck, data, len, 0, ( const struct sockaddr* ) &addr, sizeof( addr ) );
}

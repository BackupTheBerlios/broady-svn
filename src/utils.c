#include "utils.h"

unsigned short ip_sum_calc( unsigned short len_ip_header, unsigned char buff[] ) {
	unsigned short word16;
	unsigned long sum = 0;
	unsigned short i;

	/* make 16 bit words out of every two adjacent 8 bit words in the packet and add them up */
	for( i = 0; i < len_ip_header; i = i + 2 ) {
		word16 =( ( buff[ i ] << 8 ) & 0xFF00 ) + ( buff[ i + 1 ] & 0xFF );
		sum = sum + ( unsigned long ) word16;
	}

	/* take only 16 bits out of the 32 bit sum and add up the carries */
	while( sum >> 16 ) {
		sum = ( sum & 0xFFFF ) + ( sum >> 16 );
	}

	/* one's complement the result */
	sum = ~sum;

	return ( unsigned short ) sum;
}

int free_alldevs( pcap_if_t* alldevs ) {
	if( alldevs == NULL ) {
		return 0;
	}

	pcap_freealldevs( alldevs );

	return 1;
}

pcap_if_t* get_alldevs( void ) {
	pcap_if_t* alldevs = NULL;
	char errbuf[ PCAP_ERRBUF_SIZE ];

	if( pcap_findalldevs( &alldevs, errbuf ) == -1 ) {
		fprintf( stderr, "Error in pcap_findalldevs: %s\n", errbuf );

		return NULL;
	}

	if( alldevs == NULL ) {
		fprintf( stderr, "No interfaces found! Make sure WinPcap is installed.\n" );
	}

	return alldevs;
}

pcap_t* open_iface( pcap_if_t* d ) {
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	/* Open the adapter */
	if( ( adhandle = pcap_open_live(	d->name,	/* name of the device */
										65536,		/* portion of the packet to capture. */
										1,			/* promiscuous mode */
										100,		/* read timeout */
										errbuf		/* error buffer */
									) ) == NULL ) {
		fprintf( stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name );

		return NULL;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if( pcap_datalink( adhandle ) != DLT_EN10MB ) {
		fprintf( stderr, "\nThis program works only on Ethernet networks.\n" );
		pcap_close( adhandle );

		return NULL;
	}

	if( d->addresses != NULL ) {
		/* Retrieve the mask of the first address of the interface */
		netmask = ( ( struct sockaddr_in* )( d->addresses->netmask ) )->sin_addr.S_un.S_addr;
	} else {
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0x00FFFFFF;
	}

	/* compile the filter */
	if( pcap_compile( adhandle, &fcode, packet_filter, 1, netmask ) < 0 ) {
		fprintf( stderr, "\nUnable to compile the packet filter. Check the syntax.\n" );
		pcap_close( adhandle );

		return NULL;
	}

	/* set the filter */
	if( pcap_setfilter( adhandle, &fcode ) < 0 ) {
		fprintf( stderr, "\nError setting the filter.\n" );
		pcap_close( adhandle );

		return NULL;
	}

	return adhandle;
}

pcap_if_t* get_iface( char* desc, pcap_if_t* alldevs ) {
	int i = 0;
	int inum = 0;
	pcap_if_t* d = NULL;

	system( "cls" );

	/* Print the list */
	for( d = alldevs; d; d = d->next ) {
		printf( "%d. ", ++i );

		if( d->description ) {
			printf( "%s\n", d->description );
		} else {
			printf( "%s\n", d->name );
		}
	}

	printf( "\nEnter the %s interface number (1-%d): ", desc, i );
	scanf( "%d", &inum );
	printf( "\n" );

	/* Check if the user specified a valid adapter */
	if( inum < 1 || inum > i ) {
		printf( "\nAdapter number out of range.\n" );

		return NULL;
	}

	/* Jump to the selected adapter */
	for( d = alldevs, i = 0; i < inum - 1 ; d = d->next, i++ )
		;

	return d;
}

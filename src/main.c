#include "utils.h"
#include "S.h"
#include "E.h"
#include "L.h"
#include "N.h"
#include "M.h"
#include "C.h"
#include <conio.h>

netNode_t* C_network = NULL;

static pcap_if_t* alldevs = NULL;
static pcap_if_t* emit_dev = NULL;
static pcap_if_t* sniff_dev = NULL;

int PreInit( void ) {
	freopen( "stderr.txt", "wt", stderr );

	/* load config */
	C_network = C_loadNetwork( "network.txt" );
	_getch( );

	alldevs = get_alldevs( );

	if( alldevs == NULL ) {
		return 0;
	}

	sniff_dev = get_iface( "SNIFFING", alldevs );

	if( sniff_dev == NULL ) {
		free_alldevs( alldevs );

		return 0;
	}

	emit_dev = get_iface( "TRANSMITTING", alldevs );

	if( emit_dev == NULL ) {
		free_alldevs( alldevs );

		return 0;
	}

	system( "cls" );

	return 1;
}

int Init( void ) {
	if( !N_init( ) ) {
		fprintf( stderr, "\nFailed to initialize N.\n" );
		free_alldevs( alldevs );

		return 0;
	}

	if( !S_init( sniff_dev ) ) {
		fprintf( stderr, "\nFailed to initialize S.\n" );
		free_alldevs( alldevs );

		return 0;
	}

	if( !E_init( emit_dev ) ) {
		fprintf( stderr, "\nFailed to initialize E.\n" );
		free_alldevs( alldevs );

		return 0;
	}

	return 1;
}

int PostInit( void ) {
	printf( "Listening on %s\n", sniff_dev->description );
	printf( "Transmitting on %s\n\n", emit_dev->description );

	free_alldevs( alldevs );
	alldevs = NULL;
	sniff_dev = NULL;
	emit_dev = NULL;

	E_postInit( );

	return 1;
}

int Step( void ) {
	if( !S_step( ) ) {
		fprintf( stderr, "\nS failed.\n" );

		return 0;
	}

	if( !E_step( ) ) {
		fprintf( stderr, "\nE failed.\n" );

		return 0;
	}

	return 1;
}

void PreQuit( void ) {
	E_preQuit( );
}

void Quit( void ) {
	S_quit( );
	E_quit( );
	N_quit( );
}

void PostQuit( void ) {
	M_dumpLeaks( );
}

int main( void ) {
	if( !PreInit( ) ) {
		return -3;
	}

	if( !Init( ) ) {
		PostQuit( );

		return -2;
	}

	if( !PostInit( ) ) {
		Quit( );
		PostQuit( );

		return -1;
	}

	while( Step( ) ) {
		if( _kbhit( ) ) {
			if( ( _getch( ) & 223 ) == 'Q' ) {
				break;
			}
		}
	}

	PreQuit( );
	Quit( );
	PostQuit( );

	return 0;
}

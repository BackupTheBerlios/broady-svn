#include "C.h"
#include "M.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>

netNode_t* C_loadNetwork( const char* path ) {
	netNode_t* node = NULL;
	netNode_t* next = NULL;
	FILE* fp = NULL;
	/*char buffer[ 16 ];
	int comment_pi = 0;
	int comment_in = 0;
	int comment_po = 0;
	int pos = 0;*/
	char buffer[ 256 ];
	ip_address ip;

	fp = fopen( path, "rt" );

	if( fp == NULL ) {
		return NULL;
	}

	memset( &ip, 0, sizeof( ip ) );

	/*buffer[ 0 ] = 0;

	while( !feof( fp ) ) {
		unsigned char c = 0;

		c = fgetc( fp );

		if( feof( fp ) ) {
			break;
		}

		if( comment_in == 1 ) {
			if( c == '*' ) {
				comment_po = 1;
			} else if( c == '/' ) {
				if( comment_po ) {
					comment_in = 0;
				}

				comment_po = 0;
			} else {
				comment_po = 0;
			}

			continue;
		} else if( comment_in == 2 ) {
			if( c == '\n' ) {
				comment_in = 0;
			} else {
				continue;
			}
		}

		if( c == '/' ) {
			if( comment_pi ) {
				comment_pi = 0;
				comment_in = 2;
			} else {
				comment_pi = 1;
			}
		} else if( c == '*' ) {
			if( comment_pi ) {
				comment_pi = 0;
				comment_in = 1;
			}
		} else if( c == '\n' ) {
		} else if( c == '.' ) {
		} else if( c == ':' ) {
		} else if( c >= '0' && c <= '9' ) {
			buffer[ pos++ ] = c;
		}
	}*/

	while( !feof( fp ) ) {
		fscanf( fp, "%s = %u", buffer, &ip.byte1 );
		printf( "%s = ", buffer );
		fscanf( fp, "%s", buffer );
		ip.byte2 = atol( buffer );
		fscanf( fp, "%s", buffer );
		ip.byte3 = atol( buffer );
		fscanf( fp, "%s\n", buffer );
		ip.byte4 = atol( buffer );
		printf( "%u.%u.%u.%u\n", ip.byte1, ip.byte2, ip.byte3, ip.byte4 );

		next = node;
		node = malloc( sizeof( *node ) );
		node->next = next;
		memcpy( &node->ip, &ip, sizeof( ip ) );
		node->port = 16788;
	}

	fclose( fp );

	return node;
}

int C_unloadNetwork( netNode_t* node ) {
	netNode_t* next = NULL;

	if( node == NULL ) {
		return 0;
	}

	while( node ) {
		next = node->next;
		M_free( node );
		node = next;
	}

	return 1;
}

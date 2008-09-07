#include "C.h"
#include "M.h"
#include <stdlib.h>
#include <stdio.h>

netNode_t* C_loadNetwork( const char* path ) {
	netNode_t* node = NULL;
	FILE* fp = NULL;
	char buffer[ 16 ];
	int comment_pi = 0;
	int comment_in = 0;
	int comment_po = 0;
	int pos = 0;

	fp = fopen( path, "rt" );

	if( fp == NULL ) {
		return NULL;
	}

	buffer[ 0 ] = 0;

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

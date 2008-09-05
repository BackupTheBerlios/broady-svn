#include "N.h"
#include <winsock2.h>
#include <stdio.h>

typedef struct N_s {
	int init;

} N_t;

static N_t N = { 0 };

int N_isInit( void ) {
	return N.init;
}

int N_init( void ) {
	struct WSAData wsdata;

	if( N_isInit( ) ) {
		return 0;
	}

	if( WSAStartup( 0x0101, &wsdata ) ) {
		fprintf( stderr, "\n%s failed: %ld\n", __FUNCTION__, GetLastError( ) );

		return 0;
	}

	N.init = 1;

	return 1;
}

void N_quit( void ) {
	if( N_isInit( ) ) {
		WSACleanup( );
	}

	N.init = 0;
}

int N_getLAddr( int sck, unsigned long* ip, unsigned short* port ) {
	struct sockaddr_in name;
	int namelen = sizeof( name );

	if( getsockname( sck, ( struct sockaddr* ) &name, &namelen ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	memcpy( ip, &name.sin_addr, sizeof( *ip ) );
	*port = htons( name.sin_port );

	return 1;
}

int N_socket( int* sck ) {
	if( sck == NULL ) {
		return 0;
	}

	*sck = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );

	if( *sck == INVALID_SOCKET ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	return 1;
}

int N_close( int sck ) {
	if( closesocket( sck ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );
		perror( NULL );

		return 0;
	}

	return 1;
}

int N_sendto( int sck, const void* data, unsigned int len, unsigned long ip, unsigned short port ) {
	struct sockaddr_in addr;

	if( sck == INVALID_SOCKET || data == NULL || len == 0 ) {
		return 0;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons( port );
	addr.sin_addr.s_addr = ip;

	if( sendto( sck, data, len, 0, ( const struct sockaddr* ) &addr, sizeof( addr ) ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	return 1;
}

int N_ioctl( int sck, unsigned int* len ) {
	unsigned long arg = 1;

	if( sck == INVALID_SOCKET || len == NULL ) {
		return 0;
	}

	if( ioctlsocket( sck, FIONREAD, &arg ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	*len = arg;

	return 1;
}

int N_bind( int sck, unsigned long ip, unsigned short port ) {
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons( port );
	addr.sin_addr.s_addr = ip;

	if( bind( sck, ( const struct sockaddr* ) &addr, sizeof( addr ) ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	return 1;
}

int N_recvfrom( int sck, void* buffer, unsigned int* len, unsigned long* ip, unsigned short* port ) {
	unsigned long arg = 1;
	struct sockaddr_in addr;
	unsigned int size;

	if( sck == INVALID_SOCKET || len == NULL || ( buffer != NULL && *len == 0 ) ) {
		return 0;
	}

	if( ioctlsocket( sck, FIONREAD, &arg ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	if( buffer == NULL ) {
		*len = arg;

		return 1;
	}

	if( arg > *len ) {
		*len = arg;

		return 0;
	}

	size = sizeof( addr );
	addr.sin_family = AF_INET;

	if( recvfrom( sck, buffer, arg, 0, ( struct sockaddr* ) &addr, &size ) == -1 ) {
		fprintf( stderr, "\n%s failed: %d\n", __FUNCTION__, WSAGetLastError( ) );

		return 0;
	}

	return 1;
}

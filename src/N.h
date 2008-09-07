#ifndef _N_H_
#define _N_H_

extern int N_isInit( void );
extern int N_init( void );
extern void N_quit( void );

extern int N_setBroadcast( int sck, int opt );
extern int N_lastError( void );
extern int N_socket( int* sck );
extern int N_close( int sck );
extern int N_ioctl( int sck, unsigned int* len );
extern int N_bind( int sck, unsigned long ip, unsigned short port );
extern int N_sendto( int sck, const void* data, unsigned int* len, unsigned long ip, unsigned short port );
extern int N_recvfrom( int sck, void* buffer, unsigned int* len, unsigned long* ip, unsigned short* port );
extern int N_getLAddr( int sck, unsigned long* ip, unsigned short* port );

#endif /* _N_H_ */

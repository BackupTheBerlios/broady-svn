#ifndef _E_H_
#define _E_H_

#include <pcap.h>

#include "T.h"
#include "utils.h"

extern int E_isInit( void );
extern int E_init( pcap_if_t* dev );
extern void E_postInit( void );
extern int E_step( void );
extern void E_preQuit( void );
extern void E_quit( void );
extern int E_in_S( const unsigned char* packet, unsigned int len );

#endif /* _E_H_ */

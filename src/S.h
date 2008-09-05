#ifndef _S_H_
#define _S_H_

#include <pcap.h>

extern int S_init( pcap_if_t* dev );
extern void S_quit( void );

extern int S_step( void );

#endif /* _S_H_ */

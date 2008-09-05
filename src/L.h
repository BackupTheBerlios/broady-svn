#ifndef _L_H_
#define _L_H_

#include "utils.h"

extern int L_in_E( client_t* client, const char* packet, unsigned int len );
extern int L_nodeCreate( unsigned long ip, unsigned short port, int* node );

#endif /* _L_H_ */

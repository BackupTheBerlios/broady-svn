#ifndef _C_H_
#define _C_H_

typedef struct netNode_s {
	struct netNode_s* next;

	unsigned long ip;
	unsigned short port;

} netNode_t;

extern netNode_t* C_loadNetwork( const char* path );
extern int C_unloadNetwork( netNode_t* node );

extern netNode_t* C_network;

#endif /* _C_H_ */

#ifndef _T_H_
#define _T_H_

typedef struct T_s {
	unsigned int interval;
	unsigned int accum;
	unsigned int elapsed;
	unsigned int current;

} T_t;

extern void T_update( T_t* timer );
extern unsigned int T_elapsed( T_t* timer );
extern int T_fire( T_t* timer );
extern void T_init( T_t* timer );

#endif /* _T_H_ */

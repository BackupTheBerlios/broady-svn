#include "T.h"
#include <windows.h>

void T_update( T_t* timer ) {
	unsigned int tick = GetTickCount( );

	timer->elapsed = tick - timer->current;
	timer->current = tick;
	timer->accum += timer->elapsed;
}

unsigned int T_elapsed( T_t* timer ) {
	return timer->elapsed;
}

int T_fire( T_t* timer ) {
	if( timer->accum < timer->interval ) {
		return 0;
	}

	timer->accum -= timer->interval;

	return 1;
}

void T_init( T_t* timer ) {
	unsigned int interval = timer->interval;
	memset( timer, 0, sizeof( *timer ) );
	timer->interval = interval;
	timer->current = GetTickCount( );
}

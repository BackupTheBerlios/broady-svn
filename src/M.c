#include "M.h"
#include <stdlib.h>
#include <stdio.h>

#if M_USE_DEBUG
typedef struct M_block_s {
	struct M_block_s* next;

	const char* file;
	unsigned int line;
	const char* function;

	unsigned int size;
	void* ptr;

} M_block_t;

static M_block_t* M = NULL;

void* M_allocD( unsigned int size, const char* file, unsigned int line, const char* function ) {
	M_block_t* block = NULL;

	block = malloc( sizeof( *block ) + size );

	if( block == NULL ) {
		fprintf( stderr, "M >> Out of memory for %u (%u) bytes >> %s >> %s >> %u\n",
				size, sizeof( *block ) + size, file, function, line );

		return NULL;
	}

	block->next = M;
	block->size = size;
	block->ptr = ( char* ) block + sizeof( *block );
	block->file = file;
	block->line = line;
	block->function = function;
	M = block;

	return block->ptr;
}

void M_freeD( void* ptr, const char* file, unsigned int line, const char* function ) {
	M_block_t* block = ( void* )( ( char* ) ptr - sizeof( *block ) );
	M_block_t* prev = M;

	if( block->ptr != ptr ) {
		fprintf( stderr, "M >> Attempting to free an invalid block >> %s >> %s >> %u\n\n", file, function, line );
		free( ptr );

		return;
	}

	if( block == M ) {
		M = block->next;
		free( block );

		return;
	}

	while( prev->next ) {
		if( block == prev->next ) {
			prev->next = block->next;
			free( block );

			return;
		}
	}

	fprintf( stderr, "M >> Attempting to free a missing block >>\n" );
	fprintf( stderr, "M >> Code >> %s >> %s >> %u\n", file, function, line );
	fprintf( stderr, "M >> Block >> %u (%u) bytes >> %s >> %s >> %u\n\n",
			block->size, block->size + sizeof( *block ), block->file, block->function, block->line );
}

void M_dumpLeaks( void ) {
	M_block_t* block = M;
	M_block_t* next = block;
	unsigned int count = 0;

	while( block ) {
		count++;
		next = block->next;

		fprintf( stderr, "M >> LEAK %p >> %u (%u) bytes >> %s >> %s >> %u\n",
				block->ptr, block->size, block->size + sizeof( *block ), block->file, block->function, block->line );

		free( block );

		block = next;
	}

	if( count == 0 ) {
		fputs( "M >> No leaks were detected.\n\n", stderr );
	} else {
		fprintf( stderr, "M >> %u leak%s detected.\n\n", count, count == 1 ? "" : "s" );
	}
}
#else
void* M_alloc( unsigned int size ) {
	return malloc( size );
}

void M_free( void* ptr ) {
	free( ptr );
}
#endif

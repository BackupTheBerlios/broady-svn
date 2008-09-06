#ifndef _M_H_
#define _M_H_

#define M_USE_DEBUG		1

#if M_USE_DEBUG
#define M_alloc( size )		M_allocD( size, __FILE__, __LINE__, __func__ )
#define M_free( ptr )		M_freeD( ptr, __FILE__, __LINE__, __func__ )

extern void* M_allocD( unsigned int size, const char* file, unsigned int line, const char* function );
extern void M_freeD( void* ptr, const char* file, unsigned int line, const char* function );
extern void M_dumpLeaks( void );
#else
#define M_allocD( size, file, line, function )
#define M_freeD( ptr, file, line, function )
#define M_dumpLeaks( )

extern void* M_alloc( unsigned int size );
extern void M_free( void* ptr );
#endif

#endif /* _M_H_ */

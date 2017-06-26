#ifndef __THREAD_H
#define __THREAD_H

#if defined(__WINDOWS__)
	#include <windows.h>

	typedef CRITICAL_SECTION pthread_mutex_t;

	#define pthread_mutex_init(mutex, attr) (InitializeCriticalSection(mutex))
	#define pthread_mutex_destroy(mutex) (DeleteCriticalSection(mutex))
	#define pthread_mutex_lock(mutex) (EnterCriticalSection(mutex))
	#define pthread_mutex_unlock(mutex) (LeaveCriticalSection(mutex))

#elif defined(__UNIXY__)
	#include <pthread.h>
#endif

#endif

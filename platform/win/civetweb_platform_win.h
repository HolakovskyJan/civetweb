/* Copyright (c) 2013-2017 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#ifndef _CIVETWEB_PLATFORM_WIN_H
#define _CIVETWEB_PLATFORM_WIN_H

#if defined(_MSC_VER) && (_MSC_VER >= 1600)
#	define mg_static_assert static_assert
#endif

 /* DTL -- including winsock2.h works better if lean and mean */
#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <sys/stat.h>

#include <windows.h>
#include <winsock2.h> /* DTL add for SO_EXCLUSIVE */
#include <ws2tcpip.h>

typedef const char *SOCK_OPT_TYPE;
typedef int socklen_t;

#if !defined(PATH_MAX)
#define PATH_MAX (MAX_PATH)
#endif

mg_static_assert(PATH_MAX >= 1, "path length must be a positive number");

#include <process.h>
#include <direct.h>
#include <stdio.h>

#if defined(_MSC_VER)
#define __func__ __FUNCTION__
#endif /* _MSC_VER */

#define ERRNO ((int)(GetLastError()))

#if defined(_WIN64) || defined(__MINGW64__)
#define SSL_LIB "ssleay64.dll"
#define CRYPTO_LIB "libeay64.dll"
#else
#define SSL_LIB "ssleay32.dll"
#define CRYPTO_LIB "libeay32.dll"
#endif

#define O_NONBLOCK (0)
#ifndef W_OK
#define W_OK (2) /* http://msdn.microsoft.com/en-us/library/1w06ktdy.aspx */
#endif
#define LEN_T

#define vsnprintf_impl _vsnprintf
#define snprintf_impl _snprintf
#define mg_sleep(x) (Sleep(x))

#define dlsym(x, y) (GetProcAddress((HINSTANCE)(x), (y)))
#define RTLD_LAZY (0)

typedef HANDLE pthread_mutex_t;
typedef HANDLE pthread_t;
typedef struct {
	HANDLE signal;
	HANDLE broadcast;
} pthread_cond_t;

#ifndef __clockid_t_defined
typedef DWORD clockid_t;
#endif

#if defined(_MSC_VER)
/* Set the thread name for debugging purposes in Visual Studio
* http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
*/
#pragma pack(push, 8)
typedef struct tagTHREADNAME_INFO {
	DWORD dwType;     /* Must be 0x1000. */
	LPCSTR szName;    /* Pointer to name (in user addr space). */
	DWORD dwThreadID; /* Thread ID (-1=caller thread). */
	DWORD dwFlags;    /* Reserved for future use, must be zero. */
} THREADNAME_INFO;
#pragma pack(pop)
#endif

#if !defined(POLLIN)
#ifndef HAVE_POLL
struct pollfd {
	SOCKET fd;
	short events;
	short revents;
};
#define POLLIN (0x0300)
#endif
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC (1)
#endif

#if !defined(_MSC_VER) || (_MSC_VER < 1900)
struct timespec {
	time_t tv_sec; /* seconds */
	long tv_nsec;  /* nanoseconds */
};
#endif

#define END_OF_LINE "\r\n"


#if !defined(WIN_PTHREADS_TIME_H)
int mg_clock_gettime(clockid_t clk_id, struct timespec *tp);
#endif

DWORD pthread_self(void);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_cond_init(pthread_cond_t *cv, const void *unused);
int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex);
int pthread_cond_signal(pthread_cond_t *cv);
int pthread_cond_broadcast(pthread_cond_t *cv);
int pthread_cond_destroy(pthread_cond_t *cv);

#if !defined(NO_SSL_DL) && !defined(NO_SSL)
void path_to_unicode(const char *path,
	wchar_t *wbuf,
	size_t wbuf_len);
HANDLE dlopen(const char *dll_name, int flags);
int dlclose(void *handle);
#endif

#ifndef HAVE_POLL
int poll(struct pollfd *pfd, unsigned int n, int milliseconds);
#endif /* HAVE_POLL */


/* Mark required libraries */
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif

#endif /* _CIVETWEB_PLATFORM_WIN_H */
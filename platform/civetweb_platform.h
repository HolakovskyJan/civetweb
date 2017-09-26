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


#ifndef _CIVETWEB_PLATFORM_H
#define _CIVETWEB_PLATFORM_H

#if CIVETWEB_PLATFORM_WIN
#	include "win/civetweb_platform_win.h"
#elif CIVETWEB_PLATFORM_UNIX
#	include "unix/civetweb_platform_unix.h"
#else
#	include CIVETWEB_PLATFORM_OTHER_HEADER_PATH
#endif


#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#ifndef va_copy
#define va_copy(x, y) ((x) = (y))
#endif

typedef void (* mg_thread_func_t)(void *);
struct mg_thread_arg_wrapper {
	mg_thread_func_t func;
	void * arg;
};

int mg_atomic_inc(volatile int *addr);
int mg_atomic_dec(volatile int *addr);
void * mg_malloc(size_t a);
void * mg_calloc(size_t a, size_t b);
void * mg_realloc(void *a, size_t b);
void mg_free(void *a);
int mg_initialize_mutex(pthread_mutex_t *mutex);
void mg_get_system_name(char *buffer, int buflen);
void mg_get_compiler_info(char *buffer, int buflen);
void gmt_time_string(char *buf, size_t buf_len);
int set_blocking_mode(SOCKET sock, int blocking);
void set_close_on_exec(SOCKET sock);
int mg_start_thread_with_id(mg_thread_func_t func,
	void *param,
	const char *name,
	int priority,
	pthread_t *threadidptr);
int mg_join_thread(pthread_t threadid);
void mg_system_init();
void mg_system_cleanup();

#endif /* _CIVETWEB_PLATFORM_H */

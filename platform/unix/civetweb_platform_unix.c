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


#include "../civetweb_platform.h"


int mg_atomic_inc(volatile int *addr)
{
	return __sync_add_and_fetch(addr, 1);
}

int mg_atomic_dec(volatile int *addr)
{
	return __sync_sub_and_fetch(addr, 1);
}


void * mg_malloc(size_t a)
{
	return malloc(a);
}

void * mg_calloc(size_t a, size_t b)
{
	return calloc(a, b);
}

void * mg_realloc(void *a, size_t b)
{
	return realloc(a, b);
}

void mg_free(void *a)
{
	free(a);
}


int mg_initialize_mutex(pthread_mutex_t *mutex)
{
	pthread_mutexattr_t attr;
	int result;
	
	if ((result = pthread_mutexattr_init(&attr)) == 0)
	{
		if ((result = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) == 0)
		{
			result = pthread_mutex_init(mutex, &attr);
		}
		
		pthread_mutexattr_destroy(&attr);
	}
	
	return result;
}


void mg_set_thread_name(const char *name)
{
	char threadName[16 + 1]; /* 16 = Max. thread length in Linux/OSX/.. */

	snprintf_impl(threadName, sizeof(threadName), "civetweb-%s", name);

#if defined(__GLIBC__)                                                       \
    && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
	/* pthread_setname_np first appeared in glibc in version 2.12*/
	(void)pthread_setname_np(pthread_self(), threadName);
#elif defined(__linux__)
	/* on linux we can use the old prctl function */
	(void)prctl(PR_SET_NAME, threadName, 0, 0, 0);
#endif
}


void get_system_name(char *buffer, int buflen)
{
	struct utsname name;
	memset(&name, 0, sizeof(name));
	uname(&name);
	snprintf_impl(buffer,
		bufsize,
		"%s %s (%s) - %s%s",
		name.sysname,
		name.version,
		name.release,
		name.machine,
		END_OF_LINE);
}


void mg_get_compiler_info(char *buffer, int buflen)
{
#if defined(__GNUC__)
		snprintf_impl(block,
			sizeof(block),
			"gcc: %u.%u.%u%s",
			(unsigned)__GNUC__,
			(unsigned)__GNUC_MINOR__,
			(unsigned)__GNUC_PATCHLEVEL__,
			END_OF_LINE);
		system_info_length += (int)strlen(block);
#else
		snprintf_impl(block, sizeof(block), "Other compiler%s", END_OF_LINE);
#endif
}


int set_blocking_mode(SOCKET sock, int blocking)
{
	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (blocking) {
		(void)fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	} else {
		(void)fcntl(sock, F_SETFL, flags & (~(int)(O_NONBLOCK)));
	}

	return 0;
}

void set_close_on_exec(SOCKET sock)
{
	fcntl(sock, F_SETFD, FD_CLOEXEC);
}


static void * start_thread_wrapper(void *thread_func_arg)
{
	struct mg_thread_arg_wrapper *arg = (struct mg_thread_arg_wrapper *)thread_func_arg;
	arg->func(arg->arg);
	return NULL;
}

int mg_start_thread_with_id(mg_thread_func_t func,
			void *p,
			pthread_t *threadidptr)
{
	pthread_t thread_id;
	pthread_attr_t attr;
	int result;
	struct mg_thread_arg_wrapper arg = {func, p};

	(void)pthread_attr_init(&attr);

#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
	/* Compile-time option to control stack size,
	 * e.g. -DUSE_STACK_SIZE=16384 */
	(void)pthread_attr_setstacksize(&attr, USE_STACK_SIZE);
#endif /* defined(USE_STACK_SIZE) && USE_STACK_SIZE > 1 */

	result = pthread_create(&thread_id, &attr, start_thread_wrapper, arg);
	pthread_attr_destroy(&attr);
	if ((result == 0) && (threadidptr != NULL)) {
		*threadidptr = thread_id;
	}
	return result;
}

int mg_join_thread(pthread_t threadid)
{
	int result;

	result = pthread_join(threadid, NULL);
	return result;
}

void mg_set_master_thread_priority()
{
#if defined(USE_MASTER_THREAD_PRIORITY)
	int min_prio = sched_get_priority_min(SCHED_RR);
	int max_prio = sched_get_priority_max(SCHED_RR);
	if ((min_prio >= 0) && (max_prio >= 0)
	    && ((USE_MASTER_THREAD_PRIORITY) <= max_prio)
	    && ((USE_MASTER_THREAD_PRIORITY) >= min_prio)) {
		struct sched_param sched_param = {0};
		sched_param.sched_priority = (USE_MASTER_THREAD_PRIORITY);
		pthread_setschedparam(pthread_self(), SCHED_RR, &sched_param);
	}
#endif
}

void mg_system_init()
{
	signal(SIGPIPE, SIG_IGN);
}

void mg_system_cleanup()
{
}

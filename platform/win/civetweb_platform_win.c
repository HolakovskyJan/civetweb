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
#include "civetweb_util.h"


#if !defined(WIN_PTHREADS_TIME_H)
int mg_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	ULARGE_INTEGER li;
	BOOL ok = FALSE;
	double d;
	static double perfcnt_per_sec = 0.0;

	(void)clk_id;

	if (tp) {
		memset(tp, 0, sizeof(*tp));
		if (perfcnt_per_sec == 0.0) {
			QueryPerformanceFrequency((LARGE_INTEGER *)&li);
			perfcnt_per_sec = 1.0 / li.QuadPart;
		}
		if (perfcnt_per_sec != 0.0) {
			QueryPerformanceCounter((LARGE_INTEGER *)&li);
			d = li.QuadPart * perfcnt_per_sec;
			tp->tv_sec = (time_t)d;
			d -= tp->tv_sec;
			tp->tv_nsec = (long)(d * 1.0E9);
			ok = TRUE;
		}
	}

	return ok ? 0 : -1;
}
#endif

int mg_atomic_inc(volatile int *addr)
{
	/* Depending on the SDK, this function uses either
	* (volatile unsigned int *) or (volatile LONG *),
	* so whatever you use, the other SDK is likely to raise a warning. */
	return InterlockedIncrement((volatile long *)addr);
}

int mg_atomic_dec(volatile int *addr)
{
	/* Depending on the SDK, this function uses either
	* (volatile unsigned int *) or (volatile LONG *),
	* so whatever you use, the other SDK is likely to raise a warning. */
	return InterlockedDecrement((volatile long *)addr);
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


DWORD pthread_self(void)
{
	return GetCurrentThreadId();
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	return (CloseHandle(*mutex) == 0) ? -1 : 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	return (WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0) ? 0 : -1;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	return (ReleaseMutex(*mutex) == 0) ? -1 : 0;
}

int pthread_cond_init(pthread_cond_t *cv, const void *unused)
{
	(void)unused;

	cv->signal = CreateEvent(NULL, FALSE, FALSE, NULL);
	cv->broadcast = CreateEvent(NULL, TRUE, FALSE, NULL);

	return !cv->signal || !cv->broadcast;
}

int pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex)
{
	HANDLE events[] = { cv->signal, cv->broadcast };

	pthread_mutex_unlock(mutex);
	WaitForMultipleObjects(2, events, FALSE, INFINITE);

	return pthread_mutex_lock(mutex);
}

int pthread_cond_signal(pthread_cond_t *cv)
{
	return SetEvent(cv->signal);
}

int pthread_cond_broadcast(pthread_cond_t *cv)
{
	return SetEvent(cv->broadcast);
}

int pthread_cond_destroy(pthread_cond_t *cv)
{
	return CloseHandle(cv->signal) && CloseHandle(cv->broadcast);
}


int mg_initialize_mutex(pthread_mutex_t *mutex)
{
	*mutex = CreateMutex(NULL, FALSE, NULL);
	return (*mutex == NULL) ? -1 : 0;
}

void mg_set_thread_name(const char *name)
{
	char threadName[16 + 1]; /* 16 = Max. thread length in Linux/OSX/.. */

	snprintf_impl(threadName, sizeof(threadName), "civetweb-%s", name);

#if defined(_MSC_VER)
	/* Visual Studio Compiler */
	__try
	{
		THREADNAME_INFO info;
		info.dwType = 0x1000;
		info.szName = threadName;
		info.dwThreadID = ~0U;
		info.dwFlags = 0;

		RaiseException(0x406D1388,
			0,
			sizeof(info) / sizeof(ULONG_PTR),
			(ULONG_PTR *)&info);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
#elif defined(__MINGW32__)
	/* No option known to set thread name for MinGW */
#endif
}

void mg_get_system_name(char *buffer, int buflen)
{
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild = 0;
	BOOL wowRet, isWoW = FALSE;
	SYSTEM_INFO si;

	GetSystemInfo(&si);

#ifdef _MSC_VER
#	pragma warning(push)
	/* GetVersion was declared deprecated */
#	pragma warning(disable : 4996)
#endif
	dwVersion = GetVersion();
#ifdef _MSC_VER
#	pragma warning(pop)
#endif

	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	wowRet = IsWow64Process(GetCurrentProcess(), &isWoW);

	snprintf_impl(buffer,
		      buflen,
		      "Windows %u.%u%s CPU: type %u, cores %u, mask %x%s",
		      (unsigned)dwMajorVersion,
		      (unsigned)dwMinorVersion,
		      (wowRet ? (isWoW ? " (WoW64)" : "") : " (?)"),
		      (unsigned)si.wProcessorArchitecture,
		      (unsigned)si.dwNumberOfProcessors,
		      (unsigned)si.dwActiveProcessorMask,
		      END_OF_LINE);
}

void mg_get_compiler_info(char *buffer, int buflen)
{
#if defined(_MSC_VER)
	snprintf_impl(buffer,
		buflen,
		"MSC: %u (%u)%s",
		(unsigned)_MSC_VER,
		(unsigned)_MSC_FULL_VER,
		END_OF_LINE);
#elif defined(__MINGW64__) || defined(__MINGW32__)
#	if defined(__MINGW64__)
	snprintf_impl(bbuffer,
		buflen,
		"MinGW64: %u.%u%s",
		(unsigned)__MINGW64_VERSION_MAJOR,
		(unsigned)__MINGW64_VERSION_MINOR,
		END_OF_LINE);
#	endif
	snprintf_impl(buffer,
		buflen,
		"MinGW32: %u.%u%s",
		(unsigned)__MINGW32_MAJOR_VERSION,
		(unsigned)__MINGW32_MINOR_VERSION,
		END_OF_LINE);
#else
	snprintf_impl(block, sizeof(block), "Other compiler%s", END_OF_LINE);
#endif
}


/* For Windows, change all slashes to backslashes in path names. */
static void
change_slashes_to_backslashes(char *path)
{
	int i;

	for (i = 0; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			path[i] = '\\';
		}

		/* remove double backslash (check i > 0 to preserve UNC paths,
		* like \\server\file.txt) */
		if ((path[i] == '\\') && (i > 0)) {
			while ((path[i + 1] == '\\') || (path[i + 1] == '/')) {
				(void)memmove(path + i + 1, path + i + 2, strlen(path + i + 1));
			}
		}
	}
}


#if !defined(NO_SSL_DL) && !defined(NO_SSL)
static int
mg_wcscasecmp(const wchar_t *s1, const wchar_t *s2)
{
	int diff;

	do {
		diff = tolower(*s1) - tolower(*s2);
		s1++;
		s2++;
	} while ((diff == 0) && (s1[-1] != '\0'));

	return diff;
}

/* Encode 'path' which is assumed UTF-8 string, into UNICODE string.
* wbuf and wbuf_len is a target buffer and its length. */
void path_to_unicode(const char *path,
	wchar_t *wbuf,
	size_t wbuf_len)
{
	char buf[PATH_MAX], buf2[PATH_MAX];
	wchar_t wbuf2[MAX_PATH + 1];
	DWORD long_len, err;

	mg_strlcpy(buf, path, sizeof(buf));
	change_slashes_to_backslashes(buf);

	/* Convert to Unicode and back. If doubly-converted string does not
	* match the original, something is fishy, reject. */
	memset(wbuf, 0, wbuf_len * sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int)wbuf_len);
	WideCharToMultiByte(
		CP_UTF8, 0, wbuf, (int)wbuf_len, buf2, sizeof(buf2), NULL, NULL);
	if (strcmp(buf, buf2) != 0) {
		wbuf[0] = L'\0';
	}

	/* Only accept a full file path, not a Windows short (8.3) path. */
	memset(wbuf2, 0, ARRAY_SIZE(wbuf2) * sizeof(wchar_t));
	long_len = GetLongPathNameW(wbuf, wbuf2, ARRAY_SIZE(wbuf2) - 1);
	if (long_len == 0) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			/* File does not exist. This is not always a problem here. */
			return;
		}
	}
	if ((long_len >= ARRAY_SIZE(wbuf2)) || (mg_wcscasecmp(wbuf, wbuf2) != 0)) {
		/* Short name is used. */
		wbuf[0] = L'\0';
	}
}

/* If SSL is loaded dynamically, dlopen/dlclose is required. */
/* Create substitutes for POSIX functions in Win32. */
HANDLE dlopen(const char *dll_name, int flags)
{
	wchar_t wbuf[PATH_MAX];
	(void)flags;
	path_to_unicode(dll_name, wbuf, ARRAY_SIZE(wbuf));
	return LoadLibraryW(wbuf);
}

int dlclose(void *handle)
{
	int result;

	if (FreeLibrary((HMODULE)handle) != 0) {
		result = 0;
	}
	else {
		result = -1;
	}

	return result;
}
#endif /* !defined(NO_SSL_DL) && !defined(NO_SSL) */


#ifndef HAVE_POLL
int poll(struct pollfd *pfd, unsigned int n, int milliseconds)
{
	struct timeval tv;
	fd_set set;
	unsigned int i;
	int result;
	SOCKET maxfd = 0;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	FD_ZERO(&set);

	for (i = 0; i < n; i++) {
		FD_SET((SOCKET)pfd[i].fd, &set);
		pfd[i].revents = 0;

		if (pfd[i].fd > maxfd) {
			maxfd = pfd[i].fd;
		}
	}

	if ((result = select((int)maxfd + 1, &set, NULL, NULL, &tv)) > 0) {
		for (i = 0; i < n; i++) {
			if (FD_ISSET(pfd[i].fd, &set)) {
				pfd[i].revents = POLLIN;
			}
		}
	}

	/* We should subtract the time used in select from remaining
	* "milliseconds", in particular if called from mg_poll with a
	* timeout quantum.
	* Unfortunately, the remaining time is not stored in "tv" in all
	* implementations, so the result in "tv" must be considered undefined.
	* See http://man7.org/linux/man-pages/man2/select.2.html */

	return result;
}
#endif /* HAVE_POLL */


void gmt_time_string(char *buf, size_t buf_len)
{
	struct tm *tm;
	time_t t = time(NULL);

	tm = (gmtime(&t));
	if (tm != NULL) {
		strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", tm);
	}
	else {
		mg_strlcpy(buf, "Thu, 01 Jan 1970 00:00:00 GMT", buf_len);
	}
}


int set_blocking_mode(SOCKET sock, int blocking)
{
	unsigned long non_blocking = !blocking;
	return ioctlsocket(sock, (long)FIONBIO, &non_blocking);
}

void set_close_on_exec(SOCKET sock)
{
	(void)SetHandleInformation((HANDLE)(intptr_t)sock, HANDLE_FLAG_INHERIT, 0);
}


static unsigned __stdcall start_thread_wrapper(void *thread_func_arg)
{
	struct mg_thread_arg_wrapper *arg = (struct mg_thread_arg_wrapper *)thread_func_arg;
	arg->func(arg->arg);
	mg_free(arg);
	return 0;
}

/* Start a thread storing the thread context. */
int mg_start_thread_with_id(mg_thread_func_t func,
	void *p,
	pthread_t *threadidptr)
{
	uintptr_t uip;
	HANDLE threadhandle;
	int result = -1;
	struct mg_thread_arg_wrapper *arg = mg_malloc(sizeof(struct mg_thread_arg_wrapper));
	arg->func = func;
	arg->arg = p;

	uip = _beginthreadex(NULL, 0, start_thread_wrapper, arg, 0, NULL);
	threadhandle = (HANDLE)uip;
	if ((uip != (uintptr_t)(-1L)) && (threadidptr != NULL)) {
		*threadidptr = threadhandle;
		result = 0;
	}

	return result;
}

int mg_join_thread(pthread_t threadid)
{
	int result;
	DWORD dwevent;

	result = -1;
	dwevent = WaitForSingleObject(threadid, INFINITE);
	if (dwevent != WAIT_FAILED) {
		if (dwevent == WAIT_OBJECT_0) {
			CloseHandle(threadid);
			result = 0;
		}
	}

	return result;
}

void mg_set_master_thread_priority()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
}

void mg_system_init()
{
	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data);
}

void mg_system_cleanup()
{
	WSACleanup();
}

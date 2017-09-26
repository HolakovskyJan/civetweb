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


#include "../platform/civetweb_platform.h"
#include "../include/civetweb_util.h"

void mg_strlcpy(register char *dst, register const char *src, size_t n)
{
	for (; *src != '\0' && n > 1; n--) {
		*dst++ = *src++;
	}
	*dst = '\0';
}

int lowercase(const char *s)
{
	return tolower(*(const unsigned char *)s);
}

int mg_strncasecmp(const char *s1, const char *s2, size_t len)
{
	int diff = 0;

	if (len > 0) {
		do {
			diff = lowercase(s1++) - lowercase(s2++);
		} while (diff == 0 && s1[-1] != '\0' && --len > 0);
	}

	return diff;
}

int mg_strcasecmp(const char *s1, const char *s2)
{
	int diff;

	do {
		diff = lowercase(s1++) - lowercase(s2++);
	} while (diff == 0 && s1[-1] != '\0');

	return diff;
}

char * mg_strndup(const char *ptr, size_t len)
{
	char *p;

	if ((p = (char *)mg_malloc(len + 1)) != NULL) {
		mg_strlcpy(p, ptr, len + 1);
	}

	return p;
}

char * mg_strdup(const char *str)
{
	return mg_strndup(str, strlen(str));
}

const char * mg_strcasestr(const char *big_str, const char *small_str)
{
	size_t i, big_len = strlen(big_str), small_len = strlen(small_str);

	if (big_len >= small_len) {
		for (i = 0; i <= (big_len - small_len); i++) {
			if (mg_strncasecmp(big_str + i, small_str, small_len) == 0) {
				return big_str + i;
			}
		}
	}

	return NULL;
}

/* Return null terminated string of given maximum length.
* Report errors if length is exceeded. */
void mg_vsnprintf(int *truncated,
	char *buf,
	size_t buflen,
	const char *fmt,
	va_list ap)
{
	int n, ok;

	if (buflen == 0) {
		if (truncated) {
			*truncated = 1;
		}
		return;
	}

	n = (int)vsnprintf_impl(buf, buflen, fmt, ap);
	ok = (n >= 0) && ((size_t)n < buflen);

	if (ok) {
		if (truncated) {
			*truncated = 0;
		}
	}
	else {
		if (truncated) {
			*truncated = 1;
		}
		n = (int)buflen - 1;
	}
	buf[n] = '\0';
}

void mg_snprintf(int *truncated,
	char *buf,
	size_t buflen,
	const char *fmt,
	...)
{
	va_list ap;

	va_start(ap, fmt);
	mg_vsnprintf(truncated, buf, buflen, fmt, ap);
	va_end(ap);
}

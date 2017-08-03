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

#ifndef _CIVETWEB_UTIL_H
#define _CIVETWEB_UTIL_H

void mg_strlcpy(register char *dst, register const char *src, size_t n);
int lowercase(const char *s);
int mg_strncasecmp(const char *s1, const char *s2, size_t len);
int mg_strcasecmp(const char *s1, const char *s2);
char * mg_strndup(const char *ptr, size_t len);
char * mg_strdup(const char *str);
const char * mg_strcasestr(const char *big_str, const char *small_str);
void mg_vsnprintf(int *truncated,
	char *buf,
	size_t buflen,
	const char *fmt,
	va_list ap);
void mg_snprintf(int *truncated,
	char *buf,
	size_t buflen,
	const char *fmt,
	...);

#endif /* CIVETWEB_UTIL_H */

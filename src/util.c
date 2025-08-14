/* See LICENSE file for copyright and license details. 
 *
 * This is largely adapted from DWM, the dynamic window manager by 
 * suckless.org, originally licensed under the MIT license.
 */
#include <errno.h>
#include <git2/errors.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <git2.h>

#include "util.h"

void
die(const char *fmt, ...)
{
	va_list ap;
	int saved_errno;
	const git_error *e;

	saved_errno = errno;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (fmt[0] && fmt[strlen(fmt)-1] == ':') {
		e = git_error_last();

		if (e->klass != GIT_ERROR_NONE)
			fprintf(stderr, " (%d) %s", e->klass, e->message);
		else {
			fprintf(stderr, " %s", strerror(saved_errno));
		}
	}

	fputc('\n', stderr);

	exit(1);
}

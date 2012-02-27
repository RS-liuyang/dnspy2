

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "log.h"

enum verbosity_value verbosity = 0;

void log_stderr(int level, const char *fmt, ...)
{
    va_list  args;
    va_start(args, fmt);

    log_core(level, stderr,fmt, args);

    va_end(args);
}

//void log_core(int level, FILE *fd, const char *fmt, ...)
void log_core(int level, FILE *fd, const char *fmt, va_list ap)
{
//	va_list ap;
//	va_start(ap, fmt);
	if(verbosity < level)
		return;

	if (fmt != NULL)
		(void)vfprintf(fd, fmt, ap);
	(void)fprintf(fd, "\n");
//	va_end(ap);

}

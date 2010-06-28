#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "debug.h"

void debug(int lvl, int es, char* msg, ...) {
	va_list ap;
	va_start(ap, msg);
	vprintf(msg, ap);
	va_end(ap);
	if (es != 0) exit(es);
}

/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009, 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Nils Durner
 * @author Christian Grothoff
 *
 * @file
 * Plaform specific includes and defines.
 *
 * This file should never be included by installed
 * header files (those starting with "gnunet_").
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#ifndef HAVE_USED_CONFIG_H
#define HAVE_USED_CONFIG_H
#if HAVE_CONFIG_H
#include "gnunet_config.h"
#endif
#endif

#define BREAKPOINT
#define GNUNET_SIGCHLD SIGCHLD

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/**
 * These may be expensive, but good for debugging...
 */
#define ALLOW_EXTRA_CHECKS GNUNET_YES

/**
 * For strptime (glibc2 needs this).
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 499
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

/* configuration options */

#define VERBOSE_STATS 0

#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>         /* superset of previous */
#endif
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <grp.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>             /* for mallinfo on GNU */
#endif
#include <unistd.h>             /* KLB_FIX */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>             /* KLB_FIX */
#include <fcntl.h>
#include <math.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef SOMEBSD
#include <net/if.h>
#endif
#ifdef FREEBSD
#include <semaphore.h>
#endif
#ifdef DARWIN
#include <dlfcn.h>
#include <semaphore.h>
#include <net/if.h>
#endif
#if defined(LINUX) || defined(GNU)
#include <net/if.h>
#endif
#ifdef SOLARIS
#include <sys/sockio.h>
#include <sys/filio.h>
#include <sys/loadavg.h>
#include <semaphore.h>
#endif
#if HAVE_UCRED_H
#include <ucred.h>
#endif
#if HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif
#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#include <errno.h>
#include <limits.h>

#if HAVE_VFORK_H
#include <vfork.h>
#endif

#include <ctype.h>
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#if HAVE_ENDIAN_H
#include <endian.h>
#endif
#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#define DIR_SEPARATOR '/'
#define DIR_SEPARATOR_STR "/"
#define PATH_SEPARATOR ':'
#define PATH_SEPARATOR_STR ":"
#define NEWLINE "\n"

#include "compat.h"

#include <locale.h>
#ifndef FRAMEWORK_BUILD
#include "gettext.h"
/**
 * GNU gettext support macro.
 */
#define _(String) dgettext (PACKAGE, String)
#define LIBEXTRACTOR_GETTEXT_DOMAIN "libextractor"
#else
#include "libintlemu.h"
#define _(String) dgettext ("org.gnunet.gnunet", String)
#define LIBEXTRACTOR_GETTEXT_DOMAIN "org.gnunet.libextractor"
#endif

#include <sys/mman.h>

#ifdef FREEBSD
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#endif

#ifdef DARWIN
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
/* not available on darwin, override configure */
#undef HAVE_STAT64
#undef HAVE_MREMAP
#endif


#if ! HAVE_ATOLL
long long
atoll (const char *nptr);
#endif

#if ENABLE_NLS
#include "langinfo.h"
#endif

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) (-1))
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

/**
 * AI_NUMERICSERV not defined in windows.  Then we just do without.
 */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif


#if defined(__sparc__)
#define MAKE_UNALIGNED(val) ({ __typeof__((val)) __tmp; memmove (&__tmp, &(val), \
                                                                 sizeof((val))); \
                               __tmp; })
#else
#define MAKE_UNALIGNED(val) val
#endif

#define FDTYPE int
#define SOCKTYPE int

/**
 * The termination signal
 */
#define GNUNET_TERM_SIG SIGTERM


#ifndef PATH_MAX
/**
 * Assumed maximum path length.
 */
#define PATH_MAX 4096
#endif

#if HAVE_THREAD_LOCAL_GCC
#define GNUNET_THREAD_LOCAL __thread
#else
#define GNUNET_THREAD_LOCAL
#endif

/**
 * clang et al do not have such an attribute
 */
#if __has_attribute (__nonstring__)
# define __nonstring                    __attribute__((__nonstring__))
#else
# define __nonstring
#endif

#endif

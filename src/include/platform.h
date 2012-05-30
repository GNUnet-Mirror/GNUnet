/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/platform.h
 * @brief plaform specifics
 *
 * @author Nils Durner
 *
 * This file should never be included by installed
 * header files (thos starting with "gnunet_").
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#ifndef HAVE_USED_CONFIG_H
#define HAVE_USED_CONFIG_H
#if HAVE_CONFIG_H
#include "gnunet_config.h"
#endif
#endif

#ifdef WINDOWS
#define BREAKPOINT asm("int $3;");
#define GNUNET_SIGCHLD 17
#else
#define BREAKPOINT
#define GNUNET_SIGCHLD SIGCHLD
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define ALLOW_EXTRA_CHECKS GNUNET_NO

/**
 * For strptime (glibc2 needs this).
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

/* configuration options */

#define VERBOSE_STATS 0

#ifdef CYGWIN
#include <sys/reent.h>
#endif

#ifdef _MSC_VER
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif
#include <Winsock2.h>
#include <ws2tcpip.h>
#else
#ifndef MINGW
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>         /* superset of previous */
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <grp.h>
#else
#include "winproc.h"
#endif
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#ifdef WINDOWS
#include <malloc.h>             /* for alloca(), on other OSes it's in stdlib.h */
#endif
#ifndef _MSC_VER
#include <unistd.h>             /* KLB_FIX */
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _MSC_VER
#include <dirent.h>             /* KLB_FIX */
#endif
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
#ifdef GNUNET_freeBSD
#include <semaphore.h>
#endif
#ifdef DARWIN
#include <dlfcn.h>
#include <semaphore.h>
#include <net/if.h>
#endif
#ifdef LINUX
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
#ifdef CYGWIN
#include <windows.h>
#include <cygwin/if.h>
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

#include "plibc.h"

#include <locale.h>
#ifndef FRAMEWORK_BUILD
#include "gettext.h"
/**
 * GNU gettext support macro.
 */
#define _(String) dgettext("gnunet",String)
#define LIBEXTRACTOR_GETTEXT_DOMAIN "libextractor"
#else
#include "libintlemu.h"
#define _(String) dgettext("org.gnunet.gnunet",String)
#define LIBEXTRACTOR_GETTEXT_DOMAIN "org.gnunet.libextractor"
#endif

#ifdef CYGWIN
#define SIOCGIFCONF     _IOW('s', 100, struct ifconf)   /* get if list */
#define SIOCGIFFLAGS    _IOW('s', 101, struct ifreq)    /* Get if flags */
#define SIOCGIFADDR     _IOW('s', 102, struct ifreq)    /* Get if addr */
#endif

#ifndef MINGW
#include <sys/mman.h>
#endif

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


#if !HAVE_ATOLL
long long
atoll (const char *nptr);
#endif

#if ENABLE_NLS
#include "langinfo.h"
#endif

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)(-1))
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
#define MAKE_UNALIGNED(val) ({ __typeof__((val)) __tmp; memmove(&__tmp, &(val), sizeof((val))); __tmp; })
#else
#define MAKE_UNALIGNED(val) val
#endif

#if WINDOWS
#define FDTYPE HANDLE
#define SOCKTYPE SOCKET
#else
#define FDTYPE int
#define SOCKTYPE int
#endif

#endif

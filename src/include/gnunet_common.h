/*
     This file is part of GNUnet.
     Copyright (C) 2006-2013 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file include/gnunet_common.h
 * @brief commonly used definitions; globals in this file
 *        are exempt from the rule that the module name ("common")
 *        must be part of the symbol name.
 *
 * @author Christian Grothoff
 * @author Nils Durner
 *
 * @defgroup logging Logging
 * @see [Documentation](https://gnunet.org/logging)
 *
 * @defgroup memory Memory management
 */
#ifndef GNUNET_COMMON_H
#define GNUNET_COMMON_H

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef MINGW
#include "winproc.h"
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#endif

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version of the API (for entire gnunetutil.so library).
 */
#define GNUNET_UTIL_VERSION 0x000A0102


/**
 * Named constants for return values.  The following invariants hold:
 * `GNUNET_NO == 0` (to allow `if (GNUNET_NO)`) `GNUNET_OK !=
 * GNUNET_SYSERR`, `GNUNET_OK != GNUNET_NO`, `GNUNET_NO !=
 * GNUNET_SYSERR` and finally `GNUNET_YES != GNUNET_NO`.
 */
#define GNUNET_OK      1
#define GNUNET_SYSERR -1
#define GNUNET_YES     1
#define GNUNET_NO      0

#define GNUNET_MIN(a,b) (((a) < (b)) ? (a) : (b))

#define GNUNET_MAX(a,b) (((a) > (b)) ? (a) : (b))

/* some systems use one underscore only, and mingw uses no underscore... */
#ifndef __BYTE_ORDER
#ifdef _BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#else
#ifdef BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#endif
#endif
#ifndef __BIG_ENDIAN
#ifdef _BIG_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#else
#ifdef BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#endif
#endif
#ifndef __LITTLE_ENDIAN
#ifdef _LITTLE_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#ifdef LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#endif
#endif

/**
 * @ingroup logging
 * define #GNUNET_EXTRA_LOGGING if using this header outside the GNUnet source
 * tree where gnunet_config.h is unavailable
 */
#ifndef GNUNET_EXTRA_LOGGING
#define GNUNET_EXTRA_LOGGING 0
#endif

/**
 * Endian operations
 */

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define GNUNET_htobe16(x) __bswap_16 (x)
#  define GNUNET_htole16(x) (x)
#  define GNUNET_be16toh(x) __bswap_16 (x)
#  define GNUNET_le16toh(x) (x)

#  define GNUNET_htobe32(x) __bswap_32 (x)
#  define GNUNET_htole32(x) (x)
#  define GNUNET_be32toh(x) __bswap_32 (x)
#  define GNUNET_le32toh(x) (x)

#  define GNUNET_htobe64(x) __bswap_64 (x)
#  define GNUNET_htole64(x) (x)
#  define GNUNET_be64toh(x) __bswap_64 (x)
#  define GNUNET_le64toh(x) (x)
#endif
# if __BYTE_ORDER == __BIG_ENDIAN
#  define GNUNET_htobe16(x) (x)
#  define GNUNET_htole16(x) __bswap_16 (x)
#  define GNUNET_be16toh(x) (x)
#  define GNUNET_le16toh(x) __bswap_16 (x)

#  define GNUNET_htobe32(x) (x)
#  define GNUNET_htole32(x) __bswap_32 (x)
#  define GNUNET_be32toh(x) (x)
#  define GNUNET_le32toh(x) __bswap_32 (x)

#  define GNUNET_htobe64(x) (x)
#  define GNUNET_htole64(x) __bswap_64 (x)
#  define GNUNET_be64toh(x) (x)
#  define GNUNET_le64toh(x) __bswap_64 (x)
#endif


/**
 * Macro used to avoid using 0 for the length of a variable-size
 * array (Non-Zero-Length).
 *
 * Basically, C standard says that "int[n] x;" is undefined if n=0.
 * This was supposed to prevent issues with pointer aliasing.
 * However, C compilers may conclude that n!=0 as n=0 would be
 * undefined, and then optimize under the assumption n!=0, which
 * could cause actual issues.  Hence, when initializing an array
 * on the stack with a variable-length that might be zero, write
 * "int[GNUNET_NZL(n)] x;" instead of "int[n] x".
 */
#define GNUNET_NZL(l) GNUNET_MAX(1,l)


/**
 * gcc-ism to get packed structs.
 */
#define GNUNET_PACKED __attribute__((packed))

/**
 * gcc-ism to get gcc bitfield layout when compiling with -mms-bitfields
 */
#if MINGW
#define GNUNET_GCC_STRUCT_LAYOUT __attribute__((gcc_struct))
#else
#define GNUNET_GCC_STRUCT_LAYOUT
#endif

/**
 * gcc-ism to force alignment; we use this to align char-arrays
 * that may then be cast to 'struct's.  See also gcc
 * bug #33594.
 */
#ifdef __BIGGEST_ALIGNMENT__
#define GNUNET_ALIGN __attribute__((aligned (__BIGGEST_ALIGNMENT__)))
#else
#define GNUNET_ALIGN __attribute__((aligned (8)))
#endif

/**
 * gcc-ism to document unused arguments
 */
#define GNUNET_UNUSED __attribute__((unused))

/**
 * gcc-ism to document functions that don't return
 */
#define GNUNET_NORETURN __attribute__((noreturn))

#if MINGW
#if __GNUC__ > 3
/**
 * gcc 4.x-ism to pack structures even on W32 (to be used before structs);
 * Using this would cause structs to be unaligned on the stack on Sparc,
 * so we *only* use this on W32 (see #670578 from Debian); fortunately,
 * W32 doesn't run on sparc anyway.
 */
#define GNUNET_NETWORK_STRUCT_BEGIN \
  _Pragma("pack(push)") \
  _Pragma("pack(1)")

/**
 * gcc 4.x-ism to pack structures even on W32 (to be used after structs)
 * Using this would cause structs to be unaligned on the stack on Sparc,
 * so we *only* use this on W32 (see #670578 from Debian); fortunately,
 * W32 doesn't run on sparc anyway.
 */
#define GNUNET_NETWORK_STRUCT_END _Pragma("pack(pop)")

#else
#error gcc 4.x or higher required on W32 systems
#endif
#else
/**
 * Define as empty, GNUNET_PACKED should suffice, but this won't work on W32
 */
#define GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Define as empty, GNUNET_PACKED should suffice, but this won't work on W32;
 */
#define GNUNET_NETWORK_STRUCT_END
#endif

/* ************************ super-general types *********************** */

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Header for all communications.
 */
struct GNUNET_MessageHeader
{

  /**
   * The length of the struct (in bytes, including the length field itself),
   * in big-endian format.
   */
  uint16_t size GNUNET_PACKED;

  /**
   * The type of the message (GNUNET_MESSAGE_TYPE_XXXX), in big-endian format.
   */
  uint16_t type GNUNET_PACKED;

};


/**
 * Answer from service to client about last operation.
 */
struct GNUNET_OperationResultMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Status code for the operation.
   */
  uint64_t result_code GNUNET_PACKED;

  /* Followed by data. */
};

GNUNET_NETWORK_STRUCT_END

/**
 * Function called with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
typedef int
(*GNUNET_FileNameCallback) (void *cls,
                            const char *filename);


/**
 * Generic continuation callback.
 *
 * @param cls  Closure.
 */
typedef void
(*GNUNET_ContinuationCallback) (void *cls);


/**
 * Function called with the result of an asynchronous operation.
 *
 * @param cls
 *        Closure.
 * @param result_code
 *        Result code for the operation.
 * @param data
 *        Data result for the operation.
 * @param data_size
 *        Size of @a data.
 */
typedef void
(*GNUNET_ResultCallback) (void *cls, int64_t result_code,
                          const void *data, uint16_t data_size);


/* ****************************** logging ***************************** */

/**
 * @ingroup logging
 * Types of errors.
 */
enum GNUNET_ErrorType
{
  GNUNET_ERROR_TYPE_UNSPECIFIED = -1,
  GNUNET_ERROR_TYPE_NONE = 0,
  GNUNET_ERROR_TYPE_ERROR = 1,
  GNUNET_ERROR_TYPE_WARNING = 2,
  /* UX: We need a message type that is output by
   * default without looking like there is a problem.
   */
  GNUNET_ERROR_TYPE_MESSAGE = 4,
  GNUNET_ERROR_TYPE_INFO = 8,
  GNUNET_ERROR_TYPE_DEBUG = 16,
  GNUNET_ERROR_TYPE_INVALID = 32,
  GNUNET_ERROR_TYPE_BULK = 64
};


/**
 * @ingroup logging
 * User-defined handler for log messages.
 *
 * @param cls closure
 * @param kind severeity
 * @param component what component is issuing the message?
 * @param date when was the message logged?
 * @param message what is the message
 */
typedef void
(*GNUNET_Logger) (void *cls,
                  enum GNUNET_ErrorType kind,
                  const char *component,
                  const char *date,
                  const char *message);


/**
 * @ingroup logging
 * Get the number of log calls that are going to be skipped
 *
 * @return number of log calls to be ignored
 */
int
GNUNET_get_log_skip (void);


#if !defined(GNUNET_CULL_LOGGING)
int
GNUNET_get_log_call_status (int caller_level,
                            const char *comp,
                            const char *file,
                            const char *function,
                            int line);
#endif


/**
 * @ingroup logging
 * Main log function.
 *
 * @param kind how serious is the error?
 * @param message what is the message (format string)
 * @param ... arguments for format string
 */
void
GNUNET_log_nocheck (enum GNUNET_ErrorType kind, const char *message, ...)
  __attribute__ ((format (gnu_printf, 2, 3)));

/* from glib */
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define _GNUNET_BOOLEAN_EXPR(expr)              \
 __extension__ ({                               \
   int _gnunet_boolean_var_;                    \
   if (expr)                                    \
      _gnunet_boolean_var_ = 1;                 \
   else                                         \
      _gnunet_boolean_var_ = 0;                 \
   _gnunet_boolean_var_;                        \
})
#define GN_LIKELY(expr) (__builtin_expect (_GNUNET_BOOLEAN_EXPR(expr), 1))
#define GN_UNLIKELY(expr) (__builtin_expect (_GNUNET_BOOLEAN_EXPR(expr), 0))
#else
#define GN_LIKELY(expr) (expr)
#define GN_UNLIKELY(expr) (expr)
#endif

#if !defined(GNUNET_LOG_CALL_STATUS)
#define GNUNET_LOG_CALL_STATUS -1
#endif


/**
 * @ingroup logging
 * Log function that specifies an alternative component.
 * This function should be used by plugins.
 *
 * @param kind how serious is the error?
 * @param comp component responsible for generating the message
 * @param message what is the message (format string)
 * @param ... arguments for format string
 */
void
GNUNET_log_from_nocheck (enum GNUNET_ErrorType kind, const char *comp,
                         const char *message, ...);

#if !defined(GNUNET_CULL_LOGGING)
#define GNUNET_log_from(kind,comp,...) do { int log_line = __LINE__;\
  static int log_call_enabled = GNUNET_LOG_CALL_STATUS;\
  if ((GNUNET_EXTRA_LOGGING > 0) || ((GNUNET_ERROR_TYPE_DEBUG & (kind)) == 0)) { \
    if (GN_UNLIKELY(log_call_enabled == -1))\
      log_call_enabled = GNUNET_get_log_call_status ((kind) & (~GNUNET_ERROR_TYPE_BULK), (comp), __FILE__, __FUNCTION__, log_line); \
    if (GN_UNLIKELY(GNUNET_get_log_skip () > 0)) { GNUNET_log_skip (-1, GNUNET_NO); }\
    else {\
      if (GN_UNLIKELY(log_call_enabled))\
        GNUNET_log_from_nocheck ((kind), comp, __VA_ARGS__);	\
    }\
  }\
} while (0)

 #define GNUNET_log(kind,...) do { int log_line = __LINE__;\
  static int log_call_enabled = GNUNET_LOG_CALL_STATUS;\
  if ((GNUNET_EXTRA_LOGGING > 0) || ((GNUNET_ERROR_TYPE_DEBUG & (kind)) == 0)) { \
    if (GN_UNLIKELY(log_call_enabled == -1))\
      log_call_enabled = GNUNET_get_log_call_status ((kind) & (~GNUNET_ERROR_TYPE_BULK), NULL, __FILE__, __FUNCTION__, log_line);\
    if (GN_UNLIKELY(GNUNET_get_log_skip () > 0)) { GNUNET_log_skip (-1, GNUNET_NO); }\
    else {\
      if (GN_UNLIKELY(log_call_enabled))\
        GNUNET_log_nocheck ((kind), __VA_ARGS__);	\
    }\
  }\
} while (0)
#else
#define GNUNET_log(...)
#define GNUNET_log_from(...)
#endif


/**
 * @ingroup logging
 * Log error message about missing configuration option.
 *
 * @param kind log level
 * @param section section with missing option
 * @param option name of missing option
 */
void
GNUNET_log_config_missing (enum GNUNET_ErrorType kind,
			   const char *section,
			   const char *option);


/**
 * @ingroup logging
 * Log error message about invalid configuration option value.
 *
 * @param kind log level
 * @param section section with invalid option
 * @param option name of invalid option
 * @param required what is required that is invalid about the option
 */
void
GNUNET_log_config_invalid (enum GNUNET_ErrorType kind,
			   const char *section,
			   const char *option,
			   const char *required);


/**
 * @ingroup logging
 * Abort the process, generate a core dump if possible.
 * Most code should use `GNUNET_assert (0)` instead to
 * first log the location of the failure.
 */
void
GNUNET_abort_ (void) GNUNET_NORETURN;


/**
 * @ingroup logging
 * Ignore the next @a n calls to the log function.
 *
 * @param n number of log calls to ignore (could be negative)
 * @param check_reset #GNUNET_YES to assert that the log skip counter is currently zero
 */
void
GNUNET_log_skip (int n,
                 int check_reset);


/**
 * @ingroup logging
 * Setup logging.
 *
 * @param comp default component to use
 * @param loglevel what types of messages should be logged
 * @param logfile change logging to logfile (use NULL to keep stderr)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if logfile could not be opened
 */
int
GNUNET_log_setup (const char *comp,
                  const char *loglevel,
                  const char *logfile);


/**
 * @ingroup logging
 * Add a custom logger.  Note that installing any custom logger
 * will disable the standard logger.  When multiple custom loggers
 * are installed, all will be called.  The standard logger will
 * only be used if no custom loggers are present.
 *
 * @param logger log function
 * @param logger_cls closure for @a logger
 */
void
GNUNET_logger_add (GNUNET_Logger logger,
                   void *logger_cls);


/**
 * @ingroup logging
 * Remove a custom logger.
 *
 * @param logger log function
 * @param logger_cls closure for @a logger
 */
void
GNUNET_logger_remove (GNUNET_Logger logger,
                      void *logger_cls);


/**
 * @ingroup logging
 * Convert a short hash value to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param shc the hash code
 * @return string
 */
const char *
GNUNET_sh2s (const struct GNUNET_ShortHashCode *shc);


/**
 * @ingroup logging
 * Convert a hash value to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the hash code
 * @return string
 */
const char *
GNUNET_h2s (const struct GNUNET_HashCode * hc);


/**
 * @ingroup logging
 * Convert a hash value to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant! Identical to #GNUNET_h2s(), except that another
 * buffer is used so both #GNUNET_h2s() and #GNUNET_h2s2() can be
 * used within the same log statement.
 *
 * @param hc the hash code
 * @return string
 */
const char *
GNUNET_h2s2 (const struct GNUNET_HashCode * hc);


/**
 * @ingroup logging
 * Convert a hash value to a string (for printing debug messages).
 * This prints all 104 characters of a hashcode!
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the hash code
 * @return string
 */
const char *
GNUNET_h2s_full (const struct GNUNET_HashCode * hc);


/**
 * @ingroup logging
 * Convert a peer identity to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pid the peer identity
 * @return string form of the pid; will be overwritten by next
 *         call to #GNUNET_i2s().
 */
const char *
GNUNET_i2s (const struct GNUNET_PeerIdentity *pid);


/**
 * @ingroup logging
 * Convert a peer identity to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!  Identical to #GNUNET_i2s(), except that another
 * buffer is used so both #GNUNET_i2s() and #GNUNET_i2s2() can be
 * used within the same log statement.
 *
 * @param pid the peer identity
 * @return string form of the pid; will be overwritten by next
 *         call to #GNUNET_i2s().
 */
const char *
GNUNET_i2s2 (const struct GNUNET_PeerIdentity *pid);


/**
 * @ingroup logging
 * Convert a peer identity to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pid the peer identity
 * @return string form of the pid; will be overwritten by next
 *         call to #GNUNET_i2s_full().
 */
const char *
GNUNET_i2s_full (const struct GNUNET_PeerIdentity *pid);


/**
 * @ingroup logging
 * Convert a "struct sockaddr*" (IPv4 or IPv6 address) to a string
 * (for printing debug messages).  This is one of the very few calls
 * in the entire API that is NOT reentrant!
 *
 * @param addr the address
 * @param addrlen the length of the @a addr
 * @return nicely formatted string for the address
 *  will be overwritten by next call to #GNUNET_a2s().
 */
const char *
GNUNET_a2s (const struct sockaddr *addr,
            socklen_t addrlen);


/**
 * @ingroup logging
 * Convert error type to string.
 *
 * @param kind type to convert
 * @return string corresponding to the type
 */
const char *
GNUNET_error_type_to_string (enum GNUNET_ErrorType kind);


/**
 * @ingroup logging
 * Use this for fatal errors that cannot be handled
 */
#define GNUNET_assert(cond) do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); GNUNET_abort_(); } } while(0)


/**
 * @ingroup logging
 * Use this for fatal errors that cannot be handled
 */
#define GNUNET_assert_at(cond, f, l) do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Assertion failed at %s:%d.\n"), f, l); GNUNET_abort_(); } } while(0)


/**
 * @ingroup logging
 * Use this for fatal errors that cannot be handled
 *
 * @param cond Condition to evaluate
 * @param comp Component string to use for logging
 */
#define GNUNET_assert_from(cond, comp) do { if (! (cond)) { GNUNET_log_from(GNUNET_ERROR_TYPE_ERROR, comp, _("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); GNUNET_abort_(); } } while(0)


/**
 * @ingroup logging
 * Use this for internal assertion violations that are
 * not fatal (can be handled) but should not occur.
 */
#define GNUNET_break(cond)  do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); } } while(0)


/**
 * @ingroup logging
 * Use this for assertion violations caused by other
 * peers (i.e. protocol violations).  We do not want to
 * confuse end-users (say, some other peer runs an
 * older, broken or incompatible GNUnet version), but
 * we still want to see these problems during
 * development and testing.  "OP == other peer".
 */
#define GNUNET_break_op(cond)  do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK, _("External protocol violation detected at %s:%d.\n"), __FILE__, __LINE__); } } while(0)


/**
 * @ingroup logging
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_log_strerror(level, cmd) do { GNUNET_log(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0)


/**
 * @ingroup logging
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_log_from_strerror(level, component, cmd) do { GNUNET_log_from (level, component, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0)


/**
 * @ingroup logging
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_log_strerror_file(level, cmd, filename) do { GNUNET_log(level, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename, __FILE__, __LINE__, STRERROR(errno)); } while(0)


/**
 * @ingroup logging
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_log_from_strerror_file(level, component, cmd, filename) do { GNUNET_log_from (level, component, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename,__FILE__, __LINE__, STRERROR(errno)); } while(0)

/* ************************* endianess conversion ****************** */

/**
 * Convert unsigned 64-bit integer to network byte order.
 *
 * @param n
 *        The value in host byte order.
 *
 * @return The same value in network byte order.
 */
uint64_t
GNUNET_htonll (uint64_t n);


/**
 * Convert unsigned 64-bit integer to host byte order.
 *
 * @param n
 *        The value in network byte order.
 *
 * @return The same value in host byte order.
 */
uint64_t
GNUNET_ntohll (uint64_t n);


/**
 * Convert double to network byte order.
 *
 * @param d
 *        The value in host byte order.
 *
 * @return The same value in network byte order.
 */
double
GNUNET_hton_double (double d);


/**
 * Convert double to host byte order
 *
 * @param d
 *        The value in network byte order.
 *
 * @return The same value in host byte order.
 */
double
GNUNET_ntoh_double (double d);


/* ************************* allocation functions ****************** */

/**
 * @ingroup memory
 * Maximum allocation with GNUNET_malloc macro.
 */
#define GNUNET_MAX_MALLOC_CHECKED (1024 * 1024 * 40)

/**
 * @ingroup memory
 * Allocate a struct or union of the given @a type.
 * Wrapper around #GNUNET_malloc that returns a pointer
 * to the newly created object of the correct type.
 *
 * @param type name of the struct or union, i.e. pass 'struct Foo'.
 */
#define GNUNET_new(type) (type *) GNUNET_malloc (sizeof (type))

/**
 * Call memcpy() but check for @a n being 0 first. In the latter
 * case, it is now safe to pass NULL for @a src or @a dst.
 * Unlike traditional memcpy(), returns nothing.
 *
 * @param dst destination of the copy, may be NULL if @a n is zero
 * @param src source of the copy, may be NULL if @a n is zero
 * @param n number of bytes to copy
 */
#define GNUNET_memcpy(dst,src,n) do { if (0 != n) { (void) memcpy (dst,src,n); } } while (0)


/**
 * @ingroup memory
 * Allocate a size @a n array with structs or unions of the given @a type.
 * Wrapper around #GNUNET_malloc that returns a pointer
 * to the newly created objects of the correct type.
 *
 * @param n number of elements in the array
 * @param type name of the struct or union, i.e. pass 'struct Foo'.
 */
#define GNUNET_new_array(n, type) (type *) GNUNET_malloc ((n) * sizeof (type))

/**
 * @ingroup memory
 * Allocate a size @a n times @a m array
 * with structs or unions of the given @a type.
 *
 * @param n size of the first dimension
 * @param m size of the second dimension
 * @param type name of the struct or union, i.e. pass 'struct Foo'.
 */
#define GNUNET_new_array_2d(n, m, type) (type **) GNUNET_xnew_array_2d_ (n, m, sizeof (type), __FILE__, __LINE__)

/**
 * @ingroup memory
 * Allocate a size @a n times @a m times @a o array
 * with structs or unions of the given @a type.
 *
 * @param n size of the first dimension
 * @param m size of the second dimension
 * @param o size of the third dimension
 * @param type name of the struct or union, i.e. pass 'struct Foo'.
 */
#define GNUNET_new_array_3d(n, m, o, type) (type ***) GNUNET_xnew_array_3d_ (n, m, o, sizeof (type), __FILE__, __LINE__)

/**
 * @ingroup memory
 * Wrapper around malloc. Allocates size bytes of memory.
 * The memory will be zero'ed out.
 *
 * @param size the number of bytes to allocate, must be
 *        smaller than 40 MB.
 * @return pointer to size bytes of memory, never NULL (!)
 */
#define GNUNET_malloc(size) GNUNET_xmalloc_(size, __FILE__, __LINE__)

/**
 * @ingroup memory
 * Allocate and initialize a block of memory.
 *
 * @param buf data to initalize the block with
 * @param size the number of bytes in buf (and size of the allocation)
 * @return pointer to size bytes of memory, never NULL (!)
 */
#define GNUNET_memdup(buf,size) GNUNET_xmemdup_(buf, size, __FILE__, __LINE__)

/**
 * @ingroup memory
 * Wrapper around malloc. Allocates size bytes of memory.
 * The memory will be zero'ed out.
 *
 * @param size the number of bytes to allocate
 * @return pointer to size bytes of memory, NULL if we do not have enough memory
 */
#define GNUNET_malloc_large(size) GNUNET_xmalloc_unchecked_(size, __FILE__, __LINE__)

/**
 * @ingroup memory
 * Wrapper around realloc. Reallocates size bytes of memory.
 * The content of the intersection of the new and old size will be unchanged.
 *
 * @param ptr the pointer to reallocate
 * @param size the number of bytes to reallocate
 * @return pointer to size bytes of memory
 */
#define GNUNET_realloc(ptr, size) GNUNET_xrealloc_(ptr, size, __FILE__, __LINE__)

/**
 * @ingroup memory
 * Wrapper around free. Frees the memory referred to by ptr.
 * Note that it is generally better to free memory that was
 * allocated with #GNUNET_array_grow using #GNUNET_array_grow(mem, size, 0) instead of #GNUNET_free.
 *
 * @param ptr location where to free the memory. ptr must have
 *     been returned by #GNUNET_strdup, #GNUNET_strndup, #GNUNET_malloc or #GNUNET_array_grow earlier.
 */
#define GNUNET_free(ptr) GNUNET_xfree_(ptr, __FILE__, __LINE__)

/**
 * @ingroup memory
 * Free the memory pointed to by ptr if ptr is not NULL.
 * Equivalent to `if (NULL != ptr) GNUNET_free(ptr)`.
 *
 * @param ptr the location in memory to free
 */
#define GNUNET_free_non_null(ptr) do { void * __x__ = ptr; if (__x__ != NULL) { GNUNET_free(__x__); } } while(0)

/**
 * @ingroup memory
 * Wrapper around #GNUNET_xstrdup_.  Makes a copy of the zero-terminated string
 * pointed to by a.
 *
 * @param a pointer to a zero-terminated string
 * @return a copy of the string including zero-termination
 */
#define GNUNET_strdup(a) GNUNET_xstrdup_(a,__FILE__,__LINE__)

/**
 * @ingroup memory
 * Wrapper around #GNUNET_xstrndup_.  Makes a partial copy of the string
 * pointed to by a.
 *
 * @param a pointer to a string
 * @param length of the string to duplicate
 * @return a partial copy of the string including zero-termination
 */
#define GNUNET_strndup(a,length) GNUNET_xstrndup_(a,length,__FILE__,__LINE__)

/**
 * @ingroup memory
 * Grow a well-typed (!) array.  This is a convenience
 * method to grow a vector @a arr of size @a size
 * to the new (target) size @a tsize.
 * <p>
 *
 * Example (simple, well-typed stack):
 *
 * <pre>
 * static struct foo * myVector = NULL;
 * static int myVecLen = 0;
 *
 * static void push(struct foo * elem) {
 *   GNUNET_array_grow(myVector, myVecLen, myVecLen+1);
 *   GNUNET_memcpy(&myVector[myVecLen-1], elem, sizeof(struct foo));
 * }
 *
 * static void pop(struct foo * elem) {
 *   if (myVecLen == 0) die();
 *   GNUNET_memcpy(elem, myVector[myVecLen-1], sizeof(struct foo));
 *   GNUNET_array_grow(myVector, myVecLen, myVecLen-1);
 * }
 * </pre>
 *
 * @param arr base-pointer of the vector, may be NULL if size is 0;
 *        will be updated to reflect the new address. The TYPE of
 *        arr is important since size is the number of elements and
 *        not the size in bytes
 * @param size the number of elements in the existing vector (number
 *        of elements to copy over), will be updated with the new
 *        array size
 * @param tsize the target size for the resulting vector, use 0 to
 *        free the vector (then, arr will be NULL afterwards).
 */
#define GNUNET_array_grow(arr,size,tsize) GNUNET_xgrow_((void**)&arr, sizeof(arr[0]), &size, tsize, __FILE__, __LINE__)

/**
 * @ingroup memory
 * Append an element to a list (growing the list by one).
 *
 * @param arr base-pointer of the vector, may be NULL if size is 0;
 *        will be updated to reflect the new address. The TYPE of
 *        arr is important since size is the number of elements and
 *        not the size in bytes
 * @param size the number of elements in the existing vector (number
 *        of elements to copy over), will be updated with the new
 *        array size
 * @param element the element that will be appended to the array
 */
#define GNUNET_array_append(arr,size,element) do { GNUNET_array_grow(arr,size,size+1); arr[size-1] = element; } while(0)

/**
 * @ingroup memory
 * Like snprintf, just aborts if the buffer is of insufficient size.
 *
 * @param buf pointer to buffer that is written to
 * @param size number of bytes in @a buf
 * @param format format strings
 * @param ... data for format string
 * @return number of bytes written to buf or negative value on error
 */
int
GNUNET_snprintf (char *buf, size_t size, const char *format, ...);


/**
 * @ingroup memory
 * Like asprintf, just portable.
 *
 * @param buf set to a buffer of sufficient size (allocated, caller must free)
 * @param format format string (see printf, fprintf, etc.)
 * @param ... data for format string
 * @return number of bytes in "*buf" excluding 0-termination
 */
int
GNUNET_asprintf (char **buf, const char *format, ...);


/* ************** internal implementations, use macros above! ************** */

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.  Don't use GNUNET_xmalloc_ directly. Use the
 * #GNUNET_malloc macro.
 * The memory will be zero'ed out.
 *
 * @param size number of bytes to allocate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return allocated memory, never NULL
 */
void *
GNUNET_xmalloc_ (size_t size, const char *filename, int linenumber);


/**
 * Allocate memory for a two dimensional array in one block
 * and set up pointers. Aborts if no more memory is available.
 * Don't use GNUNET_xnew_array_2d_ directly. Use the
 * #GNUNET_new_array_2d macro.
 * The memory of the elements will be zero'ed out.
 *
 * @param n size of the first dimension
 * @param m size of the second dimension
 * @param elementSize size of a single element in bytes
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return allocated memory, never NULL
 */
void **
GNUNET_xnew_array_2d_ (size_t n, size_t m, size_t elementSize,
                       const char *filename, int linenumber);


/**
 * Allocate memory for a three dimensional array in one block
 * and set up pointers. Aborts if no more memory is available.
 * Don't use GNUNET_xnew_array_3d_ directly. Use the
 * #GNUNET_new_array_3d macro.
 * The memory of the elements will be zero'ed out.
 *
 * @param n size of the first dimension
 * @param m size of the second dimension
 * @param o size of the third dimension
 * @param elementSize size of a single element in bytes
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return allocated memory, never NULL
 */
void ***
GNUNET_xnew_array_3d_ (size_t n, size_t m, size_t o, size_t elementSize,
                       const char *filename, int linenumber);


/**
 * Allocate and initialize memory. Checks the return value, aborts if no more
 * memory is available.  Don't use GNUNET_xmemdup_ directly. Use the
 * #GNUNET_memdup macro.
 *
 * @param buf buffer to initialize from (must contain size bytes)
 * @param size number of bytes to allocate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return allocated memory, never NULL
 */
void *
GNUNET_xmemdup_ (const void *buf, size_t size, const char *filename,
                 int linenumber);


/**
 * Allocate memory.  This function does not check if the allocation
 * request is within reasonable bounds, allowing allocations larger
 * than 40 MB.  If you don't expect the possibility of very large
 * allocations, use #GNUNET_malloc instead.  The memory will be zero'ed
 * out.
 *
 * @param size number of bytes to allocate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return pointer to size bytes of memory, NULL if we do not have enough memory
 */
void *
GNUNET_xmalloc_unchecked_ (size_t size, const char *filename, int linenumber);


/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 */
void *
GNUNET_xrealloc_ (void *ptr, size_t n, const char *filename, int linenumber);


/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.  Don't use GNUNET_xfree_
 * directly. Use the #GNUNET_free macro.
 *
 * @param ptr pointer to memory to free
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 */
void
GNUNET_xfree_ (void *ptr, const char *filename, int linenumber);


/**
 * Dup a string. Don't call GNUNET_xstrdup_ directly. Use the #GNUNET_strdup macro.
 * @param str string to duplicate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return the duplicated string
 */
char *
GNUNET_xstrdup_ (const char *str, const char *filename, int linenumber);

/**
 * Dup partially a string. Don't call GNUNET_xstrndup_ directly. Use the #GNUNET_strndup macro.
 *
 * @param str string to duplicate
 * @param len length of the string to duplicate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return the duplicated string
 */
char *
GNUNET_xstrndup_ (const char *str, size_t len, const char *filename,
                  int linenumber);

/**
 * Grow an array, the new elements are zeroed out.
 * Grows old by (*oldCount-newCount)*elementSize
 * bytes and sets *oldCount to newCount.
 *
 * Don't call GNUNET_xgrow_ directly. Use the #GNUNET_array_grow macro.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0 (then *old will be NULL afterwards)
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 */
void
GNUNET_xgrow_ (void **old, size_t elementSize, unsigned int *oldCount,
               unsigned int newCount, const char *filename, int linenumber);


/**
 * @ingroup memory
 * Create a copy of the given message.
 *
 * @param msg message to copy
 * @return duplicate of the message
 */
struct GNUNET_MessageHeader *
GNUNET_copy_message (const struct GNUNET_MessageHeader *msg);


#if __STDC_VERSION__ < 199901L
#if __GNUC__ >= 2
#define __func__ __FUNCTION__
#else
#define __func__ "<unknown>"
#endif
#endif


/**
 * Valid task priorities.  Use these, do not pass random integers!
 * For various reasons (#3862 -- building with QT Creator, and
 * our restricted cross-compilation with emscripten) this cannot
 * be in gnunet_scheduler_lib.h, but it works if we declare it here.
 * Naturally, logically this is part of the scheduler.
 */
enum GNUNET_SCHEDULER_Priority
{
  /**
   * Run with the same priority as the current job.
   */
  GNUNET_SCHEDULER_PRIORITY_KEEP = 0,

  /**
   * Run when otherwise idle.
   */
  GNUNET_SCHEDULER_PRIORITY_IDLE = 1,

  /**
   * Run as background job (higher than idle,
   * lower than default).
   */
  GNUNET_SCHEDULER_PRIORITY_BACKGROUND = 2,

  /**
   * Run with the default priority (normal
   * P2P operations).  Any task that is scheduled
   * without an explicit priority being specified
   * will run with this priority.
   */
  GNUNET_SCHEDULER_PRIORITY_DEFAULT = 3,

  /**
   * Run with high priority (important requests).
   * Higher than DEFAULT.
   */
  GNUNET_SCHEDULER_PRIORITY_HIGH = 4,

  /**
   * Run with priority for interactive tasks.
   * Higher than "HIGH".
   */
  GNUNET_SCHEDULER_PRIORITY_UI = 5,

  /**
   * Run with priority for urgent tasks.  Use
   * for things like aborts and shutdowns that
   * need to preempt "UI"-level tasks.
   * Higher than "UI".
   */
  GNUNET_SCHEDULER_PRIORITY_URGENT = 6,

  /**
   * This is an internal priority level that is only used for tasks
   * that are being triggered due to shutdown (they have automatically
   * highest priority).  User code must not use this priority level
   * directly.  Tasks run with this priority level that internally
   * schedule other tasks will see their original priority level
   * be inherited (unless otherwise specified).
   */
  GNUNET_SCHEDULER_PRIORITY_SHUTDOWN = 7,

  /**
   * Number of priorities (must be the last priority).
   * This priority must not be used by clients.
   */
  GNUNET_SCHEDULER_PRIORITY_COUNT = 8
};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_COMMON_H */

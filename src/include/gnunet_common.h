/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_common.h
 * @brief commonly used definitions; globals in this file
 *        are exempt from the rule that the module name ("common")
 *        must be part of the symbol name.
 *
 * @author Christian Grothoff
 * @author Nils Durner
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
 
/**
 * Version of the API (for entire gnunetutil.so library).
 */
#define GNUNET_UTIL_VERSION 0x00089900

/**
 * Name used for "services" that are actually command-line
 * programs invoked by the end user.
 */
#define GNUNET_CLIENT_SERVICE_NAME "client"

/**
 * Named constants for return values.  The following
 * invariants hold: "GNUNET_NO == 0" (to allow "if (GNUNET_NO)")
 * "GNUNET_OK != GNUNET_SYSERR", "GNUNET_OK != GNUNET_NO", "GNUNET_NO != GNUNET_SYSERR"
 * and finally "GNUNET_YES != GNUNET_NO".
 */
#define GNUNET_OK      1
#define GNUNET_SYSERR -1
#define GNUNET_YES     1
#define GNUNET_NO      0

#define GNUNET_MIN(a,b) (((a) < (b)) ? (a) : (b))

#define GNUNET_MAX(a,b) (((a) > (b)) ? (a) : (b))

/**
 * gcc-ism to get packed structs.
 */
#define GNUNET_PACKED __attribute__((packed))


/* ************************ super-general types *********************** */

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
 * @brief 512-bit hashcode
 */
typedef struct
{
  uint32_t bits[512 / 8 / sizeof (uint32_t)];   /* = 16 */
}
GNUNET_HashCode;


/**
 * The identity of the host (basically the SHA-512 hashcode of
 * it's public key).
 */
struct GNUNET_PeerIdentity
{
  GNUNET_HashCode hashPubKey GNUNET_PACKED;
};


/**
 * Function called with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK to continue to iterate,
 *  GNUNET_SYSERR to abort iteration with error!
 */
typedef int (*GNUNET_FileNameCallback) (void *cls, const char *filename);


/* ****************************** logging ***************************** */

/**
 * Types of errors.
 */
enum GNUNET_ErrorType
{
  GNUNET_ERROR_TYPE_NONE = 0,
  GNUNET_ERROR_TYPE_ERROR = 1,
  GNUNET_ERROR_TYPE_WARNING = 2,
  GNUNET_ERROR_TYPE_INFO = 4,
  GNUNET_ERROR_TYPE_DEBUG = 8,
  GNUNET_ERROR_TYPE_INVALID = 16,
  GNUNET_ERROR_TYPE_BULK = 32
};


/**
 * User-defined handler for log messages.
 *
 * @param cls closure
 * @param kind severeity
 * @param component what component is issuing the message?
 * @param date when was the message logged?
 * @param message what is the message
 */
typedef void (*GNUNET_Logger) (void *cls,
                               enum GNUNET_ErrorType kind,
                               const char *component,
                               const char *date, const char *message);

/**
 * Main log function.
 *
 * @param kind how serious is the error?
 * @param message what is the message (format string)
 * @param ... arguments for format string
 */
void GNUNET_log (enum GNUNET_ErrorType kind, const char *message, ...);



/**
 * Log function that specifies an alternative component.
 * This function should be used by plugins.
 *
 * @param kind how serious is the error?
 * @param comp component responsible for generating the message
 * @param message what is the message (format string)
 * @param ... arguments for format string
 */
void
GNUNET_log_from (enum GNUNET_ErrorType kind,
                 const char *comp, const char *message, ...);


/**
 * Ignore the next n calls to the log function.
 *
 * @param n number of log calls to ignore
 * @param check_reset GNUNET_YES to assert that the log skip counter is currently zero
 */
void
GNUNET_log_skip (unsigned int n, int check_reset);


/**
 * Setup logging.
 *
 * @param comp default component to use
 * @param loglevel what types of messages should be logged
 * @param logfile change logging to logfile (use NULL to keep stderr)
 * @return GNUNET_OK on success, GNUNET_SYSERR if logfile could not be opened
 */
int
GNUNET_log_setup (const char *comp,
                  const char *loglevel, const char *logfile);


/**
 * Add a custom logger.
 *
 * @param logger log function
 * @param logger_cls closure for logger
 */
void GNUNET_logger_add (GNUNET_Logger logger, void *logger_cls);


/**
 * Remove a custom logger.
 *
 * @param logger log function
 * @param logger_cls closure for logger
 */
void GNUNET_logger_remove (GNUNET_Logger logger, void *logger_cls);


/**
 * Convert a hash value to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the hash code
 * @return string 
 */
const char *GNUNET_h2s (const GNUNET_HashCode *hc);


/**
 * Convert a hash value to a string (for printing debug messages).
 * This prints all 104 characters of a hashcode!
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the hash code
 * @return string
 */
const char *GNUNET_h2s_full (const GNUNET_HashCode *hc);


/**
 * Convert a peer identity to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pid the peer identity
 * @return string form of the pid; will be overwritten by next
 *         call to GNUNET_i2s.
 */
const char *GNUNET_i2s (const struct GNUNET_PeerIdentity *pid);


/**
 * Convert a "struct sockaddr*" (IPv4 or IPv6 address) to a string
 * (for printing debug messages).  This is one of the very few calls
 * in the entire API that is NOT reentrant!
 *
 * @param addr the address
 * @param addrlen the length of the address
 * @return nicely formatted string for the address
 *  will be overwritten by next call to GNUNET_a2s.
 */
const char *GNUNET_a2s (const struct sockaddr *addr,
			socklen_t addrlen);

/**
 * Convert error type to string.
 *
 * @param kind type to convert
 * @return string corresponding to the type
 */
const char *GNUNET_error_type_to_string (enum GNUNET_ErrorType kind);


/**
 * Use this for fatal errors that cannot be handled
 */
#define GNUNET_assert(cond) do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); abort(); } } while(0)

/**
 * Use this for fatal errors that cannot be handled
 */
#define GNUNET_assert_at(cond, f, l) do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Assertion failed at %s:%d.\n"), f, l); abort(); } } while(0)

/**
 * Use this for internal assertion violations that are
 * not fatal (can be handled) but should not occur.
 */
#define GNUNET_break(cond)  do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); } } while(0)

/**
 * Use this for assertion violations caused by other
 * peers (i.e. protocol violations).  We do not want to
 * confuse end-users (say, some other peer runs an
 * older, broken or incompatible GNUnet version), but
 * we still want to see these problems during
 * development and testing.  "OP == other peer".
 */
#define GNUNET_break_op(cond)  do { if (! (cond)) { GNUNET_log(GNUNET_ERROR_TYPE_WARNING, _("External protocol violation detected at %s:%d.\n"), __FILE__, __LINE__); } } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_log_strerror(level, cmd) do { GNUNET_log(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_log_strerror_file(level, cmd, filename) do { GNUNET_log(level, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename,__FILE__, __LINE__, STRERROR(errno)); } while(0)

/* ************************* endianess conversion ****************** */

/**
 * Convert a long-long to host-byte-order.
 * @param n the value in network byte order
 * @return the same value in host byte order
 */
unsigned long long GNUNET_ntohll (unsigned long long n);

/**
 * Convert a long long to network-byte-order.
 * @param n the value in host byte order
 * @return the same value in network byte order
 */
unsigned long long GNUNET_htonll (unsigned long long n);


/* ************************* allocation functions ****************** */

/**
 * Maximum allocation with GNUNET_malloc macro.
 */
#define GNUNET_MAX_MALLOC_CHECKED (1024 * 1024 * 40)

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 * The memory will be zero'ed out.
 *
 * @param size the number of bytes to allocate, must be
 *        smaller than 40 MB.
 * @return pointer to size bytes of memory, never NULL (!)
 */
#define GNUNET_malloc(size) GNUNET_xmalloc_(size, __FILE__, __LINE__)

/**
 * Allocate and initialize a block of memory.
 * 
 * @param buf data to initalize the block with
 * @param size the number of bytes in buf (and size of the allocation)
 * @return pointer to size bytes of memory, never NULL (!)
 */
#define GNUNET_memdup(buf,size) GNUNET_xmemdup_(buf, size, __FILE__, __LINE__)

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 * The memory will be zero'ed out.
 *
 * @param size the number of bytes to allocate
 * @return pointer to size bytes of memory, NULL if we do not have enough memory
 */
#define GNUNET_malloc_large(size) GNUNET_xmalloc_unchecked_(size, __FILE__, __LINE__)

/**
 * Wrapper around realloc. Rellocates size bytes of memory.
 *
 * @param ptr the pointer to reallocate
 * @param size the number of bytes to reallocate
 * @return pointer to size bytes of memory
 */
#define GNUNET_realloc(ptr, size) GNUNET_xrealloc_(ptr, size, __FILE__, __LINE__)

/**
 * Wrapper around free. Frees the memory referred to by ptr.
 * Note that is is generally better to free memory that was
 * allocated with GNUNET_array_grow using GNUNET_array_grow(mem, size, 0) instead of GNUNET_free.
 *
 * @param ptr location where to free the memory. ptr must have
 *     been returned by GNUNET_strdup, GNUNET_strndup, GNUNET_malloc or GNUNET_array_grow earlier.
 */
#define GNUNET_free(ptr) GNUNET_xfree_(ptr, __FILE__, __LINE__)

/**
 * Free the memory pointed to by ptr if ptr is not NULL.
 * Equivalent to if (ptr!=null)GNUNET_free(ptr).
 *
 * @param ptr the location in memory to free
 */
#define GNUNET_free_non_null(ptr) do { void * __x__ = ptr; if (__x__ != NULL) { GNUNET_free(__x__); } } while(0)

/**
 * Wrapper around GNUNET_strdup.  Makes a copy of the zero-terminated string
 * pointed to by a.
 *
 * @param a pointer to a zero-terminated string
 * @return a copy of the string including zero-termination
 */
#define GNUNET_strdup(a) GNUNET_xstrdup_(a,__FILE__,__LINE__)

/**
 * Wrapper around GNUNET_strndup.  Makes a partial copy of the string
 * pointed to by a.
 *
 * @param a pointer to a string
 * @param length of the string to duplicate
 * @return a partial copy of the string including zero-termination
 */
#define GNUNET_strndup(a,b) GNUNET_xstrndup_(a,b,__FILE__,__LINE__)

/**
 * Grow a well-typed (!) array.  This is a convenience
 * method to grow a vector <tt>arr</tt> of size <tt>size</tt>
 * to the new (target) size <tt>tsize</tt>.
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
 *   memcpy(&myVector[myVecLen-1], elem, sizeof(struct foo));
 * }
 *
 * static void pop(struct foo * elem) {
 *   if (myVecLen == 0) die();
 *   memcpy(elem, myVector[myVecLen-1], sizeof(struct foo));
 *   GNUNET_array_grow(myVector, myVecLen, myVecLen-1);
 * }
 * </pre>
 *
 * @param arr base-pointer of the vector, may be NULL if size is 0;
 *        will be updated to reflect the new address. The TYPE of
 *        arr is important since size is the number of elements and
 *        not the size in bytes
 * @param size the number of elements in the existing vector (number
 *        of elements to copy over)
 * @param tsize the target size for the resulting vector, use 0 to
 *        free the vector (then, arr will be NULL afterwards).
 */
#define GNUNET_array_grow(arr,size,tsize) GNUNET_xgrow_((void**)&arr, sizeof(arr[0]), &size, tsize, __FILE__, __LINE__)

/**
 * Append an element to a list (growing the
 * list by one).
 */
#define GNUNET_array_append(arr,size,element) do { GNUNET_array_grow(arr,size,size+1); arr[size-1] = element; } while(0)

/**
 * Like snprintf, just aborts if the buffer is of insufficient size.
 *
 * @param buf pointer to buffer that is written to
 * @param size number of bytes in buf
 * @param format format strings
 * @param ... data for format string
 * @return number of bytes written to buf or negative value on error
 */
int GNUNET_snprintf (char *buf, size_t size, const char *format, ...);


/**
 * Like asprintf, just portable.
 *
 * @param buf set to a buffer of sufficient size (allocated, caller must free)
 * @param format format string (see printf, fprintf, etc.)
 * @param ... data for format string
 * @return number of bytes in "*buf" excluding 0-termination
 */
int GNUNET_asprintf (char **buf, const char *format, ...);


/* ************** internal implementations, use macros above! ************** */

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.  Don't use GNUNET_xmalloc_ directly. Use the
 * GNUNET_malloc macro.
 * The memory will be zero'ed out.
 *
 * @param size number of bytes to allocate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return allocated memory, never NULL
 */
void *GNUNET_xmalloc_ (size_t size, const char *filename, int linenumber);



/**
 * Allocate and initialize memory. Checks the return value, aborts if no more
 * memory is available.  Don't use GNUNET_xmemdup_ directly. Use the
 * GNUNET_memdup macro.
 *
 * @param buf buffer to initialize from (must contain size bytes)
 * @param size number of bytes to allocate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return allocated memory, never NULL
 */
void *GNUNET_xmemdup_ (const void *buf, size_t size, const char *filename, int linenumber);


/**
 * Allocate memory.  This function does not check if the allocation
 * request is within reasonable bounds, allowing allocations larger
 * than 40 MB.  If you don't expect the possibility of very large
 * allocations, use GNUNET_malloc instead.  The memory will be zero'ed
 * out.
 *
 * @param size number of bytes to allocate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return pointer to size bytes of memory, NULL if we do not have enough memory
 */
void *GNUNET_xmalloc_unchecked_ (size_t size,
                                 const char *filename, int linenumber);

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 */
void *GNUNET_xrealloc_ (void *ptr,
                        size_t n, const char *filename, int linenumber);

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.  Don't use GNUNET_xfree_
 * directly. Use the GNUNET_free macro.
 *
 * @param ptr pointer to memory to free
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 */
void GNUNET_xfree_ (void *ptr, const char *filename, int linenumber);


/**
 * Dup a string. Don't call GNUNET_xstrdup_ directly. Use the GNUNET_strdup macro.
 * @param str string to duplicate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return the duplicated string
 */
char *GNUNET_xstrdup_ (const char *str, const char *filename, int linenumber);

/**
 * Dup partially a string. Don't call GNUNET_xstrndup_ directly. Use the GNUNET_strndup macro.
 * @param str string to duplicate
 * @param len lenght of the string to duplicate
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 * @return the duplicated string
 */
char *GNUNET_xstrndup_ (const char *str, size_t len, const char *filename, int linenumber);

/**
 * Grow an array, the new elements are zeroed out.
 * Grows old by (*oldCount-newCount)*elementSize
 * bytes and sets *oldCount to newCount.
 *
 * Don't call GNUNET_xgrow_ directly. Use the GNUNET_array_grow macro.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0 (then *old will be NULL afterwards)
 * @param filename where is this call being made (for debugging)
 * @param linenumber line where this call is being made (for debugging)
 */
void GNUNET_xgrow_ (void **old,
                    size_t elementSize,
                    unsigned int *oldCount,
                    unsigned int newCount,
                    const char *filename, int linenumber);




#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

#endif /*GNUNET_COMMON_H_ */

/*
     This file is part of GNUnet.
     (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/gnunet_strings_lib.h
 * @brief strings and string handling functions (including malloc
 *        and string tokenizing)
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_STRINGS_LIB_H
#define GNUNET_STRINGS_LIB_H

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_time_lib.h"


/**
 * Convert a given fancy human-readable size to bytes.
 *
 * @param fancy_size human readable string (i.e. 1 MB)
 * @param size set to the size in bytes
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_size_to_bytes (const char *fancy_size,
                                    unsigned long long *size);


/**
 * Convert a given fancy human-readable time to our internal
 * representation.
 *
 * @param fancy_time human readable string (i.e. 1 minute)
 * @param rtime set to the relative time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_time_to_relative (const char *fancy_time,
                                       struct GNUNET_TIME_Relative *rtime);


/**
 * @ingroup time
 * Convert a given fancy human-readable time to our internal
 * representation.  The human-readable time is expected to be
 * in local time, whereas the returned value will be in UTC.
 *
 * @param fancy_time human readable string (i.e. %Y-%m-%d %H:%M:%S)
 * @param atime set to the absolute time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_time_to_absolute (const char *fancy_time,
                                       struct GNUNET_TIME_Absolute *atime);


/**
 * Convert a given filesize into a fancy human-readable format.
 *
 * @param size number of bytes
 * @return fancy representation of the size (possibly rounded) for humans
 */
char *
GNUNET_STRINGS_byte_size_fancy (unsigned long long size);


/**
 * Convert the len characters long character sequence
 * given in input that is in the given input charset
 * to a string in given output charset.
 *
 * @param input input string
 * @param len number of bytes in @a input
 * @param input_charset character set used for @a input
 * @param output_charset desired character set for the return value
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
GNUNET_STRINGS_conv (const char *input, size_t len,
		     const char *input_charset,
		     const char *output_charset);


/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 *
 * @param input the input string (not necessarily 0-terminated)
 * @param len the number of bytes in the @a input
 * @param charset character set to convert from
 * @return the converted string (0-terminated)
 */
char *
GNUNET_STRINGS_to_utf8 (const char *input,
			size_t len,
			const char *charset);


/**
 * Convert the len bytes-long UTF-8 string
 * given in input to the given charset.
 *
 * @param input the input string (not necessarily 0-terminated)
 * @param len the number of bytes in the @a input
 * @param charset character set to convert to
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
GNUNET_STRINGS_from_utf8 (const char *input,
			  size_t len,
			  const char *charset);


/**
 * Convert the utf-8 input string to lower case.
 * Output needs to be allocated appropriately.
 *
 * @param input input string
 * @param output output buffer
 */
void
GNUNET_STRINGS_utf8_tolower (const char *input,
			     char *output);


/**
 * Convert the utf-8 input string to upper case.
 * Output needs to be allocated appropriately.
 *
 * @param input input string
 * @param output output buffer
 */
void
GNUNET_STRINGS_utf8_toupper (const char *input,
			     char *output);


/**
 * Complete filename (a la shell) from abbrevition.
 *
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @return the full file name,
 *          NULL is returned on error
 */
char *
GNUNET_STRINGS_filename_expand (const char *fil);


/**
 * Fill a buffer of the given size with count 0-terminated strings
 * (given as varargs).  If "buffer" is NULL, only compute the amount
 * of space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function will add
 * 0-terminators after each string.  The
 * "GNUNET_string_buffer_tokenize" function can be used to parse the
 * buffer back into individual strings.
 *
 * @param buffer the buffer to fill with strings, can
 *               be NULL in which case only the necessary
 *               amount of space will be calculated
 * @param size number of bytes available in buffer
 * @param count number of strings that follow
 * @param ... count 0-terminated strings to copy to buffer
 * @return number of bytes written to the buffer
 *         (or number of bytes that would have been written)
 */
size_t
GNUNET_STRINGS_buffer_fill (char *buffer,
			    size_t size,
			    unsigned int count,
			    ...);


/**
 * Given a buffer of a given size, find "count" 0-terminated strings
 * in the buffer and assign the count (varargs) of type "const char**"
 * to the locations of the respective strings in the buffer.
 *
 * @param buffer the buffer to parse
 * @param size size of the @a buffer
 * @param count number of strings to locate
 * @param ... pointers to where to store the strings
 * @return offset of the character after the last 0-termination
 *         in the buffer, or 0 on error.
 */
unsigned int
GNUNET_STRINGS_buffer_tokenize (const char *buffer,
                                size_t size,
                                unsigned int count, ...);



/**
 * @ingroup time
 * Like `asctime`, except for GNUnet time.  Converts a GNUnet internal
 * absolute time (which is in UTC) to a string in local time.
 * Note that the returned value will be overwritten if this function
 * is called again.
 *
 * @param t the absolute time to convert
 * @return timestamp in human-readable form in local time
 */
const char *
GNUNET_STRINGS_absolute_time_to_string (struct GNUNET_TIME_Absolute t);


/**
 * @ingroup time
 * Give relative time in human-readable fancy format.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param delta time in milli seconds
 * @param do_round are we allowed to round a bit?
 * @return string in human-readable form
 */
const char *
GNUNET_STRINGS_relative_time_to_string (struct GNUNET_TIME_Relative delta,
					int do_round);


/**
 * "man basename"
 * Returns a pointer to a part of filename (allocates nothing)!
 *
 * @param filename filename to extract basename from
 * @return short (base) name of the file (that is, everything following the
 *         last directory separator in filename. If filename ends with a
 *         directory separator, the result will be a zero-length string.
 *         If filename has no directory separators, the result is filename
 *         itself.
 */
const char *
GNUNET_STRINGS_get_short_name (const char *filename);


/**
 * Convert binary data to ASCII encoding using Base32Hex (RFC 4648).
 * Does not append 0-terminator, but returns a pointer to the place where
 * it should be placed, if needed.
 *
 * @param data data to encode
 * @param size size of data (in bytes)
 * @param out buffer to fill
 * @param out_size size of the buffer. Must be large enough to hold
 * ((size*8) + (((size*8) % 5) > 0 ? 5 - ((size*8) % 5) : 0)) / 5
 * @return pointer to the next byte in 'out' or NULL on error.
 */
char *
GNUNET_STRINGS_data_to_string (const void *data,
			       size_t size,
			       char *out,
			       size_t out_size);


/**
 * Return the base32crockford encoding of the given buffer.
 *
 * The returned string will be freshly allocated, and must be free'd
 * with #GNUNET_free().
 *
 * @param buffer with data
 * @param size size of the buffer
 * @return freshly allocated, null-terminated string
 */
char *
GNUNET_STRINGS_data_to_string_alloc (const void *buf,
                                     size_t size);


/**
 * Convert Base32hex encoding back to data.
 * @a out_size must match exactly the size of the data before it was encoded.
 *
 * @param enc the encoding
 * @param enclen number of characters in 'enc' (without 0-terminator, which can be missing)
 * @param out location where to store the decoded data
 * @param out_size size of the output buffer @a out
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_STRINGS_string_to_data (const char *enc,
			       size_t enclen,
			       void *out,
			       size_t out_size);


/**
 * Encode into Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64_encode (const char *data, size_t len, char **output);


/**
 * Decode from Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64_decode (const char *data, size_t len, char **output);


/**
 * Parse a path that might be an URI.
 *
 * @param path path to parse. Must be NULL-terminated.
 * @param scheme_part a pointer to 'char *' where a pointer to a string that
 *        represents the URI scheme will be stored. Can be NULL. The string is
 *        allocated by the function, and should be freed by GNUNET_free() when
 *        it is no longer needed.
 * @param path_part a pointer to 'const char *' where a pointer to the path
 *        part of the URI will be stored. Can be NULL. Points to the same block
 *        of memory as 'path', and thus must not be freed. Might point to '\0',
 *        if path part is zero-length.
 * @return #GNUNET_YES if it's an URI, #GNUNET_NO otherwise. If 'path' is not
 *         an URI, '* scheme_part' and '*path_part' will remain unchanged
 *         (if they weren't NULL).
 */
int
GNUNET_STRINGS_parse_uri (const char *path,
			  char **scheme_part,
			  const char **path_part);


/**
 * Check whether filename is absolute or not, and if it's an URI
 *
 * @param filename filename to check
 * @param can_be_uri #GNUNET_YES to check for being URI, #GNUNET_NO - to
 *        assume it's not URI
 * @param r_is_uri a pointer to an int that is set to #GNUNET_YES if 'filename'
 *        is URI and to GNUNET_NO otherwise. Can be NULL. If 'can_be_uri' is
 *        not #GNUNET_YES, *r_is_uri is set to #GNUNET_NO.
 * @param r_uri_scheme a pointer to a char * that is set to a pointer to URI scheme.
 *        The string is allocated by the function, and should be freed with
 *        GNUNET_free (). Can be NULL.
 * @return #GNUNET_YES if 'filename' is absolute, #GNUNET_NO otherwise.
 */
int
GNUNET_STRINGS_path_is_absolute (const char *filename,
				 int can_be_uri,
				 int *r_is_uri,
				 char **r_uri_scheme);


/**
 * Flags for what we should check a file for.
 */
enum GNUNET_STRINGS_FilenameCheck
{
  /**
   * Check that it exists.
   */
  GNUNET_STRINGS_CHECK_EXISTS = 0x00000001,

  /**
   * Check that it is a directory.
   */
  GNUNET_STRINGS_CHECK_IS_DIRECTORY = 0x00000002,

  /**
   * Check that it is a link.
   */
  GNUNET_STRINGS_CHECK_IS_LINK = 0x00000004,

  /**
   * Check that the path is an absolute path.
   */
  GNUNET_STRINGS_CHECK_IS_ABSOLUTE = 0x00000008
};


/**
 * Perform checks on @a filename.  FIXME: some duplication with
 * "GNUNET_DISK_"-APIs.  We should unify those.
 *
 * @param filename file to check
 * @param checks checks to perform
 * @return #GNUNET_YES if all checks pass, #GNUNET_NO if at least one of them
 *         fails, #GNUNET_SYSERR when a check can't be performed
 */
int
GNUNET_STRINGS_check_filename (const char *filename,
			       enum GNUNET_STRINGS_FilenameCheck checks);


/**
 * Tries to convert @a zt_addr string to an IPv6 address.
 * The string is expected to have the format "[ABCD::01]:80".
 *
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill. Initially gets filled with zeroes,
 *        then its sin6_port, sin6_family and sin6_addr are set appropriately.
 * @return #GNUNET_OK if conversion succeded. #GNUNET_SYSERR otherwise, in which
 *         case the contents of r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ipv6 (const char *zt_addr,
				uint16_t addrlen,
				struct sockaddr_in6 *r_buf);


/**
 * Tries to convert @a zt_addr string to an IPv4 address.
 * The string is expected to have the format "1.2.3.4:80".
 *
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill.
 * @return #GNUNET_OK if conversion succeded. #GNUNET_SYSERR otherwise, in which case
 *         the contents of r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ipv4 (const char *zt_addr,
				uint16_t addrlen,
				struct sockaddr_in *r_buf);


/**
 * Tries to convert @a addr string to an IP (v4 or v6) address.
 * Will automatically decide whether to treat 'addr' as v4 or v6 address.
 *
 * @param addr a string, may not be 0-terminated.
 * @param addrlen number of bytes in @a addr (if addr is 0-terminated,
 *        0-terminator should not be counted towards addrlen).
 * @param r_buf a buffer to fill.
 * @return #GNUNET_OK if conversion succeded. #GNUNET_SYSERR otherwise, in which
 *         case the contents of r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ip (const char *addr,
			      uint16_t addrlen,
			      struct sockaddr_storage *r_buf);


/**
 * Returns utf-8 encoded arguments.  Does nothing (returns a copy of
 * @a argc and @a argv) on any platform other than W32.  Returned @a
 * argv has `u8argv[u8argc] == NULL`.  Returned @a argv is a single
 * memory block, and can be freed with a single GNUNET_free() call.
 *
 * @param argc argc (as given by main())
 * @param argv argv (as given by main())
 * @param u8argc a location to store new argc in (though it's th same as argc)
 * @param u8argv a location to store new argv in
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_STRINGS_get_utf8_args (int argc,
			      char *const *argv,
			      int *u8argc,
                              char *const **u8argv);


/* ***************** IPv4/IPv6 parsing ****************** */

struct GNUNET_STRINGS_PortPolicy
{

  /**
   * Starting port range (0 if none given).
   */
  uint16_t start_port;

  /**
   * End of port range (0 if none given).
   */
  uint16_t end_port;

  /**
   * #GNUNET_YES if the port range should be negated
   * ("!" in policy).
   */
  int negate_portrange;

};


/**
 * @brief IPV4 network in CIDR notation.
 */
struct GNUNET_STRINGS_IPv4NetworkPolicy
{
  /**
   * IPv4 address.
   */
  struct in_addr network;

  /**
   * IPv4 netmask.
   */
  struct in_addr netmask;

  /**
   * Policy for port access.
   */
  struct GNUNET_STRINGS_PortPolicy pp;

};


/**
 * @brief network in CIDR notation for IPV6.
 */
struct GNUNET_STRINGS_IPv6NetworkPolicy
{
  /**
   * IPv6 address.
   */
  struct in6_addr network;

  /**
   * IPv6 netmask.
   */
  struct in6_addr netmask;

  /**
   * Policy for port access.
   */
  struct GNUNET_STRINGS_PortPolicy pp;

};


/**
 * Parse an IPv4 network policy. The argument specifies a list of
 * subnets. The format is <tt>(network[/netmask][:[!]SPORT-DPORT];)*</tt>
 * (no whitespace, must be terminated with a semicolon). The network
 * must be given in dotted-decimal notation. The netmask can be given
 * in CIDR notation (/16) or in dotted-decimal (/255.255.0.0).
 *
 * @param routeListX a string specifying the IPv4 subnets
 * @return the converted list, terminated with all zeros;
 *         NULL if the synatx is flawed
 */
struct GNUNET_STRINGS_IPv4NetworkPolicy *
GNUNET_STRINGS_parse_ipv4_policy (const char *routeListX);


/**
 * Parse an IPv6 network policy. The argument specifies a list of
 * subnets. The format is <tt>(network[/netmask[:[!]SPORT[-DPORT]]];)*</tt>
 * (no whitespace, must be terminated with a semicolon). The network
 * must be given in colon-hex notation.  The netmask must be given in
 * CIDR notation (/16) or can be omitted to specify a single host.
 * Note that the netmask is mandatory if ports are specified.
 *
 * @param routeListX a string specifying the policy
 * @return the converted list, 0-terminated, NULL if the synatx is flawed
 */
struct GNUNET_STRINGS_IPv6NetworkPolicy *
GNUNET_STRINGS_parse_ipv6_policy (const char *routeListX);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_STRING_H */
#endif
/* end of gnunet_util_string.h */

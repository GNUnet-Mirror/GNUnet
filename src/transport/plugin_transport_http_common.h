/*
     This file is part of GNUnet
     (C) 2002-2013 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http_common.c
 * @brief functionality shared by http client and server transport service plugin
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_transport_plugin.h"

/**
 * Timeout values for testing
 */
#define TESTING GNUNET_NO

#if TESTING
#define HTTP_SERVER_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)
#define HTTP_CLIENT_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)
#define HTTP_CLIENT_SESSION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 7)
#define SERVER_SESSION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 7)
#define TIMEOUT_LOG GNUNET_ERROR_TYPE_DEBUG

#else

#if BUILD_HTTPS
#define PROTOCOL "https"
#else
#define PROTOCOL "http"
#endif

#define HTTP_SERVER_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)
#define HTTP_CLIENT_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)
#define HTTP_CLIENT_SESSION_TIMEOUT GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT
#define HTTP_SERVER_SESSION_TIMEOUT GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT
#define TIMEOUT_LOG GNUNET_ERROR_TYPE_DEBUG

#endif

#define HTTP_DEFAULT_PORT 80
#define HTTPS_DEFAULT_PORT 443

enum HTTP_ADDRESS_OPTIONS
{
  HTTP_OPTIONS_NONE = 0,
  HTTP_OPTIONS_VERIFY_CERTIFICATE = 1
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * HttpAddress
 */
struct HttpAddress
{
  /**
   * Address options
   */
  uint32_t options;

  /**
   * Length of URL located after struct
   */
  uint32_t urlen;
};

GNUNET_NETWORK_STRUCT_END

/**
 * Representation of HTTP URL split into its components.
 */
struct SplittedHTTPAddress
{
  char *protocol;
  char *host;
  char *path;
  int port;
};


/**
 * Split an HTTP address into protocol, hostname, port
 * and path components.
 */
struct SplittedHTTPAddress *
http_split_address (const char *addr);


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for @a asc
 */
void
http_common_plugin_address_pretty_printer (void *cls,
                                           const char *type,
                                           const void *addr,
                                           size_t addrlen,
                                           int numeric,
                                           struct GNUNET_TIME_Relative timeout,
                                           GNUNET_TRANSPORT_AddressStringCallback asc,
                                           void *asc_cls);


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param plugin name of the plugin
 * @param addr binary address
 * @param addrlen length of @a addr
 * @return string representing the same address
 */
const char *
http_common_plugin_address_to_string (const char *plugin,
                                      const void *addr,
                                      size_t addrlen);


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure (`struct Plugin*`)
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 *        If the function returns #GNUNET_SYSERR, its contents are undefined.
 * @param added length of created address
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
http_common_plugin_string_to_address (void *cls,
                                      const char *addr,
                                      uint16_t addrlen,
                                      void **buf,
                                      size_t *added);


/**
 * Create a HTTP address from a socketaddr
 *
 * @param protocol protocol
 * @param addr `sockaddr *` address
 * @param addrlen length of the @a addr
 * @return the string
 */
struct HttpAddress *
http_common_address_from_socket (const char *protocol,
                                 const struct sockaddr *addr,
                                 socklen_t addrlen);


/**
 * Create a socketaddr from a HTTP address
 *
 * @param addr a `sockaddr *` address
 * @param addrlen length of the @a addr
 * @param res the result:
 *   #GNUNET_SYSERR, invalid input,
 *   #GNUNET_YES: could convert to ip,
 *   #GNUNET_NO: valid input but could not convert to ip (hostname?)
 * @return the string
 */
struct sockaddr *
http_common_socket_from_address (const void *addr,
                                 size_t addrlen,
                                 int *res);


const char *
http_common_plugin_address_to_url (void *cls,
                                   const void *addr,
                                   size_t addrlen);


/**
 * Get the length of an address
 *
 * @param addr address
 * @return the size
 */
size_t
http_common_address_get_size (const struct HttpAddress * addr);


/**
 * Compare addr1 to addr2
 *
 * @param addr1 address1
 * @param addrlen1 length of @a address1
 * @param addr2 address2
 * @param addrlen2 length of @a address2
 * @return #GNUNET_YES if equal, #GNUNET_NO else
 */
size_t
http_common_cmp_addresses (const void *addr1,
                           size_t addrlen1,
                           const void *addr2,
                           size_t addrlen2);

/* end of plugin_transport_http_common.h */

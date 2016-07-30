/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * obtain information about our current address
 *
 * @defgroup transport  Transport service
 * address information
 *
 * @see [Documentation](https://gnunet.org/transport-service)
 *
 * @{
 */
#ifndef GNUNET_TRANSPORT_HELLO_SERVICE_H
#define GNUNET_TRANSPORT_HELLO_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"

/**
 * Version number of the transport API.
 */
#define GNUNET_TRANSPORT_HELLO_VERSION 0x00000000


/**
 * Some addresses contain sensitive information or are
 * not suitable for global distribution.  We use address
 * classes to filter addresses by which domain they make
 * sense to be used in.  These are used in a bitmask.
 */
enum GNUNET_TRANSPORT_AddressClass
{

  /**
   * No address.
   */
  GNUNET_TRANSPORT_AC_NONE = 0,

  /**
   * Addresses that fall into no other category
   * (i.e. incoming which we cannot use elsewhere).
   */
  GNUNET_TRANSPORT_AC_OTHER = 1,

  /**
   * Addresses that are global and are insensitive
   * (i.e. IPv4).
   */
  GNUNET_TRANSPORT_AC_GLOBAL = 2,

  /**
   * Addresses that are global and are sensitive
   * (i.e. IPv6 with our MAC).
   */
  GNUNET_TRANSPORT_AC_GLOBAL_PRIVATE = 4,

  /**
   * Addresses useful in the local wired network,
   * i.e. a MAC.  Sensitive, but obvious to people nearby.
   * Useful for broadcasts.
   */
  GNUNET_TRANSPORT_AC_LAN = 8,

  /**
   * Addresses useful in the local wireless network,
   * i.e. a MAC.  Sensitive, but obvious to people nearby.
   * Useful for broadcasts.
   */
  GNUNET_TRANSPORT_AC_WLAN = 16,

  /**
   * Addresses useful in the local bluetooth network.  Sensitive, but
   * obvious to people nearby.  Useful for broadcasts.
   */
  GNUNET_TRANSPORT_AC_BT = 32
  
};


/**
 * Function called whenever there is an update to the
 * HELLO of this peer.
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
typedef void
(*GNUNET_TRANSPORT_HelloUpdateCallback) (void *cls,
                                         const struct GNUNET_MessageHeader *hello);


/**
 * Handle to cancel a #GNUNET_TRANSPORT_hello_get() operation.
 */
struct GNUNET_TRANSPORT_HelloGetHandle;


/**
 * Obtain updates on changes to the HELLO message for this peer. The callback
 * given in this function is never called synchronously.
 *
 * @param cfg configuration to use
 * @param ac which network type should the addresses from the HELLO belong to?
 * @param rec function to call with the HELLO
 * @param rec_cls closure for @a rec
 * @return handle to cancel the operation
 */
struct GNUNET_TRANSPORT_HelloGetHandle *
GNUNET_TRANSPORT_hello_get (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            enum GNUNET_TRANSPORT_AddressClass ac,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls);


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param ghh handle to cancel
 */
void
GNUNET_TRANSPORT_hello_get_cancel (struct GNUNET_TRANSPORT_HelloGetHandle *ghh);


/**
 * Function with addresses found in a HELLO.
 *
 * @param cls closure
 * @param peer identity of the peer
 * @param address the address (UTF-8, 0-terminated)
 * @param nt network type of the address
 * @param expiration when does this address expire?
 */
typedef void
(*GNUNET_TRANSPORT_AddressCallback) (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const char *address,
                                     enum GNUNET_ATS_Network_Type nt,
                                     struct GNUNET_TIME_Absolute expiration);


/**
 * Parse a HELLO message that we have received into its
 * constituent addresses.
 *
 * @param hello message to parse
 * @param cb function to call on each address found
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK if hello was well-formed, #GNUNET_SYSERR if not
 */
int
GNUNET_TRANSPORT_hello_parse (const struct GNUNET_MessageHeader *hello,
                              GNUNET_TRANSPORT_AddressCallback cb,
                              void *cb_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_HELLO_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_transport_hello_service.h */

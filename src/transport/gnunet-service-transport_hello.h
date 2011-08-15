/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_hello.h
 * @brief hello API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_HELLO_H
#define GNUNET_SERVICE_TRANSPORT_HELLO_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"


/**
 * After how long do we expire an address in a HELLO that we just
 * validated?  This value is also used for our own addresses when we
 * create a HELLO.
 */
#define GST_HELLO_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)


/**
 * Signature of a function to call whenever our hello changes.
 *
 * @param cls closure
 * @param hello updated HELLO
 */
typedef void (*GST_HelloCallback) (void *cls,
                                   const struct GNUNET_MessageHeader * hello);


/**
 * Initialize the HELLO module.
 *
 * @param cb function to call whenever our HELLO changes
 * @param cb_cls closure for cb
 */
void GST_hello_start (GST_HelloCallback cb, void *cb_cls);


/**
 * Shutdown the HELLO module.
 */
void GST_hello_stop (void);


/**
 * Obtain this peers HELLO message.
 *
 * @return our HELLO message
 */
const struct GNUNET_MessageHeader *GST_hello_get (void);


/**
 * Add or remove an address from this peer's HELLO message.
 *
 * @param addremove GNUNET_YES to add, GNUNET_NO to remove
 * @param plugin_name name of the plugin for which this is an address
 * @param plugin_address address in a plugin-specific format
 * @param plugin_address_len number of bytes in plugin_address
 */
void GST_hello_modify_addresses (int addremove, const char *plugin_name,
                                 const void *plugin_address,
                                 size_t plugin_address_len);


/**
 * Test if a particular address is one of ours.
 *
 * @param plugin_name name of the plugin for which this is an address
 * @param plugin_address address in a plugin-specific format
 * @param plugin_address_len number of bytes in plugin_address
 * @param sig location where to cache PONG signatures for this address [set]
 * @param sig_expiration how long until the current 'sig' expires?
 *            (ZERO if sig was never created) [set]
 * @return GNUNET_YES if this is one of our addresses,
 *         GNUNET_NO if not
 */
int GST_hello_test_address (const char *plugin_name, const void *plugin_address,
                            size_t plugin_address_len,
                            struct GNUNET_CRYPTO_RsaSignature **sig,
                            struct GNUNET_TIME_Absolute **sig_expiration);


#endif
/* end of file gnunet-service-transport_hello.h */

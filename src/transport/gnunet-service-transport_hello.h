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
#include "gnunet_hello_lib.h"



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
void
GST_hello_start (GST_HelloCallback cb, void *cb_cls);


/**
 * Shutdown the HELLO module.
 */
void
GST_hello_stop (void);


/**
 * Obtain this peers HELLO message.
 *
 * @return our HELLO message
 */
const struct GNUNET_MessageHeader *
GST_hello_get (void);


/**
 * Add or remove an address from this peer's HELLO message.
 *
 * @param addremove GNUNET_YES to add, GNUNET_NO to remove
 * @param address address to add or remove
 */
void
GST_hello_modify_addresses (int addremove,
                            const struct GNUNET_HELLO_Address *address);


/**
 * Test if a particular address is one of ours.
 *
 * @param address the address to test
 * @param sig location where to cache PONG signatures for this address [set]
 * @param sig_expiration how long until the current 'sig' expires?
 *            (ZERO if sig was never created) [set]
 * @return GNUNET_YES if this is one of our addresses,
 *         GNUNET_NO if not
 */
int
GST_hello_test_address (const struct GNUNET_HELLO_Address *address,
                        struct GNUNET_CRYPTO_RsaSignature **sig,
                        struct GNUNET_TIME_Absolute **sig_expiration);


#endif
/* end of file gnunet-service-transport_hello.h */

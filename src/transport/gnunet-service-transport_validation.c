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
 * @file transport/gnunet-service-transport_validation.c
 * @brief address validation subsystem
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_validation.h"


/**
 * Start the validation subsystem.
 */
void 
GST_validation_start ()
{
}


/**
 * Stop the validation subsystem.
 */
void
GST_validation_stop ()
{
}


/**
 * We've received a PING.  If appropriate, generate a PONG.
 *
 * @param sender peer sending the PING
 * @param hdr the PING
 * @param plugin_name name of plugin that received the PING
 * @param sender_address address of the sender as known to the plugin, NULL
 *                       if we did not initiate the connection
 * @param sender_address_len number of bytes in sender_address
 */
void
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len)
{
}


/**
 * We've received a PONG.  Check if it matches a pending PING and
 * mark the respective address as confirmed.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG
 * @param plugin_name name of plugin that received the PONG
 * @param sender_address address of the sender as known to the plugin, NULL
 *                       if we did not initiate the connection
 * @param sender_address_len number of bytes in sender_address
 */
void
GST_validation_handle_pong (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len)
{
}


/**
 * We've received a HELLO, check which addresses are new and trigger
 * validation.
 *
 * @param hello the HELLO we received
 */
void
GST_validation_handle_hello (const struct GNUNET_MessageHeader *hello)
{
}


/**
 * Opaque handle to stop incremental validation address callbacks.
 */
struct GST_ValidationIteratorContext
{
};


/**
 * Call the given function for each address for the given target.
 * Can either give a snapshot (synchronous API) or be continuous.
 *
 * @param target peer information is requested for
 * @param snapshot_only GNUNET_YES to iterate over addresses once, GNUNET_NO to
 *                      continue to give information about addresses as it evolves
 * @param cb function to call; will not be called after this function returns
 *                             if snapshot_only is GNUNET_YES
 * @param cb_cls closure for 'cb'
 * @return context to cancel, NULL if 'snapshot_only' is GNUNET_YES
 */
struct GST_ValidationIteratorContext *
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
			      int snapshot_only,
			      GST_ValidationAddressCallback cb,
			      void *cb_cls)
{
  return NULL;
}


/**
 * Cancel an active validation address iteration.
 *
 * @param ctx the context of the operation that is cancelled
 */
void
GST_validation_get_addresses_cancel (struct GST_ValidationIteratorContext *ctx)
{
  GNUNET_break (0);
}


/* end of file gnunet-service-transport_validation.c */

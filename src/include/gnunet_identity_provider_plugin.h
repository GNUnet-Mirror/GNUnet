/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * @author Martin Schanzenbach
 *
 * @file
 * Plugin API for the idp database backend
 *
 * @defgroup identity-provider-plugin  IdP service plugin API
 * Plugin API for the idp database backend
 * @{
 */
#ifndef GNUNET_IDENTITY_PROVIDER_PLUGIN_H
#define GNUNET_IDENTITY_PROVIDER_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_identity_provider_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called by for each matching ticket.
 *
 * @param cls closure
 * @param ticket the ticket
 */
typedef void (*GNUNET_IDENTITY_PROVIDER_TicketIterator) (void *cls,
						 const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket);


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_IDENTITY_PROVIDER_PluginFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /**
   * Store a ticket in the database.
   *
   * @param cls closure (internal context for the plugin)
   * @param ticket the ticket to store
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int (*store_ticket) (void *cls,
			const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket);

  /**
   * Delete a ticket from the database.
   *
   * @param cls closure (internal context for the plugin)
   * @param ticket the ticket to store
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int (*delete_ticket) (void *cls,
			const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket);



  /**
   * Iterate over all tickets
   *
   * @param cls closure (internal context for the plugin)
   * @param identity the identity
   * @param audience GNUNET_YES if the identity is the audience of the ticket
   *                 else it is considered the issuer
   * @param iter function to call with the result
   * @param iter_cls closure for @a iter
   * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
   */
  int (*iterate_tickets) (void *cls,
			  const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
        int audience,
			  uint64_t offset,
			  GNUNET_IDENTITY_PROVIDER_TicketIterator iter, void *iter_cls);


};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @author Martin Schanzenbach
 *
 * @file
 * Plugin API for the idp database backend
 *
 * @defgroup reclaim-plugin  IdP service plugin API
 * Plugin API for the idp database backend
 * @{
 */
#ifndef GNUNET_RECLAIM_PLUGIN_H
#define GNUNET_RECLAIM_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_reclaim_service.h"

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
typedef void (*GNUNET_RECLAIM_TicketIterator) (void *cls,
						 const struct GNUNET_RECLAIM_Ticket *ticket,
             const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_RECLAIM_PluginFunctions
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
			const struct GNUNET_RECLAIM_Ticket *ticket,
      const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);

  /**
   * Delete a ticket from the database.
   *
   * @param cls closure (internal context for the plugin)
   * @param ticket the ticket to store
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int (*delete_ticket) (void *cls,
			const struct GNUNET_RECLAIM_Ticket *ticket);



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
			  GNUNET_RECLAIM_TicketIterator iter, void *iter_cls);

  int (*get_ticket_attributes) (void* cls,
                                const struct GNUNET_RECLAIM_Ticket *ticket,
                                GNUNET_RECLAIM_TicketIterator iter,
                                void *iter_cls);
};

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

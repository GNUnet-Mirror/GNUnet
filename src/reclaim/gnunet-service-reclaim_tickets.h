/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_reclaim_plugin.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_signatures.h"
#include "reclaim.h"

/**
 * Continuation called with ticket.
 *
 * @param cls closure
 * @param ticket the ticket
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_OK on success
 * @param emsg NULL on success, otherwise an error message
 */
typedef void
(*RECLAIM_TICKETS_TicketResult) (void *cls,
                                 struct GNUNET_RECLAIM_Ticket *ticket,
                                 uint32_t success,
                                 const char *emsg);


/**
 * @author Martin Schanzenbach
 * @file src/reclaim/gnunet-service-reclaim_tickets.h
 * @brief reclaim tickets
 *
 */
void
RECLAIM_TICKETS_issue_ticket (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                              const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                              const struct GNUNET_CRYPTO_EcdsaPublicKey *audience,
                              RECLAIM_TICKETS_TicketResult cb,
                              void* cb_cls);

int
RECLAIM_TICKETS_init (const struct GNUNET_CONFIGURATION_Handle *c);

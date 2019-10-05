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

/**
 * @author Martin Schanzenbach
 * @file src/reclaim/gnunet-service-reclaim_tickets.h
 * @brief reclaim tickets
 *
 */

#ifndef GNUNET_SERVICE_RECLAIM_TICKETS_H
#define GNUNET_SERVICE_RECLAIM_TICKETS_H

#include "platform.h"

#include "gnunet_util_lib.h"

#include "gnunet_constants.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "reclaim.h"

/**
 * Ticket iterator
 */
struct RECLAIM_TICKETS_Iterator;


/**
 * Handle to a consume operation
 */
struct RECLAIM_TICKETS_ConsumeHandle;


/**
 * Ticket revocation request handle
 */
struct RECLAIM_TICKETS_RevokeHandle;


/**
 * List of tickets
 */
struct TicketRecordsEntry
{
  /**
   * DLL
   */
  struct TicketRecordsEntry *next;

  /**
   * DLL
   */
  struct TicketRecordsEntry *prev;

  /**
   * Record count
   */
  unsigned int rd_count;

  /**
   * Data
   */
  char *data;

  /**
   * Data size
   */
  size_t data_size;

  /**
   * Label
   */
  char *label;
};


/**
 * Continuation called with ticket.
 *
 * @param cls closure
 * @param ticket the ticket
 */
typedef void (*RECLAIM_TICKETS_TicketIter) (
  void *cls,
  struct GNUNET_RECLAIM_Ticket *ticket);


/**
 * Continuation called with ticket.
 *
 * @param cls closure
 * @param ticket the ticket
 * @param success #GNUNET_SYSERR on failure (including timeout/queue
 * drop/failure to validate) #GNUNET_OK on success
 * @param emsg NULL on success, otherwise an error message
 */
typedef void (*RECLAIM_TICKETS_TicketResult) (
  void *cls,
  struct GNUNET_RECLAIM_Ticket *ticket,
  int32_t success,
  const char *emsg);


/**
 * Consume callback.
 *
 * @param cls closure
 * @param identity the issuer of the ticket/attributes
 * @param l attribute list retrieved through ticket
 * @param success GNUNET_OK on success
 * @param emsg error message (NULL on success)
 */
typedef void (*RECLAIM_TICKETS_ConsumeCallback) (
  void *cls,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *l,
  int32_t success,
  const char *emsg);


/**
 * Revocation callback.
 *
 * @param cls closure
 * @param success GNUNET_OK on success
 */
typedef void (*RECLAIM_TICKETS_RevokeCallback) (void *cls, int32_t success);


/**
 * Revoke a ticket.
 * We start by looking up attribute references in order
 * to change attribute IDs.
 *
 * @param ticket ticket to revoke
 * @param identity private key of issuer
 * @param cb revocation status callback
 * @param cb_cls callback closure
 * @return handle to the operation
 */
struct RECLAIM_TICKETS_RevokeHandle *
RECLAIM_TICKETS_revoke (const struct GNUNET_RECLAIM_Ticket *ticket,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                        RECLAIM_TICKETS_RevokeCallback cb,
                        void *cb_cls);


/**
 * Cancel a revocation.
 *
 * @param rh handle to the operation
 */
void
RECLAIM_TICKETS_revoke_cancel (struct RECLAIM_TICKETS_RevokeHandle *rh);


/**
 * Consume a ticket.
 * We first looking attribute references under the label
 * ticket.rnd in GNS.
 *
 * @param id the audience of the ticket
 * @param ticket the ticket to consume
 * @param cb callback to call with attributes of ticket
 * @param cb_cls callback closure
 * @return handle to the operation
 */
struct RECLAIM_TICKETS_ConsumeHandle *
RECLAIM_TICKETS_consume (const struct GNUNET_CRYPTO_EcdsaPrivateKey *id,
                         const struct GNUNET_RECLAIM_Ticket *ticket,
                         RECLAIM_TICKETS_ConsumeCallback cb,
                         void *cb_cls);


/**
 * Cancel a consume operation
 *
 * @param cth the operation to cancel
 */
void
RECLAIM_TICKETS_consume_cancel (struct RECLAIM_TICKETS_ConsumeHandle *cth);


/**
 * Issue a new reclaim ticket, thereby authorizing
 * the audience to access the set of provided attributes.
 *
 * @param identity the issuer
 * @param attrs the attributes to share
 * @param audience the audience to share the attributes with
 * @param cb the callback to call with the ticket result
 * @param cb_cls the callback closure
 * FIXME: Return handle??
 */
void
RECLAIM_TICKETS_issue (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                       const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                       const struct GNUNET_CRYPTO_EcdsaPublicKey *audience,
                       RECLAIM_TICKETS_TicketResult cb,
                       void *cb_cls);


/**
 * Continue ticket iteration
 *
 * @param iter the iteration to continue
 */
void
RECLAIM_TICKETS_iteration_next (struct RECLAIM_TICKETS_Iterator *iter);


/**
 * Stop a running ticket iteration
 *
 * @param iter iteration to cancel
 */
void
RECLAIM_TICKETS_iteration_stop (struct RECLAIM_TICKETS_Iterator *iter);


/**
 * Iterate over all tickets issued by an identity
 *
 * @param identity the issuing identity
 * @param cb ticket callback function
 * @param cb_cls callback closure
 * @return a handle to the iteration
 */
struct RECLAIM_TICKETS_Iterator *
RECLAIM_TICKETS_iteration_start (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
  RECLAIM_TICKETS_TicketIter cb,
  void *cb_cls);


/**
 * Initialize tickets component
 *
 * @param c the configuration
 * @return GNUNET_SYSERR on error
 */
int
RECLAIM_TICKETS_init (const struct GNUNET_CONFIGURATION_Handle *c);


/**
 * Close handles and clean up.
 * FIXME: cancel all pending operations (gns, ns etc)
 */
void
RECLAIM_TICKETS_deinit (void);

#endif

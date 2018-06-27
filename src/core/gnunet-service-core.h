/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
*/

/**
 * @file core/gnunet-service-core.h
 * @brief Globals for gnunet-service-core
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_H
#define GNUNET_SERVICE_CORE_H

#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
#include "core.h"
#include "gnunet-service-core_typemap.h"


/**
 * Opaque handle to a client.
 */
struct GSC_Client;


/**
 * Record kept for each request for transmission issued by a
 * client that is still pending. (This struct is used by
 * both the 'CLIENTS' and 'SESSIONS' subsystems.)
 */
struct GSC_ClientActiveRequest
{

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct GSC_ClientActiveRequest *next;

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct GSC_ClientActiveRequest *prev;

  /**
   * Handle to the client.
   */
  struct GSC_Client *client_handle;

  /**
   * Which peer is the message going to be for?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * At what time did we first see this request?
   */
  struct GNUNET_TIME_Absolute received_time;

  /**
   * By what time would the client want to see this message out?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * How important is this request.
   */
  enum GNUNET_CORE_Priority priority;

  /**
   * Has this request been solicited yet?
   */
  int was_solicited;

  /**
   * How many bytes does the client intend to send?
   */
  uint16_t msize;

  /**
   * Unique request ID (in big endian).
   */
  uint16_t smr_id;

};


/**
 * Tell a client that we are ready to receive the message.
 *
 * @param car request that is now ready; the responsibility
 *        for the handle remains shared between CLIENTS
 *        and SESSIONS after this call.
 */
void
GSC_CLIENTS_solicit_request (struct GSC_ClientActiveRequest *car);


/**
 * We will never be ready to transmit the given message in (disconnect
 * or invalid request).  Frees resources associated with @a car.  We
 * don't explicitly tell the client, it'll learn with the disconnect
 * (or violated the protocol).
 *
 * @param car request that now permanently failed; the
 *        responsibility for the handle is now returned
 *        to CLIENTS (SESSIONS is done with it).
 * @param drop_client #GNUNET_YES if the client violated the protocol
 *        and we should thus drop the connection
 */
void
GSC_CLIENTS_reject_request (struct GSC_ClientActiveRequest *car,
                            int drop_client);


/**
 * Notify a particular client about a change to existing connection to
 * one of our neighbours (check if the client is interested).  Called
 * from #GSC_SESSIONS_notify_client_about_sessions().
 *
 * @param client client to notify
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for connect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GSC_CLIENTS_notify_client_about_neighbour (struct GSC_Client *client,
                                           const struct GNUNET_PeerIdentity *neighbour,
                                           const struct GSC_TypeMap *tmap_old,
                                           const struct GSC_TypeMap *tmap_new);


/**
 * Deliver P2P message to interested clients.  Caller must have checked
 * that the sending peer actually lists the given message type as one
 * of its types.
 *
 * @param sender peer who sent us the message
 * @param msg the message
 * @param msize number of bytes to transmit
 * @param options options for checking which clients should
 *        receive the message
 */
void
GSC_CLIENTS_deliver_message (const struct GNUNET_PeerIdentity *sender,
                             const struct GNUNET_MessageHeader *msg,
                             uint16_t msize,
                             uint32_t options);


/**
 * Notify all clients about a change to existing session.
 * Called from SESSIONS whenever there is a change in sessions
 * or types processed by the respective peer.
 *
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for connect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GSC_CLIENTS_notify_clients_about_neighbour (const struct GNUNET_PeerIdentity *neighbour,
                                            const struct GSC_TypeMap *tmap_old,
                                            const struct GSC_TypeMap *tmap_new);


/**
 * Our configuration.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GSC_cfg;

/**
 * For creating statistics.
 */
extern struct GNUNET_STATISTICS_Handle *GSC_stats;

/**
 * Our identity.
 */
extern struct GNUNET_PeerIdentity GSC_my_identity;


#endif

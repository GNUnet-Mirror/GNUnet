/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @brief common stuff for the set service
 */

#ifndef GNUNET_SERVICE_SET_H_PRIVATE
#define GNUNET_SERVICE_SET_H_PRIVATE

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_stream_lib.h"
#include "gnunet_set_service.h"
#include "set.h"
#include "mq.h"


/* FIXME: cfuchs */
struct IntersectionState;


/**
 * Extra state required for set union.
 */
struct UnionState;


/**
 * A set that supports a specific operation
 * with other peers.
 */
struct Set
{
  /**
   * Client that owns the set.
   * Only one client may own a set.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for the client
   */
  struct GNUNET_MQ_MessageQueue *client_mq;

  /**
   * Type of operation supported for this set
   */
  uint32_t operation; // use enum from API

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *next;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *prev;

  /**
   * Appropriate state for each type of
   * operation.
   */
  union {
    struct IntersectionState *i;
    struct UnionState *u;
  } state;
};


struct Listener
{
  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *next;

  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *prev;

  /**
   * Client that owns the set.
   * Only one client may own a set.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for the client
   */
  struct GNUNET_MQ_MessageQueue *client_mq;

  /**
   * Type of operation supported for this set
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Application id of intereset for this listener.
   */
  struct GNUNET_HashCode app_id;
};


/**
 * Peer that has connected to us, but is not yet evaluating a set operation.
 * Once the peer has sent a request, and the client has
 * accepted or rejected it, this information will be deleted.
 */
struct Incoming
{
  /**
   * Incoming peers are held in a linked list
   */
  struct Incoming *next;

  /**
   * Incoming peers are held in a linked list
   */
  struct Incoming *prev;

  /**
   * Identity of the peer that connected to us
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Socket connected to the peer
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Message queue for the peer
   */
  struct GNUNET_MQ_MessageQueue *mq;

  /**
   * App code, set once the peer has
   * requested an operation
   */
  struct GNUNET_HashCode app_id;

  /**
   * Context message, set once the peer
   * has requested an operation.
   */
  struct GNUNET_MessageHeader *context_msg;

  /**
   * Salt the peer has requested to use for the
   * operation
   */
  uint16_t salt;

  /**
   * Operation the other peer wants to do
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Request id associated with the
   * request coming from this client
   */
  uint32_t request_id;
};


/**
 * Configuration of the local peer
 */
extern const struct GNUNET_CONFIGURATION_Handle *configuration;


/**
 * Disconnect a client and free all resources
 * that the client allocated (e.g. Sets or Listeners)
 *
 * @param client the client to disconnect
 */
void
_GSS_client_disconnect (struct GNUNET_SERVER_Client *client);


struct Set *
_GSS_union_set_create (void);


void
_GSS_union_evaluate (struct EvaluateMessage *m, struct Set *set);


void
_GSS_union_add (struct ElementMessage *m, struct Set *set);


void
_GSS_union_accept (struct AcceptMessage *m, struct Set *set,
                   struct Incoming *incoming);


#endif

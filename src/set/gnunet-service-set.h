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
 * @file set/gnunet-service-set.h
 * @brief common components for the implementation the different set operations
 * @author Florian Dold
 */

#ifndef GNUNET_SERVICE_SET_H_PRIVATE
#define GNUNET_SERVICE_SET_H_PRIVATE

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_mesh_service.h"
#include "gnunet_set_service.h"
#include "set.h"


/**
 * Implementation-specific set state.
 * Used as opaque pointer, and specified further
 * in the respective implementation.
 */
struct SetState;


/**
 * Implementation-specific set operation.
 * Used as opaque pointer, and specified further
 * in the respective implementation.
 */
struct OperationState;


/* forward declarations */
struct Set;
struct TunnelContext;


/**
 * Detail information about an operation.
 */
struct OperationSpecification
{
  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * The remove peer we evaluate the operation with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;

  /**
   * Context message, may be NULL.
   */
  struct GNUNET_MessageHeader *context_msg;

  /**
   * Salt to use for the operation.
   */
  uint32_t salt;

  /**
   * ID used to identify responses to a client.
   */
  uint32_t client_request_id;

  /**
   * Set associated with the operation, NULL until the spec has been associated
   * with a set.
   */
  struct Set *set;
};


/**
 * Signature of functions that create the implementation-specific
 * state for a set supporting a specific operation.
 *
 * @return a set state specific to the supported operation
 */
typedef struct SetState *(*CreateImpl) (void);


/**
 * Signature of functions that implement the add/remove functionality
 * for a set supporting a specific operation.
 *
 * @param set implementation-specific set state
 * @param msg element message from the client
 */
typedef void (*AddRemoveImpl) (struct SetState *state, const struct GNUNET_SET_Element *element);


/**
 * Signature of functions that handle disconnection
 * of the remote peer.
 *
 * @param op the set operation, contains implementation-specific data
 */
typedef void (*PeerDisconnectImpl) (struct OperationState *op);


/**
 * Signature of functions that implement the destruction of the
 * implementation-specific set state.
 *
 * @param state the set state, contains implementation-specific data
 */
typedef void (*DestroySetImpl) (struct SetState *state);


/**
 * Signature of functions that implement the creation of set operations
 * (currently evaluate and accept).
 *
 * @param spec specification of the set operation to be created
 * @param tunnel the tunnel with the other peer
 * @param tc tunnel context
 */
typedef void (*OpCreateImpl) (struct OperationSpecification *spec,
                              struct GNUNET_MESH_Tunnel *tunnel,
                              struct TunnelContext *tc);


/**
 * Signature of functions that implement the message handling for
 * the different set operations.
 *
 * @param op operation state
 * @param msg received message
 * @return GNUNET_OK on success, GNUNET_SYSERR to
 *         destroy the operation and the tunnel
 */
typedef int (*MsgHandlerImpl) (struct OperationState *op,
                               const struct GNUNET_MessageHeader *msg);

typedef void (*CancelImpl) (struct SetState *set,
                            uint32_t request_id);


/**
 * Dispatch table for a specific set operation.
 * Every set operation has to implement the callback
 * in this struct.
 */
struct SetVT
{
  /**
   * Callback for the set creation.
   */
  CreateImpl create;

  /**
   * Callback for element insertion
   */
  AddRemoveImpl add;

  /**
   * Callback for element removal.
   */
  AddRemoveImpl remove;

  /**
   * Callback for accepting a set operation request
   */
  OpCreateImpl accept;

  /**
   * Callback for starting evaluation with a remote peer.
   */
  OpCreateImpl evaluate;

  /**
   * Callback for destruction of the set state.
   */
  DestroySetImpl destroy_set;

  /**
   * Callback for handling operation-specific messages.
   */
  MsgHandlerImpl msg_handler;

  /**
   * Callback for handling the remote peer's
   * disconnect.
   */
  PeerDisconnectImpl peer_disconnect;

  /**
   * Callback for canceling an operation by
   * its ID.
   */
  CancelImpl cancel;
};


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
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * Type of operation supported for this set
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Virtual table for this set.
   * Determined by the operation type of this set.
   */
  const struct SetVT *vt;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *next;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *prev;

  /**
   * Implementation-specific state.
   */
  struct SetState *state;
};


/**
 * Information about a tunnel we are connected to.
 * Used as tunnel context with mesh.
 */
struct TunnelContext
{
  /**
   * V-Table for the operation belonging
   * to the tunnel contest.
   */
  const struct SetVT *vt;

  /**
   * Implementation-specific operation state.
   */
  struct OperationState *op;
};


/**
 * Get the table with implementing functions for
 * set union.
 */
const struct SetVT *
_GSS_union_vt (void);


#endif

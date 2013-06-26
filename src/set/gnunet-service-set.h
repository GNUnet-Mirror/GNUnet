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
#include "gnunet_mesh2_service.h"
#include "gnunet_set_service.h"
#include "set.h"


/* FIXME: cfuchs */
struct IntersectionState;


/* FIXME: cfuchs */
struct IntersectionOperation;


/**
 * Extra state required for set union.
 */
struct UnionState;

/**
 * State of a union operation being evaluated.
 */
struct UnionEvaluateOperation;



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
 * A listener is inhabited by a client, and
 * waits for evaluation requests from remote peers.
 */
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
   * Client that owns the listener.
   * Only one client may own a listener.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for the client
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;
};


/**
 * Peer that has connected to us, but is not yet evaluating a set operation.
 * Once the peer has sent a request, and the client has
 * accepted or rejected it, this information will be deleted.
 */
struct Incoming;


/**
 * Different types a tunnel can be.
 */
enum TunnelContextType {
  /**
   * Tunnel is waiting for a set request from the tunnel,
   * or for the ack/nack of the client for a received request.
   */
  CONTEXT_INCOMING,

  /**
   * The tunnel performs a union operation.
   */
  CONTEXT_OPERATION_UNION,

  /**
   * The tunnel performs an intersection operation.
   */
  CONTEXT_OPERATION_INTERSECTION,
};


/**
 * State associated with the tunnel, dependent on
 * tunnel type.
 */
union TunnelContextData
{
  /**
   * Valid for tag 'CONTEXT_INCOMING'
   */
  struct Incoming *incoming;

  /**
   * Valid for tag 'CONTEXT_OPERATION_UNION'
   */
  struct UnionEvaluateOperation *union_op;

  /**
   * Valid for tag 'CONTEXT_OPERATION_INTERSECTION'
   */
  struct IntersectionEvaluateOperation *intersection_op;
};

/**
 * Information about a tunnel we are connected to.
 * Used as tunnel context with mesh.
 */
struct TunnelContext
{
  /**
   * Type of the tunnel.
   */
  enum TunnelContextType type;

  /**
   * State associated with the tunnel, dependent on
   * tunnel type.
   */
  union TunnelContextData data;
};



/**
 * Configuration of the local peer.
 */
extern const struct GNUNET_CONFIGURATION_Handle *configuration;

/**
 * Handle to the mesh service.
 */
extern struct GNUNET_MESH_Handle *mesh;


/**
 * Create a new set supporting the union operation
 *
 * @return the newly created set
 */
struct Set *
_GSS_union_set_create (void);


/**
 * Evaluate a union operation with
 * a remote peer.
 *
 * @param spec specification of the operation the evaluate
 * @param tunnel tunnel already connected to the partner peer
 * @return a handle to the operation
 */
struct UnionEvaluateOperation *
_GSS_union_evaluate (struct OperationSpecification *spec,
                     struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Add the element from the given element message to the set.
 *
 * @param m message with the element
 * @param set set to add the element to
 */
void
_GSS_union_add (struct GNUNET_SET_ElementMessage *m, struct Set *set);


/**
 * Remove the element given in the element message from the set.
 * Only marks the element as removed, so that older set operations can still exchange it.
 *
 * @param m message with the element
 * @param set set to remove the element from
 */
void
_GSS_union_remove (struct GNUNET_SET_ElementMessage *m, struct Set *set);


/**
 * Destroy a set that supports the union operation
 *
 * @param set the set to destroy, must be of type GNUNET_SET_OPERATION_UNION
 */
void
_GSS_union_set_destroy (struct Set *set);


/**
 * Accept an union operation request from a remote peer
 *
 * @param spec all necessary information about the operation
 * @param tunnel open tunnel to the partner's peer
 * @return operation
 */
struct UnionEvaluateOperation *
_GSS_union_accept (struct OperationSpecification *spec,
                   struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Destroy a union operation, and free all resources
 * associated with it.
 *
 * @param eo the union operation to destroy
 */
void
_GSS_union_operation_destroy (struct UnionEvaluateOperation *eo);


/**
 * Dispatch messages for a union operation.
 *
 * @param cls closure
 * @param tunnel mesh tunnel
 * @param tunnel_ctx tunnel context
 * @param mh message to process
 * @return GNUNET_SYSERR if the tunnel should be disconnected,
 *         GNUNET_OK otherwise
 */
int
_GSS_union_handle_p2p_message (void *cls,
                               struct GNUNET_MESH_Tunnel *tunnel,
                               void **tunnel_ctx,
                               const struct GNUNET_MessageHeader *mh);


#endif

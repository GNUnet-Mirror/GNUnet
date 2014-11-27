/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/set.h
 * @brief messages used for the set api
 * @author Florian Dold
 * @author Christian Grothoff
 */
#ifndef SET_H
#define SET_H

#include "platform.h"
#include "gnunet_common.h"

/**
 * FIXME
 */
#define GNUNET_SET_ACK_WINDOW 10


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message sent by the client to the service to ask starting
 * a new set to perform operations with.  Includes the desired
 * set operation type.
 */
struct GNUNET_SET_CreateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation type, values of `enum GNUNET_SET_OperationType`
   */
  uint32_t operation GNUNET_PACKED;
};


/**
 * Message sent by the client to the service to start listening for
 * incoming requests to perform a certain type of set operation for a
 * certain type of application.
 */
struct GNUNET_SET_ListenMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_LISTEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation type, values of `enum GNUNET_SET_OperationType`
   */
  uint32_t operation GNUNET_PACKED;

  /**
   * application id
   */
  struct GNUNET_HashCode app_id;

};


/**
 * Message sent by a listening client to the service to accept
 * performing the operation with the other peer.
 */
struct GNUNET_SET_AcceptMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_ACCEPT
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the incoming request we want to accept.
   */
  uint32_t accept_reject_id GNUNET_PACKED;

  /**
   * Request ID to identify responses.
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * How should results be sent to us?
   * See `enum GNUNET_SET_ResultMode`.
   */
  uint32_t result_mode GNUNET_PACKED;
};


/**
 * Message sent by a listening client to the service to reject
 * performing the operation with the other peer.
 */
struct GNUNET_SET_RejectMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_REJECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the incoming request we want to reject.
   */
  uint32_t accept_reject_id GNUNET_PACKED;

};


/**
 * A request for an operation with another client.
 */
struct GNUNET_SET_RequestMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_REQUEST.
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the to identify the request when accepting or
   * rejecting it.
   */
  uint32_t accept_id GNUNET_PACKED;

  /**
   * Identity of the requesting peer.
   */
  struct GNUNET_PeerIdentity peer_id;

  /* rest: nested context message */
};


/**
 * Message sent by client to service to initiate a set operation as a
 * client (not as listener).  A set (which determines the operation
 * type) must already exist in association with this client.
 */
struct GNUNET_SET_EvaluateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_EVALUATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * How should results be sent to us?
   * See `enum GNUNET_SET_ResultMode`.
   */
  uint32_t result_mode GNUNET_PACKED;

  /**
   * Peer to evaluate the operation with
   */
  struct GNUNET_PeerIdentity target_peer;

  /**
   * Application id
   */
  struct GNUNET_HashCode app_id;

  /**
   * Id of our set to evaluate, chosen implicitly by the client when it
   * calls #GNUNE_SET_commit().
   */
  uint32_t request_id GNUNET_PACKED;

  /* rest: context message, that is, application-specific
     message to convince listener to pick up */
};


struct GNUNET_SET_ResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * id the result belongs to
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Was the evaluation successful?
   */
  uint16_t result_status GNUNET_PACKED;

  /**
   * Type of the element attachted to the message,
   * if any.
   */
  uint16_t element_type GNUNET_PACKED;

  /* rest: the actual element */
};


/**
 * Message sent by client to the service to add or remove
 * an element to/from the set.
 */
struct GNUNET_SET_ElementMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_ADD or
   *       #GNUNET_MESSAGE_TYPE_SET_REMOVE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the element to add or remove.
   */
  uint16_t element_type GNUNET_PACKED;

  /**
   * For alignment, always zero.
   */
  uint16_t reserved GNUNET_PACKED;

  /* rest: the actual element */
};


/**
 * Sent to the service by the client
 * in order to cancel a set operation.
 */
struct GNUNET_SET_CancelMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_CANCEL
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the request we want to cancel.
   */
  uint32_t request_id GNUNET_PACKED;
};


struct GNUNET_SET_IterResponseMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_ITER_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the element attachted to the message,
   * if any.
   */
  uint16_t element_type GNUNET_PACKED;

  /* rest: element */
};

struct GNUNET_SET_IterAckMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_ITER_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Non-zero if the service should continue sending elements.
   */
  uint32_t send_more;
};

GNUNET_NETWORK_STRUCT_END

#endif

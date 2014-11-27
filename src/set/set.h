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


struct GNUNET_SET_AcceptMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_ACCEPT
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the incoming request we want to accept / reject.
   */
  uint32_t accept_reject_id GNUNET_PACKED;

  /**
   * Request ID to identify responses,
   * must be 0 if we don't accept the request.
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * How should results be sent to us?
   * See `enum GNUNET_SET_ResultMode`.
   */
  uint32_t result_mode GNUNET_PACKED;
};


struct GNUNET_SET_RejectMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_REJECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the incoming request we want to accept / reject.
   */
  uint32_t accept_reject_id GNUNET_PACKED;

  /**
   * Request ID to identify responses,
   * must be 0 if we don't accept the request.
   */
  uint32_t request_id GNUNET_PACKED;

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


struct GNUNET_SET_EvaluateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_EVALUATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * id of our evaluate, chosen by the client
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Peer to evaluate the operation with
   */
  struct GNUNET_PeerIdentity target_peer;

  /**
   * Application id
   */
  struct GNUNET_HashCode app_id;

  /**
   * Salt to use for the operation.
   */
  uint32_t salt GNUNET_PACKED;

  /**
   * How should results be sent to us?
   * See `enum GNUNET_SET_ResultMode`.
   */
  uint32_t result_mode GNUNET_PACKED;

  /* rest: inner message */
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


struct GNUNET_SET_ElementMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_ADD or
   *       #GNUNET_MESSAGE_TYPE_SET_REMOVE
   */
  struct GNUNET_MessageHeader header;

  uint16_t element_type GNUNET_PACKED;

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

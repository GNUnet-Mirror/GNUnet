/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file set/set.h
 * @brief messages used for the set api
 */
#ifndef SET_H
#define SET_H

#include "platform.h"
#include "gnunet_common.h"


/**
 * The service sends up to GNUNET_SET_ACK_WINDOW messages per client handle,
 * the client should send an ack every GNUNET_SET_ACK_WINDOW/2 messages.
 */
#define GNUNET_SET_ACK_WINDOW 8


GNUNET_NETWORK_STRUCT_BEGIN

struct SetCreateMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation type, values of enum GNUNET_SET_OperationType
   */
  // FIXME: use 32_t for 'enum'.
  uint16_t operation GNUNET_PACKED;
};


struct ListenMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_LISTEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation type, values of enum GNUNET_SET_OperationType
   */
  uint16_t operation GNUNET_PACKED;

  /**
   * application id
   */
  struct GNUNET_HashCode app_id;

};


struct AcceptMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_ACCEPT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request id that will be sent along with
   * results for the accepted operation.
   * Chosen by the client.
   * Must be 0 if the request has been rejected.
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * ID of the incoming request we want to accept / reject.
   */
  uint32_t accept_id GNUNET_PACKED;
};


/**
 * A request for an operation with another client.
 */
struct RequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_Request.
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the request we want to accept,
   * chosen by the service.
   */
  uint32_t accept_id GNUNET_PACKED;

  /**
   * Identity of the requesting peer.
   */
  struct GNUNET_PeerIdentity peer_id;

  /* rest: nested context message */
};


struct EvaluateMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_EVALUATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * id of our evaluate, chosen by the client
   */
  uint32_t request_id GNUNET_PACKED;

  /**
   * Peer to evaluate the operation with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Application id
   */
  struct GNUNET_HashCode app_id;

  /**
   * Salt to use for the operation
   */
  uint16_t salt GNUNET_PACKED;

  /**
   * Padding
   */
  uint16_t reserved GNUNET_PACKED;

  /* rest: inner message */
};


struct ResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_RESULT
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


struct ElementMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_ADD or
   *       GNUNET_MESSAGE_TYPE_SET_REMOVE
   */
  struct GNUNET_MessageHeader header;

  uint16_t element_type GNUNET_PACKED;

  uint16_t reserved GNUNET_PACKED;

  /* rest: the actual element */
};


struct CancelMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_CANCEL
   */
  struct GNUNET_MessageHeader header;

  /**
   * id we want to cancel result belongs to
   */
  uint32_t request_id GNUNET_PACKED;
};


GNUNET_NETWORK_STRUCT_END

#endif

/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/consensus.h
 * @brief
 */
#ifndef SET_H
#define SET_H

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
  uint16_t operation GNUNET_PACKED;
};


struct ListenMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_LISTEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * application id
   */
  struct GNUNET_HashCode app_id;

  /**
   * Operation type, values of enum GNUNET_SET_OperationType
   */
  uint16_t operation GNUNET_PACKED;

  /**
   * Operation type, values of enum GNUNET_SET_OperationType
   */
  uint16_t op GNUNET_PACKED;
  
};


struct AcceptMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_ACCEPT
   */
  struct GNUNET_MessageHeader header;

  /**
   * request id of the request we want to accept
   */
  uint32_t request_id GNUNET_PACKED;
};


struct RequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_Request
   */
  struct GNUNET_MessageHeader header;

  /**
   * requesting peer
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * request id of the request we want to accept
   */
  uint32_t request_id GNUNET_PACKED;

  /* rest: inner message */
};


struct EvaluateMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SET_EVALUATE
   */
  struct GNUNET_MessageHeader header;

  struct GNUNET_PeerIdentity other_peer;

  struct GNUNET_HashCode app_id;

  /**
   * id of our evaluate
   */
  uint32_t request_id GNUNET_PACKED;

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

  uint16_t result_status GNUNET_PACKED;

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

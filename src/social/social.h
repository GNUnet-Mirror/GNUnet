/*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file social/social.h
 * @brief Common type definitions for the Social service and API.
 * @author Gabor X Toth
 */

#ifndef SOCIAL_H
#define SOCIAL_H

#include "platform.h"
#include "gnunet_social_service.h"

enum MessageState
{
  MSG_STATE_START    = 0,
  MSG_STATE_HEADER   = 1,
  MSG_STATE_METHOD   = 2,
  MSG_STATE_MODIFIER = 3,
  MSG_STATE_MOD_CONT = 4,
  MSG_STATE_DATA     = 5,
  MSG_STATE_END      = 6,
  MSG_STATE_CANCEL   = 7,
  MSG_STATE_ERROR    = 8,
};


GNUNET_NETWORK_STRUCT_BEGIN

/**** library -> service ****/


struct AppConnectRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_APP_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /* Followed by char *app_id */
};


struct AppDetachRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_APP_DETACH
   */
  struct GNUNET_MessageHeader header;

  /**
   * Public key of place.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

};


struct MsgProcRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_SET
   */
  struct GNUNET_MessageHeader header;

  /**
   * @see enum GNUNET_SOCIAL_MsgProcFlags
   */
  uint32_t flags;

  /* Followed by char *method_prefix */
};


struct HostEnterRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER
   */
  struct GNUNET_MessageHeader header;

  uint32_t policy GNUNET_PACKED;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;

  struct GNUNET_CRYPTO_EddsaPrivateKey place_key;

  /* Followed by char *app_id */
};


struct GuestEnterRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER
   */
  struct GNUNET_MessageHeader header;

  uint32_t relay_count GNUNET_PACKED;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;

  struct GNUNET_PeerIdentity origin;

  uint32_t flags GNUNET_PACKED;

  /* Followed by char *app_id */
  /* Followed by struct GNUNET_PeerIdentity relays[relay_count] */
  /* Followed by struct GNUNET_MessageHeader *join_msg */
};


/** Compatible parts of HostEnterRequest and GuestEnterRequest */
struct PlaceEnterRequest
{
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;
};


struct EgoPlacePublicKey
{
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;
  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;
};


struct GuestEnterByNameRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_BY_NAME
   */
  struct GNUNET_MessageHeader header;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  /* Followed by char *app_id */
  /* Followed by char *gns_name */
  /* Followed by char *password */
  /* Followed by struct GNUNET_MessageHeader *join_msg */
};


struct ZoneAddPlaceRequest
{
  struct GNUNET_MessageHeader header;

  uint32_t relay_count GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Expiration time: absolute value in us.
   */
  uint64_t expiration_time;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;

  struct GNUNET_PeerIdentity origin;

  /* Followed by const char *name */
  /* Followed by const char *password */
  /* Followed by  struct GNUNET_PeerIdentity *relays[relay_count] */
};


struct ZoneAddNymRequest
{
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Expiration time: absolute value in us.
   */
  uint64_t expiration_time;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  struct GNUNET_CRYPTO_EcdsaPublicKey nym_pub_key;

  /* Followed by const char *name */
};


/**** service -> library ****/


struct AppEgoMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Public key of ego.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  /* Followed by char *name */
};


struct AppPlaceMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE
   */
  struct GNUNET_MessageHeader header;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;

  uint8_t is_host;

  uint8_t place_state;
};


struct HostEnterAck {
  /**
   * Type: GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code for the operation.
   */
  uint32_t result_code GNUNET_PACKED;

  /**
   * Last message ID sent to the channel.
   */
  uint64_t max_message_id GNUNET_PACKED;

  /**
   * Public key of the place.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey place_pub_key;
};


GNUNET_NETWORK_STRUCT_END

#endif

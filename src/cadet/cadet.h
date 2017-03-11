/*
     This file is part of GNUnet.
     Copyright (C) 2001 - 2011 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @author Bartlomiej Polot
 * @file cadet/cadet.h
 */

#ifndef CADET_H_
#define CADET_H_

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include <stdint.h>

#if !defined(GNUNET_CULL_LOGGING)
  #define CADET_TIMING_START \
          struct GNUNET_TIME_Absolute __timestamp;\
          __timestamp = GNUNET_TIME_absolute_get()

  #define CADET_TIMING_END   \
          struct GNUNET_TIME_Relative __duration;\
          __duration = GNUNET_TIME_absolute_get_duration (__timestamp);\
          LOG (GNUNET_ERROR_TYPE_INFO, " %s duration %s\n",\
              __FUNCTION__,\
              GNUNET_STRINGS_relative_time_to_string (__duration, GNUNET_YES));
#else
  #define CADET_TIMING_START
  #define CADET_TIMING_END
#endif


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_protocols.h"
#include "gnunet_cadet_service.h"

/******************************************************************************/
/**************************       CONSTANTS      ******************************/
/******************************************************************************/

/**
 * Minimum value for channel IDs of local clients.
 */
#define GNUNET_CADET_LOCAL_CHANNEL_ID_CLI        0x80000000U

/**
 * FIXME.
 */
#define HIGH_PID                                0xFF000000

/**
 * FIXME.
 */
#define LOW_PID                                 0x00FFFFFF


/**
 * Test if the two PIDs (of type `uint32_t`) are in the range where we
 * have to worry about overflows.  This is the case when @a pid is
 * large and @a max is small, useful when comparing @a pid smaller
 * than @a max.
 */
#define PID_OVERFLOW(pid, max) (((pid) > HIGH_PID) && ((max) < LOW_PID))

/******************************************************************************/
/**************************        MESSAGES      ******************************/
/******************************************************************************/

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Number uniquely identifying a channel of a client.
 */
struct GNUNET_CADET_ClientChannelNumber
{
  /**
   * Values for channel numbering.
   * Local channel numbers given by the service (incoming) are
   * smaller than #GNUNET_CADET_LOCAL_CHANNEL_ID_CLI.
   * Local channel numbers given by the client (created) are
   * larger than #GNUNET_CADET_LOCAL_CHANNEL_ID_CLI.
   */
  uint32_t channel_of_client GNUNET_PACKED;
};


/**
 * Message for a client to create and destroy channels.
 */
struct GNUNET_CADET_PortMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_OPEN
   * or #GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_CLOSE
   *
   * Size: sizeof(struct GNUNET_CADET_ChannelMessage)
   */
  struct GNUNET_MessageHeader header;

  /**
   * Port to open/close.
   */
  struct GNUNET_HashCode port GNUNET_PACKED;
};


/**
 * Message for a client to create channels.
 */
struct GNUNET_CADET_LocalChannelCreateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE
   *
   * Size: sizeof(struct GNUNET_CADET_ChannelOpenMessageMessage)
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of a channel controlled by this client.
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

  /**
   * Channel's peer
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Port of the channel.
   */
  struct GNUNET_HashCode port;

  /**
   * Options.
   */
  uint32_t opt GNUNET_PACKED;
};


/**
 * Message for or to a client to destroy tunnel.
 */
struct GNUNET_CADET_LocalChannelDestroyMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of a channel controlled by this client.
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;
};


/**
 * Message for cadet data traffic.
 */
struct GNUNET_CADET_LocalData
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

  /**
   * Payload follows
   */
};


/**
 * Message to allow the client send more data to the service
 * (always service -> client).
 */
struct GNUNET_CADET_LocalAck
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel allowed to send more data.
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

};


/**
 * Message to inform the client about channels in the service.
 *
 * TODO: split into two messages!
 */
struct GNUNET_CADET_LocalInfo
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL or
   * #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel allowed to send more data.
   */
  struct GNUNET_CADET_ClientChannelNumber ccn;

  /**
   * ID of the destination of the channel (can be local peer).
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message to inform the client about one of the peers in the service.
 *
 * TODO: split into two messages!
 */
struct GNUNET_CADET_LocalInfoPeer
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER or
   * #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of paths.
   */
  uint16_t paths GNUNET_PACKED;

  /**
   * Do we have a tunnel toward this peer?
   */
  int16_t tunnel GNUNET_PACKED;

  /**
   * ID of the peer (can be local peer).
   */
  struct GNUNET_PeerIdentity destination;

  /* If type == PEER (no 'S'): GNUNET_PeerIdentity paths[]
   * (each path ends in destination) */
};


/**
 * Message to inform the client about one of the tunnels in the service.
 *
 * TODO: split into two messages!
 */
struct GNUNET_CADET_LocalInfoTunnel
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL
   * or #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of channels.
   */
  uint32_t channels GNUNET_PACKED;

  /**
   * ID of the destination of the tunnel (can be local peer).
   */
  struct GNUNET_PeerIdentity destination;

  /**
   * Number of connections.
   */
  uint32_t connections GNUNET_PACKED;

  /**
   * Encryption state.
   */
  uint16_t estate GNUNET_PACKED;

  /**
   * Connection state.
   */
  uint16_t cstate GNUNET_PACKED;

  /* If TUNNEL (no 'S'): struct GNUNET_CADET_ConnectionTunnelIdentifier connection_ids[connections] */
  /* If TUNNEL (no 'S'): uint32_t channel_ids[channels] */
};


GNUNET_NETWORK_STRUCT_END


/**
 * @brief Translate a fwd variable into a string representation, for logging.
 *
 * @param fwd Is FWD? (#GNUNET_YES or #GNUNET_NO)
 *
 * @return String representing FWD or BCK.
 */
char *
GC_f2s (int fwd);


/**
 * Check if one pid is bigger than other, accounting for overflow.
 *
 * @param bigger Argument that should be bigger.
 * @param smaller Argument that should be smaller.
 *
 * @return True if bigger (arg1) has a higher value than smaller (arg 2).
 */
int
GC_is_pid_bigger (uint32_t bigger, uint32_t smaller);


/**
 * Get the higher ACK value out of two values, taking in account overflow.
 *
 * @param a First ACK value.
 * @param b Second ACK value.
 *
 * @return Highest ACK value from the two.
 */
uint32_t
GC_max_pid (uint32_t a, uint32_t b);


/**
 * Get the lower ACK value out of two values, taking in account overflow.
 *
 * @param a First ACK value.
 * @param b Second ACK value.
 *
 * @return Lowest ACK value from the two.
 */
uint32_t
GC_min_pid (uint32_t a, uint32_t b);


/**
 * Allocate a string with a hexdump of any binary data.
 *
 * @param bin Arbitrary binary data.
 * @param len Length of @a bin in bytes.
 * @param output Where to write the output (if *output be NULL it's allocated).
 *
 * @return The size of the output.
 */
size_t
GC_bin2s (void *bin,
          unsigned int len,
          char **output);


/**
 * Convert a message type into a string to help debug
 * Generated with:
 * FIND:        "#define ([^ ]+)[ ]*([0-9]+)"
 * REPLACE:     "    case \2: return "\1"; break;"
 *
 * @param m Message type.
 *
 * @return Human readable string description.
 */
const char *
GC_m2s (uint16_t m);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

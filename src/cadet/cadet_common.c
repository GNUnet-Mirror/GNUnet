/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file cadet/cadet_common.c
 * @brief CADET helper functions
 * @author Bartlomiej Polot
 */

#include "cadet.h"

/**
 * @brief Translate a fwd variable into a string representation, for logging.
 *
 * @param fwd Is FWD? (#GNUNET_YES or #GNUNET_NO)
 *
 * @return String representing FWD or BCK.
 */
char *
GC_f2s (int fwd)
{
  if (GNUNET_YES == fwd)
  {
    return "FWD";
  }
  else if (GNUNET_NO == fwd)
  {
    return "BCK";
  }
  else
  {
    /* Not an error, can happen with CONNECTION_BROKEN messages. */
    return "";
  }
}

int
GC_is_pid_bigger (uint32_t bigger, uint32_t smaller)
{
    return (GNUNET_YES == PID_OVERFLOW (smaller, bigger) ||
            (bigger > smaller && GNUNET_NO == PID_OVERFLOW (bigger, smaller)));
}


uint32_t
GC_max_pid (uint32_t a, uint32_t b)
{
  if (GC_is_pid_bigger(a, b))
    return a;
  return b;
}


uint32_t
GC_min_pid (uint32_t a, uint32_t b)
{
  if (GC_is_pid_bigger(a, b))
    return b;
  return a;
}


const struct GNUNET_HashCode *
GC_h2hc (const struct GNUNET_CADET_Hash *id)
{
  static struct GNUNET_HashCode hc;
  memcpy (&hc, id, sizeof (*id));

  return &hc;
}


const char *
GC_h2s (const struct GNUNET_CADET_Hash *id)
{
  static char s[53];

  memcpy (s, GNUNET_h2s_full (GC_h2hc (id)), 52);
  s[52] = '\0';

  return s;
}


#if !defined(GNUNET_CULL_LOGGING)
const char *
GC_m2s (uint16_t m)
{
  static char buf[2][32];
  static int idx;
  const char *t;

  idx = (idx + 1) % 2;
  switch (m)
  {
    /**
     * Used to mark the "payload" of a non-payload message.
     */
    case 0:
      return "";

      /**
       * Request the creation of a path
       */
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
      t = "CONNECTION_CREATE";
      break;

      /**
       * Request the modification of an existing path
       */
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      t = "CONNECTION_ACK";
      break;

      /**
       * Notify that a connection of a path is no longer valid
       */
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      t = "CONNECTION_BROKEN";
      break;

      /**
       * At some point, the route will spontaneously change
       */
    case GNUNET_MESSAGE_TYPE_CADET_PATH_CHANGED:
      t = "PATH_CHANGED";
      break;

      /**
       * Transport payload data.
       */
    case GNUNET_MESSAGE_TYPE_CADET_DATA:
      t = "DATA";
      break;

    /**
     * Confirm receipt of payload data.
     */
    case GNUNET_MESSAGE_TYPE_CADET_DATA_ACK:
      t = "DATA_ACK";
      break;

      /**
       * Key exchange encapsulation.
       */
    case GNUNET_MESSAGE_TYPE_CADET_KX:
      t = "KX";
      break;

      /**
       * New ephemeral key.
       */
    case GNUNET_MESSAGE_TYPE_CADET_KX_EPHEMERAL:
      t = "KX_EPHEMERAL";
      break;

      /**
       * Challenge to test peer's session key.
       */
    case GNUNET_MESSAGE_TYPE_CADET_KX_PING:
      t = "KX_PING";
      break;

      /**
       * Answer to session key challenge.
       */
    case GNUNET_MESSAGE_TYPE_CADET_KX_PONG:
      t = "KX_PONG";
      break;

      /**
       * Request the destuction of a path
       */
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
      t = "CONNECTION_DESTROY";
      break;

      /**
       * ACK for a data packet.
       */
    case GNUNET_MESSAGE_TYPE_CADET_ACK:
      t = "ACK";
      break;

      /**
       * POLL for ACK.
       */
    case GNUNET_MESSAGE_TYPE_CADET_POLL:
      t = "POLL";
      break;

      /**
       * Announce origin is still alive.
       */
    case GNUNET_MESSAGE_TYPE_CADET_KEEPALIVE:
      t = "KEEPALIVE";
      break;

    /**
       * Connect to the cadet service, specifying subscriptions
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_CONNECT:
      t = "LOCAL_CONNECT";
      break;

      /**
       * Ask the cadet service to create a new tunnel
       */
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
      t = "CHANNEL_CREATE";
      break;

      /**
       * Ask the cadet service to destroy a tunnel
       */
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
      t = "CHANNEL_DESTROY";
      break;

      /**
       * Confirm the creation of a channel.
       */
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK:
      t = "CHANNEL_ACK";
      break;

      /**
       * Confirm the creation of a channel.
       */
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK:
      t = "CHANNEL_NACK";
      break;

      /**
       * Encrypted payload.
       */
    case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
      t = "ENCRYPTED";
      break;

      /**
       * Local payload traffic
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA:
      t = "LOCAL_DATA";
      break;

      /**
       * Local ACK for data.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK:
      t = "LOCAL_ACK";
      break;

      /**
       * Local monitoring of channels.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNELS:
      t = "LOCAL_INFO_CHANNELS";
      break;

      /**
       * Local monitoring of a channel.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL:
      t = "LOCAL_INFO_CHANNEL";
      break;

      /**
       * Local monitoring of service.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS:
      t = "LOCAL_INFO_TUNNELS";
      break;

      /**
       * Local monitoring of service.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL:
      t = "LOCAL_INFO_TUNNEL";
      break;

      /**
       * Local information about all connections of service.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CONNECTIONS:
      t = "LOCAL_INFO_CONNECTIONS";
      break;

      /**
       * Local information of service about a specific connection.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CONNECTION:
      t = "LOCAL_INFO_CONNECTION";
      break;

      /**
       * Local information about all peers known to the service.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS:
      t = "LOCAL_INFO_PEERS";
      break;

      /**
       * Local information of service about a specific peer.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER:
      t = "LOCAL_INFO_PEER";
      break;

      /**
       * Traffic (net-cat style) used by the Command Line Interface.
       */
    case GNUNET_MESSAGE_TYPE_CADET_CLI:
      t = "CLI";
      break;

      /**
       * Debug request.
       */
    case GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_DUMP:
      t = "INFO_DUMP";
      break;

    default:
      sprintf(buf[idx], "%u (UNKNOWN TYPE)", m);
      return buf[idx];
  }
  sprintf(buf[idx], "{%18s}", t);
  return buf[idx];
}
#else
const char *
GC_m2s (uint16_t m)
{
  return "";
}
#endif

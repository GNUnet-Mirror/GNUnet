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
 * @file mesh/mesh_common.c
 * @brief MESH helper functions
 * @author Bartlomiej Polot
 */

#include "mesh.h"

/**
 * @brief Translate a fwd variable into a string representation, for logging.
 *
 * @param fwd Is FWD? (#GNUNET_YES or #GNUNET_NO)
 *
 * @return String representing FWD or BCK.
 */
char *
GM_f2s (int fwd)
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
    GNUNET_break (0);
    return "";
  }
}

int
GM_is_pid_bigger (uint32_t bigger, uint32_t smaller)
{
    return (GNUNET_YES == PID_OVERFLOW (smaller, bigger) ||
            (bigger > smaller && GNUNET_NO == PID_OVERFLOW (bigger, smaller)));
}


uint32_t
GM_max_pid (uint32_t a, uint32_t b)
{
  if (GM_is_pid_bigger(a, b))
    return a;
  return b;
}


uint32_t
GM_min_pid (uint32_t a, uint32_t b)
{
  if (GM_is_pid_bigger(a, b))
    return b;
  return a;
}


#if !defined(GNUNET_CULL_LOGGING)
const char *
GM_m2s (uint16_t m)
{
  static char buf[32];
  switch (m)
    {
      /**
       * Request the creation of a path
       */
    case 256: return "CONNECTION_CREATE";

      /**
       * Request the modification of an existing path
       */
    case 257: return "CONNECTION_ACK";

      /**
       * Notify that a connection of a path is no longer valid
       */
    case 258: return "CONNECTION_BROKEN";

      /**
       * At some point, the route will spontaneously change
       */
    case 259: return "PATH_CHANGED";

      /**
       * Transport payload data.
       */
    case 260: return "DATA";

    /**
     * Confirm receipt of payload data.
     */
    case 261: return "DATA_ACK";

      /**
       * Key exchange encapsulation.
       */
    case 262: return "KX";

      /**
       * New ephemeral key.
       */
    case 263: return "KX_EPHEMERAL";

      /**
       * Challenge to test peer's session key.
       */
    case 264: return "KX_PING";

      /**
       * Answer to session key challenge.
       */
    case 265: return "KX_PONG";

      /**
       * Request the destuction of a path
       */
    case 266: return "CONNECTION_DESTROY";

      /**
       * ACK for a data packet.
       */
    case 268: return "ACK";

      /**
       * POLL for ACK.
       */
    case 269: return "POLL";

      /**
       * Announce origin is still alive.
       */
    case 270: return "KEEPALIVE";

    /**
       * Connect to the mesh service, specifying subscriptions
       */
    case 272: return "LOCAL_CONNECT";

      /**
       * Ask the mesh service to create a new tunnel
       */
    case 273: return "CHANNEL_CREATE";

      /**
       * Ask the mesh service to destroy a tunnel
       */
    case 274: return "CHANNEL_DESTROY";

      /**
       * Confirm the creation of a channel.
       */
    case 275: return "CHANNEL_ACK";

      /**
       * Confirm the creation of a channel.
       */
    case 276: return "CHANNEL_NACK";

      /**
       * Encrypted payload.
       */
    case 280: return "ENCRYPTED";

      /**
       * Local payload traffic
       */
    case 285: return "LOCAL_DATA";

      /**
       * Local ACK for data.
       */
    case 286: return "LOCAL_ACK";

      /**
       * Local monitoring of service.
       */
    case 287: return "LOCAL_NACK";

      /**
       * Local monitoring of service.
       */
    case 292: return "LOCAL_INFO_TUNNELS";

      /**
       * Local monitoring of service.
       */
    case 293: return "LOCAL_INFO_TUNNEL";

      /**
       * Local information about all connections of service.
       */
    case 294: return "LOCAL_INFO_CONNECTIONS";

      /**
       * Local information of service about a specific connection.
       */
    case 295: return "LOCAL_INFO_CONNECTION";

      /**
       * Local information about all peers known to the service.
       */
      case 296: return "LOCAL_INFO_PEERS";

      /**
       * Local information of service about a specific peer.
       */
    case 297: return "LOCAL_INFO_PEER";

      /**
       * Traffic (net-cat style) used by the Command Line Interface.
       */
    case 298: return "CLI";

      /**
       * 640kb should be enough for everybody
       */
    case 299: return "RESERVE_END";
    }
  sprintf(buf, "%u (UNKNOWN TYPE)", m);
  return buf;
}
#else
const char *
GM_m2s (uint16_t m)
{
  return "";
}
#endif

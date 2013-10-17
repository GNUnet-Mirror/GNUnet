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


int
GMC_is_pid_bigger (uint32_t bigger, uint32_t smaller)
{
    return (GNUNET_YES == PID_OVERFLOW (smaller, bigger) ||
            (bigger > smaller && GNUNET_NO == PID_OVERFLOW (bigger, smaller)));
}


uint32_t
GMC_max_pid (uint32_t a, uint32_t b)
{
  if (GMC_is_pid_bigger(a, b))
    return a;
  return b;
}


uint32_t
GMC_min_pid (uint32_t a, uint32_t b)
{
  if (GMC_is_pid_bigger(a, b))
    return b;
  return a;
}


#if !defined(GNUNET_CULL_LOGGING)
const char *
GNUNET_MESH_DEBUG_M2S (uint16_t m)
{
  static char buf[32];
  switch (m)
    {
      /**
       * Request the creation of a path
       */
    case 256: return "GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE";

      /**
       * Request the modification of an existing path
       */
    case 257: return "GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK";

      /**
       * Notify that a connection of a path is no longer valid
       */
    case 258: return "GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN";

      /**
       * At some point, the route will spontaneously change
       */
    case 259: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGED";

      /**
       * Transport data in the mesh (origin->end) unicast
       */
    case 260: return "GNUNET_MESSAGE_TYPE_MESH_DATA";

      /**
       * Transport data back in the mesh (end->origin) FIXME
       */
    case 262: return "GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN";

      /**
       * Send origin an ACK that UNICAST arrived FIXME
       */
    case 263: return "GNUNET_MESSAGE_TYPE_MESH_UNICAST_ACK";

      /**
       * Send origin an ACK that TO_ORIGIN arrived FIXME
       */
    case 264: return "GNUNET_MESSAGE_TYPE_MESH_TO_ORIG_ACK";

      /**
       * Request the destuction of a path
       */
    case 266: return "GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY";

      /**
       * Request the destruction of a whole tunnel
       */
    case 267: return "GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY";

      /**
       * ACK for a data packet.
       */
    case 268: return "GNUNET_MESSAGE_TYPE_MESH_ACK";

      /**
       * POLL for ACK.
       */
    case 269: return "GNUNET_MESSAGE_TYPE_MESH_POLL";

      /**
       * Announce origin is still alive.
       */
    case 270: return "GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE";

      /**
       * Announce destination is still alive.
       */
    case 271: return "GNUNET_MESSAGE_TYPE_MESH_BCK_KEEPALIVE";

    /**
       * Connect to the mesh service, specifying subscriptions
       */
    case 272: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT";

      /**
       * Ask the mesh service to create a new tunnel
       */
    case 273: return "GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE";

      /**
       * Ask the mesh service to destroy a tunnel
       */
    case 274: return "GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY";

      /**
       * Confirm the creation of a channel.
       */
    case 275: return "GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK";

      /**
       * Encrypted payload.
       */
    case 280: return "GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED";

      /**
       * Local payload traffic
       */
    case 285: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA";

      /**
       * Local ACK for data.
       */
    case 286: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK";

      /**
       * Local monitoring of service.
       */
    case 287: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS";

      /**
       * Local monitoring of service of a specific tunnel.
       */
    case 288: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL";

      /**
       * 640kb should be enough for everybody
       */
    case 299: return "GNUNET_MESSAGE_TYPE_MESH_RESERVE_END";
    }
  sprintf(buf, "%u (UNKNOWN TYPE)", m);
  return buf;
}
#else
const char *
GNUNET_MESH_DEBUG_M2S (uint16_t m)
{
  return "";
}
#endif

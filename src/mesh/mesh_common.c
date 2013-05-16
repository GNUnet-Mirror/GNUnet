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
    return (GNUNET_YES == PID_OVERFLOW(smaller, bigger) ||
            (bigger > smaller && GNUNET_NO == PID_OVERFLOW(bigger, smaller)));
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

void
GMC_hash32 (uint32_t i, struct GNUNET_HashCode *h)
{
  memset (h, 0, sizeof(struct GNUNET_HashCode));
  *(unsigned int *) h = i;
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
    case 256: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE";

      /**
       * Request the modification of an existing path
       */
    case 257: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGE";

      /**
       * Notify that a connection of a path is no longer valid
       */
    case 258: return "GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN";

      /**
       * At some point, the route will spontaneously change
       */
    case 259: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGED";

      /**
       * Transport data in the mesh (origin->end) unicast
       */
    case 260: return "GNUNET_MESSAGE_TYPE_MESH_UNICAST";

      /**
       * Transport data to all peers in a tunnel
       */
    case 261: return "GNUNET_MESSAGE_TYPE_MESH_MULTICAST";

      /**
       * Transport data back in the mesh (end->origin)
       */
    case 262: return "GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN";

      /**
       * Send origin an ACK that the path is complete
       */
    case 263: return "GNUNET_MESSAGE_TYPE_MESH_PATH_ACK";

      /**
       * Avoid path timeouts
       */
    case 264: return "GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE";

      /**
       * Request the destuction of a path
       */
    case 265: return "GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY";

      /**
       * Request the destruction of a whole tunnel
       */
    case 266: return "GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY";

      /**
       * ACK for a data packet.
       */
    case 267: return "GNUNET_MESSAGE_TYPE_MESH_ACK";

      /**
       * POLL for ACK.
       */
    case 268: return "GNUNET_MESSAGE_TYPE_MESH_POLL";

      /**
       * Connect to the mesh service, specifying subscriptions
       */
    case 272: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT";

      /**
       * Ask the mesh service to create a new tunnel
       */
    case 273: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE";

      /**
       * Ask the mesh service to destroy a tunnel
       */
    case 274: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY";

      /**
       * Ask the mesh service to add a peer to an existing tunnel
       */
    case 275: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD";

      /**
       * Ask the mesh service to remove a peer from a tunnel
       */
    case 276: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL";

      /**
       * Ask the mesh service to add a peer offering a service to an existing tunnel
       */
    case 277: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE";

      /**
       * Ask the mesh service to add a peer described by a service string
       */
    case 278: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_ANNOUNCE_REGEX";

      /**
       * Ask the mesh service to add a peer described by a service string
       */
    case 279: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_STRING";

      /**
       * Ask the mesh service to add a peer to the blacklist of an existing tunnel
       */
    case 280: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_BLACKLIST";

      /**
       * Ask the mesh service to remove a peer from the blacklist of a tunnel
       */
    case 281: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_UNBLACKLIST";

      /**
       * Set tunnel speed to slowest peer
       */
    case 282: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MIN";

      /**
       * Set tunnel speed to fastest peer
       */
    case 283: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MAX";

      /**
       * Set tunnel buffering on.
       */
    case 284: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_BUFFER";

      /**
       * Set tunnel buffering off.
       */
    case 285: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_NOBUFFER";

      /**
       * Local ACK for data.
       */
    case 286: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK";

      /**
       * Local monitoring of service.
       */
    case 287: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_MONITOR";

      /**
       * Local monitoring of service of a specific tunnel.
       */
    case 288: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_MONITOR_TUNNEL";

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

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
 * @file mesh/mesh.c
 * @brief MESH helper functions
 * @author Bartlomiej Polot
 */

#include "mesh.h"

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
    case 256: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE"; break;

      /**
       * Request the modification of an existing path
       */
    case 257: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGE"; break;

      /**
       * Notify that a connection of a path is no longer valid
       */
    case 258: return "GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN"; break;

      /**
       * At some point, the route will spontaneously change
       */
    case 259: return "GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGED"; break;

      /**
       * Transport data in the mesh (origin->end) unicast
       */
    case 260: return "GNUNET_MESSAGE_TYPE_MESH_UNICAST"; break;

      /**
       * Transport data to all peers in a tunnel
       */
    case 261: return "GNUNET_MESSAGE_TYPE_MESH_MULTICAST"; break;

      /**
       * Transport data back in the mesh (end->origin)
       */
    case 262: return "GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN"; break;

      /**
       * Send origin an ACK that the path is complete
       */
    case 263: return "GNUNET_MESSAGE_TYPE_MESH_PATH_ACK"; break;

      /**
       * Avoid path timeouts
       */
    case 264: return "GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE"; break;

      /**
       * Request the destuction of a path
       */
    case 265: return "GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY"; break;

      /**
       * Request the destruction of a whole tunnel
       */
    case 266: return "GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY"; break;

      /**
       * ACK for a data packet.
       */
    case 267: return "GNUNET_MESSAGE_TYPE_MESH_ACK"; break;

      /**
       * Connect to the mesh service, specifying subscriptions
       */
    case 272: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT"; break;

      /**
       * Ask the mesh service to create a new tunnel
       */
    case 273: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE"; break;

      /**
       * Ask the mesh service to destroy a tunnel
       */
    case 274: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY"; break;

      /**
       * Ask the mesh service to add a peer to an existing tunnel
       */
    case 275: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD"; break;

      /**
       * Ask the mesh service to remove a peer from a tunnel
       */
    case 276: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL"; break;

      /**
       * Ask the mesh service to add a peer offering a service to an existing tunnel
       */
    case 277: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE"; break;

      /**
       * Ask the mesh service to add a peer described by a service string
       */
    case 278: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_ANNOUNCE_REGEX"; break;

      /**
       * Ask the mesh service to add a peer described by a service string
       */
    case 279: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_STRING"; break;

      /**
       * Ask the mesh service to add a peer to the blacklist of an existing tunnel
       */
    case 280: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_BLACKLIST"; break;

      /**
       * Ask the mesh service to remove a peer from the blacklist of a tunnel
       */
    case 281: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_UNBLACKLIST"; break;

      /**
       * Set tunnel speed to slowest peer
       */
    case 282: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MIN"; break;

      /**
       * Set tunnel speed to fastest peer
       */
    case 283: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_MAX"; break;

      /**
       * Set tunnel buffering on.
       */
    case 284: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_BUFFER"; break;

      /**
       * Set tunnel buffering off.
       */
    case 285: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_NOBUFFER"; break;

      /**
       * Local ACK for data.
       */
    case 286: return "GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK"; break;

      /**
       * 640kb should be enough for everybody
       */
    case 299: return "GNUNET_MESSAGE_TYPE_MESH_RESERVE_END"; break;
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

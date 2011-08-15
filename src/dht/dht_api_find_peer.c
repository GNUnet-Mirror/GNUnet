/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file dht/dht_api_find_peer.c
 * @brief library to access the DHT to find peers
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "dht.h"


/**
 * Handle to control a find peer operation.
 */
struct GNUNET_DHT_FindPeerHandle
{

  /**
   * Handle to the actual route operation for the request
   */
  struct GNUNET_DHT_RouteHandle *route_handle;

  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_FindPeerProcessor proc;

  /**
   * Closure for the iterator callback
   */
  void *proc_cls;

};



/**
 * Iterator called on each result obtained from a generic route
 * operation
 *
 * @param cls closure
 * @param key key that was used
 * @param outgoing_path NULL-terminated array of pointers
 *                      to the peers on reverse path
 *                      (or NULL if not recorded)
 * @param reply response
 */
static void
find_peer_reply_iterator (void *cls, const GNUNET_HashCode * key,
                          const struct GNUNET_PeerIdentity *const
                          *outgoing_path,
                          const struct GNUNET_MessageHeader *reply)
{
  struct GNUNET_DHT_FindPeerHandle *find_peer_handle = cls;
  const struct GNUNET_MessageHeader *hello;

  if (ntohs (reply->type) != GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (ntohs (reply->size) >= sizeof (struct GNUNET_MessageHeader));
  hello = (const struct GNUNET_MessageHeader *) &reply[1];
  if (ntohs (hello->type) != GNUNET_MESSAGE_TYPE_HELLO)
  {
    GNUNET_break (0);
    return;
  }
  find_peer_handle->proc (find_peer_handle->proc_cls,
                          (const struct GNUNET_HELLO_Message *) hello);
}



/**
 * Perform an asynchronous FIND PEER operation on the DHT.
 *
 * @param handle handle to the DHT service
 * @param timeout timeout for this request to be sent to the
 *        service
 * @param options routing options for this message
 * @param key the key to look up
 * @param proc function to call on each result
 * @param proc_cls closure for proc
 * @return handle to stop the async get, NULL on error
 */
struct GNUNET_DHT_FindPeerHandle *
GNUNET_DHT_find_peer_start (struct GNUNET_DHT_Handle *handle,
                            struct GNUNET_TIME_Relative timeout,
                            const GNUNET_HashCode * key,
                            enum GNUNET_DHT_RouteOption options,
                            GNUNET_DHT_FindPeerProcessor proc, void *proc_cls)
{
  struct GNUNET_DHT_FindPeerHandle *find_peer_handle;
  struct GNUNET_DHT_FindPeerMessage find_peer_msg;

  find_peer_handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_FindPeerHandle));
  find_peer_handle->proc = proc;
  find_peer_handle->proc_cls = proc_cls;
  find_peer_msg.header.size =
      htons (sizeof (struct GNUNET_DHT_FindPeerMessage));
  find_peer_msg.header.type = htons (GNUNET_MESSAGE_TYPE_DHT_FIND_PEER);
  find_peer_handle->route_handle =
      GNUNET_DHT_route_start (handle, key, 0, options, &find_peer_msg.header,
                              timeout, &find_peer_reply_iterator,
                              find_peer_handle, NULL, NULL);
  GNUNET_break (find_peer_handle->route_handle != NULL);
  return find_peer_handle;
}


/**
 * Stop async find peer.  Frees associated resources.
 *
 * @param find_peer_handle GET operation to stop.
 */
void
GNUNET_DHT_find_peer_stop (struct GNUNET_DHT_FindPeerHandle *find_peer_handle)
{
  GNUNET_DHT_route_stop (find_peer_handle->route_handle);
  GNUNET_free (find_peer_handle);
}


/* end of dht_api_find_peer.c */

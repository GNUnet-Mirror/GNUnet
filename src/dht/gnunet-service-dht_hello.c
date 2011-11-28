/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-dht_hello.c
 * @brief GNUnet DHT integration with peerinfo
 * @author Christian Grothoff
 *
 * TODO:
 * - consider adding mechanism to remove expired HELLOs
 */
#include "platform.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet_peerinfo_service.h"


/**
 * Handle for peerinfo notifications.
 */
static struct GNUNET_PEERINFO_NotifyContext *pnc;

/**
 * Hash map of peers to HELLOs.
 */
static struct GNUNET_CONTAINER_MultiHashMap *peer_to_hello;


/**
 * Obtain a peer's HELLO if available
 *
 * @param peer peer to look for a HELLO from
 * @return HELLO for the given peer
 */
const struct GNUNET_HELLO_Message *
GDS_HELLO_get (const struct GNUNET_PeerIdentity *peer)
{
  if (NULL == peer_to_hello)
    return NULL;
  return GNUNET_CONTAINER_multihashmap_get (peer_to_hello, &peer->hashPubKey);
}


/**
 * Function called for each HELLO known to PEERINFO.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param err_msg error message (not used)
 */
static void
process_hello (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  struct GNUNET_TIME_Absolute ex;
  struct GNUNET_HELLO_Message *hm;

  if (hello == NULL)
    return;
  ex = GNUNET_HELLO_get_last_expiration (hello);
  if (GNUNET_TIME_absolute_get_remaining (ex).rel_value == 0)
    return;
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# HELLOs obtained from peerinfo"), 1,
                            GNUNET_NO);
  hm = GNUNET_CONTAINER_multihashmap_get (peer_to_hello, &peer->hashPubKey);
  GNUNET_free_non_null (hm);
  hm = GNUNET_malloc (GNUNET_HELLO_size (hello));
  memcpy (hm, hello, GNUNET_HELLO_size (hello));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONTAINER_multihashmap_put (peer_to_hello,
                                                    &peer->hashPubKey, hm,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE));
}


/**
 * Initialize HELLO subsystem.
 */
void
GDS_HELLO_init ()
{
  pnc = GNUNET_PEERINFO_notify (GDS_cfg, &process_hello, NULL);
  peer_to_hello = GNUNET_CONTAINER_multihashmap_create (256);
}


/**
 * Free memory occopied by the HELLO.
 */
static int
free_hello (void *cls, const GNUNET_HashCode * key, void *hello)
{
  GNUNET_free (hello);
  return GNUNET_OK;
}


/**
 * Shutdown HELLO subsystem.
 */
void
GDS_HELLO_done ()
{
  if (NULL != pnc)
  {
    GNUNET_PEERINFO_notify_cancel (pnc);
    pnc = NULL;
  }
  if (NULL != peer_to_hello)
  {
    GNUNET_CONTAINER_multihashmap_iterate (peer_to_hello, &free_hello, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (peer_to_hello);
  }
}

/* end of gnunet-service-dht_hello.c */

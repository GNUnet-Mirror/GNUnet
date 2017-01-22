/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_hello.c
 * @brief spread knowledge about how to contact other peers from PEERINFO
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * TODO:
 * - is most of this necessary/helpful?
 * - should we not simply restrict this to OUR hello?
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_statistics_service.h"
#include "gnunet_peerinfo_service.h"
#include "cadet_protocol.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_dht.h"
#include "gnunet-service-cadet-new_hello.h"
#include "gnunet-service-cadet-new_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"cadet-hll",__VA_ARGS__)

/**
 * Hello message of local peer.
 */
static struct GNUNET_HELLO_Message *mine;

/**
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Iterator context.
 */
static struct GNUNET_PEERINFO_NotifyContext *nc;


/**
 * Process each hello message received from peerinfo.
 *
 * @param cls Closure (unused).
 * @param peer Identity of the peer.
 * @param hello Hello of the peer.
 * @param err_msg Error message.
 */
static void
got_hello (void *cls,
           const struct GNUNET_PeerIdentity *id,
           const struct GNUNET_HELLO_Message *hello,
           const char *err_msg)
{
  struct CadetPeer *peer;

  if ( (NULL == id) ||
       (NULL == hello) )
    return;
  if (0 == memcmp (id,
                   &my_full_id,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_free_non_null (mine);
    mine = (struct GNUNET_HELLO_Message *) GNUNET_copy_message (&hello->header);
    GCD_hello_update ();
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Hello for %s (%d bytes), expires on %s\n",
       GNUNET_i2s (id),
       GNUNET_HELLO_size (hello),
       GNUNET_STRINGS_absolute_time_to_string (GNUNET_HELLO_get_last_expiration (hello)));
  peer = GCP_get (id,
                  GNUNET_YES);
  GCP_set_hello (peer,
                 hello);
}


/**
 * Initialize the hello subsystem.
 *
 * @param c Configuration.
 */
void
GCH_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_assert (NULL == nc);
  peerinfo = GNUNET_PEERINFO_connect (c);
  nc = GNUNET_PEERINFO_notify (c,
                               GNUNET_NO,
                               &got_hello,
                               NULL);
}


/**
 * Shut down the hello subsystem.
 */
void
GCH_shutdown ()
{
  if (NULL != nc)
  {
    GNUNET_PEERINFO_notify_cancel (nc);
    nc = NULL;
  }
  if (NULL != peerinfo)
  {
    GNUNET_PEERINFO_disconnect (peerinfo);
    peerinfo = NULL;
  }
  if (NULL != mine)
  {
    GNUNET_free (mine);
    mine = NULL;
  }
}


/**
 * Get own hello message.
 *
 * @return Own hello message.
 */
const struct GNUNET_HELLO_Message *
GCH_get_mine (void)
{
  return mine;
}

/* end of gnunet-service-cadet-new_hello.c */

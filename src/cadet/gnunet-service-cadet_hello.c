/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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

#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_statistics_service.h"
#include "gnunet_peerinfo_service.h"

#include "cadet_protocol.h"
#include "cadet_path.h"

#include "gnunet-service-cadet_hello.h"
#include "gnunet-service-cadet_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"cadet-hll",__VA_ARGS__)


/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/



/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Local peer own ID (memory efficient handle).
 */
extern GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value).
 */
extern struct GNUNET_PeerIdentity my_full_id;


/**
 * Don't try to recover tunnels if shutting down.
 */
extern int shutting_down;


/**
 * Hello message of local peer.
 */
const struct GNUNET_HELLO_Message *mine;

/**
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Iterator context.
 */
struct GNUNET_PEERINFO_NotifyContext* nc;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

/**
 * Process each hello message received from peerinfo.
 *
 * @param cls Closure (unused).
 * @param peer Identity of the peer.
 * @param hello Hello of the peer.
 * @param err_msg Error message.
 */
static void
got_hello (void *cls, const struct GNUNET_PeerIdentity *id,
           const struct GNUNET_HELLO_Message *hello,
           const char *err_msg)
{
  struct CadetPeer *peer;

  if (NULL == id || NULL == hello)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " hello with id %p and msg %p\n", id, hello);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " hello for %s (%d bytes), expires on %s\n",
       GNUNET_i2s (id), GNUNET_HELLO_size (hello),
       GNUNET_STRINGS_absolute_time_to_string (GNUNET_HELLO_get_last_expiration(hello)));
  peer = GCP_get (id, GNUNET_YES);
  GCP_set_hello (peer, hello);

  if (GCP_get_short_id (peer) == myid)
    mine = GCP_get_hello (peer);
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize the hello subsystem.
 *
 * @param c Configuration.
 */
void
GCH_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
  GNUNET_assert (NULL == nc);
  peerinfo = GNUNET_PEERINFO_connect (c);
  nc = GNUNET_PEERINFO_notify (c, GNUNET_NO, &got_hello, NULL);
}


/**
 * Shut down the hello subsystem.
 */
void
GCH_shutdown ()
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down channels\n");
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


/**
 * Get another peer's hello message.
 *
 * @param id ID of the peer whose hello message is requested.
 *
 * @return Hello message, if any (NULL possible).
 */
const struct GNUNET_HELLO_Message *
GCH_get (const struct GNUNET_PeerIdentity *id)
{
  struct CadetPeer *p;

  p = GCP_get (id, GNUNET_NO);
  if (NULL == p)
    return NULL;
  return GCP_get_hello (p);
}


/**
 * Convert a hello message to a string.
 *
 * @param h Hello message.
 */
char *
GCH_2s (const struct GNUNET_HELLO_Message *h)
{
  return "hello (TODO)";
}



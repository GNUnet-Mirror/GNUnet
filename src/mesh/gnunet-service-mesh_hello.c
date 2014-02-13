/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

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

#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_statistics_service.h"
#include "gnunet_peerinfo_service.h"

#include "mesh_protocol.h"
#include "mesh_path.h"

#include "gnunet-service-mesh_hello.h"
#include "gnunet-service-mesh_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"mesh-hll",__VA_ARGS__)


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
  struct MeshPeer *peer;

  if (NULL == id || NULL == hello)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " hello with id %p and msg %p\n", id, hello);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " hello for %s (%d bytes), expires on %s\n",
       GNUNET_i2s (id), NULL != hello ? GNUNET_HELLO_size (hello) : -1,
       GNUNET_STRINGS_absolute_time_to_string (GNUNET_HELLO_get_last_expiration(hello)));
  if (NULL == hello)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " hello is NULL\n");
    return;
  }
  peer = GMP_get (id);
  GMP_set_hello (peer, hello);

  if (GMP_get_short_id (peer) == myid)
  {
    mine = GMP_get_hello (peer);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " updated mine to %p\n", mine);
  }
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
GMH_init (const struct GNUNET_CONFIGURATION_Handle *c)
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
GMH_shutdown ()
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
}


/**
 * Get own hello message.
 *
 * @return Own hello message.
 */
const struct GNUNET_HELLO_Message *
GMH_get_mine (void)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, " mine is %p\n", mine);
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
GMH_get (const struct GNUNET_PeerIdentity *id)
{
  return GMP_get_hello (GMP_get (id));
}


/**
 * Convert a hello message to a string.
 *
 * @param h Hello message.
 */
char *
GMH_2s (const struct GNUNET_HELLO_Message *h)
{
  return "hello (TODO)";
}



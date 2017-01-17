/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_core.c
 * @brief cadet service; interaction with CORE service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * All functions in this file should use the prefix GCO (Gnunet Cadet cOre (bottom))
 */
#include "platform.h"
#include "gnunet-service-cadet-new_core.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet_core_service.h"

/**
 * Handle to the CORE service.
 */
static struct GNUNET_CORE_Handle *core;


/**
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_init_cb (void *cls,
              const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (0 ==
                memcmp (my_identity,
                        &my_full_id,
                        sizeof (struct GNUNET_PeerIdentity)));
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void *
core_connect_cb (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  struct CadetPeer *cp;

  cp = GCP_get (peer,
                GNUNET_YES);
  GCP_set_mq (cp,
              mq);
  return cp;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *peer_cls)
{
  struct CadetPeer *cp = peer_cls;

  GCP_set_mq (cp,
              NULL);
}


/**
 * Initialize the CORE subsystem.
 *
 * @param c Configuration.
 */
void
GCO_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_handler_end ()
  };
  core = GNUNET_CORE_connect (c,
                              NULL,
                              &core_init_cb,
                              &core_connect_cb,
                              &core_disconnect_cb,
                              handlers);
}


/**
 * Shut down the CORE subsystem.
 */
void
GCO_shutdown ()
{
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
}

/* end of gnunet-cadet-service_core.c */

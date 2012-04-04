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
 * @file integration-test/connection_watchdog.c
 * @brief tool to monitor core and transport connections for consistency
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_statistics_service.h"

/**
 * Final status code.
 */
static int ret;

struct GNUNET_TRANSPORT_Handle *th;
struct GNUNET_CORE_Handle *ch;
struct GNUNET_PeerIdentity my_peer_id;

static unsigned int transport_connections;
static unsigned int core_connections;



static struct GNUNET_CONTAINER_MultiHashMap *peers;

struct PeerContainer
{
  struct GNUNET_PeerIdentity id;
  int transport_connected;
  int core_connected;
};


int map_check_it (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct PeerContainer *pc = value;
  if (pc->core_connected != pc->transport_connected)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
     "Inconsistend peer `%s': TRANSPORT %s <-> CORE %s\n",
     GNUNET_i2s (&pc->id),
     (GNUNET_YES == pc->transport_connected) ? "YES" : "NO",
     (GNUNET_YES == pc->core_connected) ? "YES" : "NO");
  }

  return GNUNET_OK;
}


int map_cleanup_it (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct PeerContainer *pc = value;
  GNUNET_CONTAINER_multihashmap_remove(peers, key, value);
  GNUNET_free (pc);
  return GNUNET_OK;
}

static void map_check (void)
{

  GNUNET_CONTAINER_multihashmap_iterate (peers, &map_check_it, NULL);
}

static void
map_connect (const struct GNUNET_PeerIdentity *peer, void * source)
{
  struct PeerContainer * pc;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(peers, &peer->hashPubKey))
  {
    pc = GNUNET_malloc (sizeof (struct PeerContainer));
    pc->id = *peer;
    pc->core_connected = GNUNET_NO;
    pc->transport_connected = GNUNET_NO;
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(peers, &peer->hashPubKey, pc, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  pc = GNUNET_CONTAINER_multihashmap_get(peers, &peer->hashPubKey);
  if (source == th)
  {
    if (GNUNET_NO == pc->transport_connected)
    {
      pc->transport_connected = GNUNET_YES;
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified multiple times about for peers `%s' (%s : %s)\n",
           "TRANSPORT",
           GNUNET_i2s (&pc->id),
           "CORE", (pc->core_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }
  if (source == ch)
  {
    if (GNUNET_NO == pc->core_connected)
    {
      pc->core_connected = GNUNET_YES;
      return;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified multiple times about for peers `%s' (%s : %s)\n",
           "CORE",
           GNUNET_i2s (&pc->id),
               "TRANSPORT", (pc->transport_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
      return;
    }
  }
}


static void
map_disconnect (const struct GNUNET_PeerIdentity * peer, void * source)
{

  struct PeerContainer * pc;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(peers, &peer->hashPubKey))
  {
    if (source == th)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         "%s disconnect notification for unknown peer `%s'\n",
         "TRANSPORT", GNUNET_i2s (peer));
      GNUNET_break (0);
      return;
    }
    if (source == ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         "%s disconnect notification for unknown peer `%s'\n",
         "CORE", GNUNET_i2s (peer));
      return;
    }
  }

  pc = GNUNET_CONTAINER_multihashmap_get(peers, &peer->hashPubKey);
  if (source == th)
  {
    if (GNUNET_YES == pc->transport_connected)
    {
      pc->transport_connected = GNUNET_NO;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified for not connected peer `%s' (%s : %s)\n",
           "TRANSPORT",
           GNUNET_i2s (&pc->id),
           "CORE", (pc->core_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }
  if (source == ch)
  {
    if (GNUNET_YES == pc->core_connected)
    {
      pc->core_connected = GNUNET_NO;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           "%s notified for not connected peer `%s' (%s : %s)\n",
           "CORE",
           GNUNET_i2s (&pc->id),
           "TRANSPORT", (pc->transport_connected == GNUNET_YES) ? "yes" : "no");
      GNUNET_break (0);
    }
  }

  if ((GNUNET_NO == pc->core_connected) && (GNUNET_NO == pc->transport_connected))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Removing peer `%s'\n", GNUNET_i2s (&pc->id));
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (peers, &peer->hashPubKey, pc));
    GNUNET_free (pc);
  }

}


static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != th)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Disconnecting from transport service\n");
    GNUNET_TRANSPORT_disconnect (th);
    th = NULL;
  }
  if (NULL != ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Disconnecting from core service\n");
    GNUNET_CORE_disconnect (ch);
    ch = NULL;
  }

  map_check();

  GNUNET_CONTAINER_multihashmap_iterate (peers, &map_cleanup_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(peers);
}

void
transport_notify_connect_cb (void *cls,
                const struct GNUNET_PeerIdentity
                * peer,
                const struct
                GNUNET_ATS_Information * ats,
                uint32_t ats_count)
{
  transport_connections ++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "TRANSPORT connect notification for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), transport_connections);
  map_connect (peer, th);
}

/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
void
transport_notify_disconnect_cb (void *cls,
                               const struct
                               GNUNET_PeerIdentity * peer)
{
  GNUNET_assert (transport_connections > 0);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "TRANSPORT disconnect notification for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), transport_connections) ;
  map_disconnect (peer, th);
  transport_connections --;

}


static void
core_connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_ATS_Information *atsi,
                      unsigned int atsi_count)
{
  if (0 != memcmp (peer, &my_peer_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    core_connections ++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      connect notification for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
    map_connect (peer, ch);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      connect notification for myself `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
  }
}

static void
core_disconnect_cb (void *cls,
                      const struct
                      GNUNET_PeerIdentity * peer)
{
  if (0 != memcmp (peer, &my_peer_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_assert (core_connections >= 0);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      disconnect notification for peer `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
    map_disconnect (peer, ch);
    core_connections --;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CORE      disconnect notification for myself `%s' (%u total)\n",
      GNUNET_i2s (peer), core_connections);
  }

}

static void
core_init_cb (void *cls, struct GNUNET_CORE_Handle *server,
                   const struct GNUNET_PeerIdentity *my_identity)
{
  my_peer_id = *my_identity;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Connected to core service\n");
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  transport_connections = 0;
  core_connections = 0;

  peers = GNUNET_CONTAINER_multihashmap_create (20);

  th = GNUNET_TRANSPORT_connect(cfg, NULL, NULL, NULL,
                                &transport_notify_connect_cb,
                                &transport_notify_disconnect_cb);
  GNUNET_assert (th != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Connected to transport service\n");
  ch =  GNUNET_CORE_connect (cfg, 1, NULL,
                             &core_init_cb,
                             &core_connect_cb,
                             &core_disconnect_cb,
                             NULL, GNUNET_NO,
                             NULL, GNUNET_NO,
                             NULL);
  GNUNET_assert (ch != NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task, NULL);

}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    /* FIMXE: add options here */
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-template",
                              gettext_noop ("help text"), options, &run,
                              NULL)) ? ret : 1;
}

/* end of connection_watchdog.c */

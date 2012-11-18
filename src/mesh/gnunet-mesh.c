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
 * @file mesh/gnunet-mesh.c
 * @brief Print information about mesh tunnels and peers.
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_program_lib.h"


/**
 * Option -m.
 */
static int monitor_connections;


/**
 * Mesh handle.
 */
static struct GNUNET_MESH_Handle *mh;


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls Closure (unused).
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != mh)
  {
    GNUNET_MESH_disconnect (mh);
        mh = NULL;
  }
}


/**
 * Method called to retrieve information about each tunnel the mesh peer
 * is aware of.
 *
 * @param cls Closure (unused).
 * @param initiator Peer that started the tunnel (owner).
 * @param tunnel_number Tunnel number.
 * @param peer Array of peer identities that participate in the tunnel.
 * @param npeers Number of peers in peers.
 */
static void
monitor_callback (void *cls,
                 const struct GNUNET_PeerIdentity *initiator,
                 unsigned int tunnel_number,
                 const struct GNUNET_PeerIdentity *peers,
                 unsigned int npeers)
{
  unsigned int i;

  fprintf (stdout, "Tunnel %s [%u]: %u peers\n",
           GNUNET_i2s (initiator), tunnel_number, npeers);
  for (i = 0; i < npeers; i++)
    fprintf (stdout, " * %s\n", GNUNET_i2s (&peers[i]));
  fprintf (stdout, "\n");
}


/**
 * Call MESH's monitor API, start monitoring process
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
monitor (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }
  GNUNET_MESH_monitor (mh, &monitor_callback, NULL);
  if (GNUNET_YES == monitor_connections)
  {
    /* keep open */
  }
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
  static const struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0} /* FIXME add option to monitor msg types */
  };
  GNUNET_MESH_ApplicationType apps = 0; /* FIXME add option to monitor apps */

  if (args[0] != NULL)
  {
    FPRINTF (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  mh = GNUNET_MESH_connect (cfg,
                            NULL, /* cls */
                            NULL, /* nt */
                            NULL, /* cleaner */
                            handlers,
                            &apps);
  if (NULL == mh)
    GNUNET_SCHEDULER_add_now (shutdown_task, NULL);
  else
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  shutdown_task, NULL);
  GNUNET_SCHEDULER_add_now (&monitor, NULL);
}


/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'m', "monitor", NULL,
    gettext_noop ("provide inthe 'struct GNUNET_TRANSPORT_PeerIterateContextformation about all tunnels (continuously)"),
     0, &GNUNET_GETOPT_set_one, &monitor_connections},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;


  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-mesh",
                      gettext_noop
                      ("Print information about mesh tunnels and peers."),
                      options, &run, NULL);

  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return 0;
  else
    return 1;
}

/* end of gnunet-mesh.c */

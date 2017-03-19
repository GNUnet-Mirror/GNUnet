/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/gnunet-rps.c
 * @brief random peer sampling
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_rps_service.h"
#include <inttypes.h>

static int ret;

/**
 * RPS handle
 */
static struct GNUNET_RPS_Handle *rps_handle;

/**
 * Request handle
 */
static struct GNUNET_RPS_Request_Handle *req_handle;

/**
 * PeerID (Option --seed)
 */
static struct GNUNET_PeerIdentity peer_id;


/**
 * Task run when user presses CTRL-C to abort.
 * Cancels pending request and disconnects.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  if (NULL != req_handle)
    GNUNET_RPS_request_cancel (req_handle);
  GNUNET_RPS_disconnect (rps_handle);
}


/**
 * Callback called on receipt of reply.
 * Prints replied PeerIDs.
 *
 * @param cls closure
 * @param n number of peers
 * @param recv_peers the received peers
 */
static void
reply_handle (void *cls,
              uint64_t n,
              const struct GNUNET_PeerIdentity *recv_peers)
{
  uint64_t i;

  req_handle = NULL;
  for (i = 0; i < n; i++)
  {
    FPRINTF (stdout, "%s\n",
        GNUNET_i2s_full (&recv_peers[i]));
  }
  ret = 0;

  GNUNET_SCHEDULER_shutdown ();
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static uint64_t num_peers;
  static struct GNUNET_PeerIdentity zero_pid;

  rps_handle = GNUNET_RPS_connect (cfg);

  if (0 == memcmp (&zero_pid,
                   &peer_id,
                   sizeof (peer_id)))
  { /* Request n PeerIDs */
    /* If number was specified use it, else request single peer. */
    num_peers = (NULL == args[0]) ? 1 : atoi (args[0]);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Requesting %" PRIu64 " PeerIDs\n", num_peers);
    req_handle = GNUNET_RPS_request_peers (rps_handle, num_peers, reply_handle, NULL);
    GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  }
  else
  { /* Seed PeerID */
    GNUNET_RPS_seed_ids (rps_handle, 1, &peer_id);
    FPRINTF (stdout, "Seeded PeerID %s\n", GNUNET_i2s_full (&peer_id));
    ret = 0;
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
}

/**
 * The main function to rps.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  const char helpstr[] =
    "Get random GNUnet peers. If none is specified a single is requested.";
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_SET_BASE32_AUTO ('s',
                                          "seed",
                                          "PEER_ID",
                                          gettext_noop ("Seed a PeerID"),
                                          &peer_id),
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-rps [NUMBER_OF_PEERS]",
                              gettext_noop
                              (helpstr),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-rps.c */

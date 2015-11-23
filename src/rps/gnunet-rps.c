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
static struct GNUNET_PeerIdentity *peer_id;


/**
 * Shutdown task
 */
static struct GNUNET_SCHEDULER_Task *shutdown_task;


/**
 * Set an option of type 'struct GNUNET_PeerIdentity *' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'struct GNUNET_PeerIdentity *', which will be allocated with the requested string.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'char *',
 *             which will be allocated)
 * @param option name of the option
 * @param value actual value of the option (a PeerID)
 * @return #GNUNET_OK
 */
static int
GNUNET_GETOPT_set_peerid (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                          void *scls, const char *option, const char *value)
{
  struct GNUNET_PeerIdentity **val = (struct GNUNET_PeerIdentity **) scls;

  GNUNET_assert (NULL != value);
  GNUNET_free_non_null (*val);
  /* Not quite sure whether that is a sane way */
  *val = GNUNET_new (struct GNUNET_PeerIdentity);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (value,
                                                  strlen (value),
                                                  &((*val)->public_key)))
  {
    FPRINTF (stderr, "Invalid peer ID %s\n", value);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Task run when user presses CTRL-C to abort.
 * Cancels pending request and disconnects.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = NULL;
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

  GNUNET_SCHEDULER_cancel (shutdown_task);
  GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
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

  rps_handle = GNUNET_RPS_connect (cfg);

  if (NULL == peer_id)
  { /* Request n PeerIDs */
    /* If number was specified use it, else request single peer. */
    num_peers = (NULL == args[0]) ? 1 : atoi (args[0]);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Requesting %u PeerIDs\n", num_peers);
    req_handle = GNUNET_RPS_request_peers (rps_handle, num_peers, reply_handle, NULL);
    shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
        &do_shutdown, NULL);
  }
  else
  { /* Seed PeerID */
    GNUNET_RPS_seed_ids (rps_handle, 1, peer_id);
    FPRINTF (stdout, "Seeded PeerID %s\n", GNUNET_i2s_full (peer_id));
    ret = 0;
    GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
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
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'s', "seed", "PEER_ID",
      gettext_noop ("Seed a PeerID"),
      GNUNET_YES, &GNUNET_GETOPT_set_peerid, &peer_id},
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

/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file dv/gnunet-dv.c
 * @brief DV monitoring command line tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dv_service.h"

/**
 * Handle to DV service.
 */
static struct GNUNET_DV_ServiceHandle *sh;

/**
 * Was verbose specified?
 */
static int verbose;


/**
 * Function called if DV starts to be able to talk to a peer.
 *
 * @param cls closure
 * @param peer newly connected peer
 * @param distance distance to the peer
 * @param network the network the next hop is located in
 */
static void
connect_cb (void *cls,
	    const struct GNUNET_PeerIdentity *peer,
	    uint32_t distance,
            enum GNUNET_ATS_Network_Type network)
{
  fprintf (stderr, "Connect: %s at %u\n",
	   GNUNET_i2s (peer),
	   (unsigned int) distance);
}


/**
 * Function called if DV distance to a peer is changed.
 *
 * @param cls closure
 * @param peer connected peer
 * @param distance new distance to the peer
 * @param network network used on first hop to peer
 */
static void
change_cb (void *cls,
	   const struct GNUNET_PeerIdentity *peer,
	   uint32_t distance,
           enum GNUNET_ATS_Network_Type network)
{
  fprintf (stderr, "Change: %s at %u\n",
	   GNUNET_i2s (peer),
	   (unsigned int) distance);
}


/**
 * Function called if DV is no longer able to talk to a peer.
 *
 * @param cls closure
 * @param peer peer that disconnected
 */
static void
disconnect_cb (void *cls,
	       const struct GNUNET_PeerIdentity *peer)
{
  fprintf (stderr, "Disconnect: %s\n",
	   GNUNET_i2s (peer));
}


/**
 * Function called if DV receives a message for this peer.
 *
 * @param cls closure
 * @param sender sender of the message
 * @param distance how far did the message travel
 * @param msg actual message payload
 */
static void
message_cb (void *cls,
	    const struct GNUNET_PeerIdentity *sender,
	    uint32_t distance,
	    const struct GNUNET_MessageHeader *msg)
{
  if (verbose)
    fprintf (stderr, "Message: %s at %u sends %u bytes of type %u\n",
	     GNUNET_i2s (sender),
	     (unsigned int) distance,
	     (unsigned int) ntohs (msg->size),
	     (unsigned int) ntohs (msg->type));
}


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DV_service_disconnect (sh);
  sh = NULL;
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
  sh = GNUNET_DV_service_connect (cfg, NULL,
				  &connect_cb,
				  &change_cb,
				  &disconnect_cb,
				  &message_cb);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
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
  int res;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'V', "verbose", NULL,
     gettext_noop ("verbose output"),
     0, &GNUNET_GETOPT_set_one, &verbose},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-dv",
			    gettext_noop ("Print information about DV state"),
			    options, &run,
			    NULL);
  GNUNET_free ((void *) argv);

  if (GNUNET_OK != res)
    return 1;
  return 0;
}

/* end of gnunet-dv.c */

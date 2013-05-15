/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file set/gnunet-set.c
 * @brief profiling tool for the set service
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_stream_lib.h"


static struct GNUNET_PeerIdentity local_id;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_STREAM_ListenSocket *listen_socket;

static struct GNUNET_STREAM_Socket *s1;

static struct GNUNET_STREAM_Socket *s2;

static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != s2)
    GNUNET_STREAM_close (s2);
  GNUNET_STREAM_close (s1);
  GNUNET_STREAM_listen_close (listen_socket);
  GNUNET_CONFIGURATION_destroy (cfg);
}

static size_t
stream_data_processor (void *cls,
                       enum GNUNET_STREAM_Status status,
                       const void *data,
                       size_t size)
{
  return size;
}

static int
listen_cb (void *cls,
           struct GNUNET_STREAM_Socket *socket,
           const struct 
           GNUNET_PeerIdentity *initiator)
{
  if (NULL == (s2 = socket))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "socket listen failed\n");
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "socket listen succesful\n");
  GNUNET_assert (NULL != socket);
  GNUNET_assert (0 == memcmp (initiator, &local_id, sizeof (*initiator)));
  GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL, 
                      &stream_data_processor, NULL);
  return GNUNET_YES;
}

static void
open_cb (void *cls, struct GNUNET_STREAM_Socket *socket)
{
 
}

static void
stream_connect (void)
{
   s1 = GNUNET_STREAM_open (cfg,
                           &local_id,
                           GNUNET_APPLICATION_TYPE_SET,
                           &open_cb,
                           NULL,
                            GNUNET_STREAM_OPTION_END);
}

/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg2)
{

  cfg = GNUNET_CONFIGURATION_dup (cfg2);
  GNUNET_CRYPTO_get_host_identity (cfg, &local_id);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "I am Peer %s\n", GNUNET_h2s (&local_id.hashPubKey));

  listen_socket = GNUNET_STREAM_listen (cfg,
                                        GNUNET_APPLICATION_TYPE_SET,
                                        &listen_cb,
                                        NULL,
                                        GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
                                        &stream_connect,
                                        GNUNET_STREAM_OPTION_END);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);
}



int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run (argc, argv, "gnunet-set",
		      "help",
		      options, &run, NULL);
  return 0;
}


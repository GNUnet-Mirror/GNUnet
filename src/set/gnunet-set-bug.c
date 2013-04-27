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

static struct GNUNET_STREAM_ListenSocket *listen_socket;

static struct GNUNET_STREAM_Socket *s1;



static size_t
stream_data_processor (void *cls,
                       enum GNUNET_STREAM_Status status,
                       const void *data,
                       size_t size)
{
  return size;
}

static int listen_cb (void *cls,
                      struct GNUNET_STREAM_Socket *socket,
                      const struct 
                      GNUNET_PeerIdentity *initiator)
{
  GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL, 
                      stream_data_processor, NULL);
  return GNUNET_YES;
}

static void
open_cb (void *cls, struct GNUNET_STREAM_Socket *socket)
{
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
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  GNUNET_CRYPTO_get_host_identity (cfg, &local_id);

  listen_socket = GNUNET_STREAM_listen (cfg,
                                        GNUNET_APPLICATION_TYPE_SET,
                                        listen_cb,
                                        NULL,
                                        NULL);

  s1 = GNUNET_STREAM_open (cfg,
                           &local_id,
                           GNUNET_APPLICATION_TYPE_SET,
                           open_cb,
                           NULL,
                           NULL);
}



int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-set",
		      "help",
		      options, &run, NULL, GNUNET_NO);
  return 0;
}


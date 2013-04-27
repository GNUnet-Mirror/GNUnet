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
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_set_service.h"


static struct GNUNET_PeerIdentity local_id;

static struct GNUNET_HashCode app_id;
static struct GNUNET_SET_Handle *set1;
static struct GNUNET_SET_Handle *set2;
static struct GNUNET_SET_ListenHandle *listen_handle;


static void
listen_cb (void *cls,
           const struct GNUNET_PeerIdentity *other_peer,
           const struct GNUNET_MessageHeader *context_msg,
           struct GNUNET_SET_Request *request)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "listen cb called\n");
}

static void
result_cb (void *cls, struct GNUNET_SET_Element *element,
           enum GNUNET_SET_Status status)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got result\n");
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
  static const char* app_str = "gnunet-set";
  
  GNUNET_CRYPTO_hash (app_str, strlen (app_str), &app_id);

  GNUNET_CRYPTO_get_host_identity (cfg, &local_id);

  set1 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  set2 = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  listen_handle = GNUNET_SET_listen (cfg, GNUNET_SET_OPERATION_UNION,
                                     &app_id, listen_cb, NULL);

  GNUNET_SET_evaluate (set1, &local_id, &app_id, NULL, 42,
                       GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_SET_RESULT_ADDED,
                       result_cb, NULL);
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


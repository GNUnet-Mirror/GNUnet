/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core.c
 * @brief high-level P2P messaging
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_clients.h"
#include "gnunet-service-core_kx.h"
#include "gnunet-service-core_neighbours.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet-service-core_typemap.h"


/**
 * Our identity.
 */
struct GNUNET_PeerIdentity GSC_my_identity;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *GSC_cfg;

/**
 * For creating statistics.
 */
struct GNUNET_STATISTICS_Handle *GSC_stats;

/**
 * Handle to the server of the core service.
 */
static struct GNUNET_SERVER_Handle *GSC_server;

/**
 * Hostkey generation context
 */
static struct GNUNET_CRYPTO_EccKeyGenerationContext *keygen;


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport.
 * 
 * @param cls NULL, unused
 * @param tc scheduler context, unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core service shutting down.\n");
  if (NULL != keygen)
  {
    GNUNET_CRYPTO_ecc_key_create_stop (keygen);
    keygen = NULL;
  }
  GSC_CLIENTS_done ();
  GSC_NEIGHBOURS_done ();
  GSC_SESSIONS_done ();
  GSC_KX_done ();
  GSC_TYPEMAP_done ();
  if (NULL != GSC_stats)
  {
    GNUNET_STATISTICS_destroy (GSC_stats, GNUNET_NO);
    GSC_stats = NULL;
  }
  GSC_cfg = NULL;
}



/**
 * Callback for hostkey read/generation
 *
 * @param cls NULL
 * @param pk the private key
 * @param emsg error message
 */
static void
key_generation_cb (void *cls,
                   struct GNUNET_CRYPTO_EccPrivateKey *pk,
                   const char *emsg)
{
  keygen = NULL;
  if (NULL == pk)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to read or generate private key: %s\n"),
		emsg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_OK != GSC_KX_init (pk)) || 
      (GNUNET_OK != GSC_NEIGHBOURS_init ()))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GSC_SESSIONS_init ();
  GSC_CLIENTS_init (GSC_server);
  GNUNET_SERVER_resume (GSC_server);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Core service of `%4s' ready.\n"),
              GNUNET_i2s (&GSC_my_identity));
}


/**
 * Initiate core service.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *keyfile;

  GSC_cfg = c;
  GSC_server = server;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (GSC_cfg, "PEER", "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Core service is lacking HOSTKEY configuration setting.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GSC_stats = GNUNET_STATISTICS_create ("core", GSC_cfg);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  GNUNET_SERVER_suspend (server);
  GSC_TYPEMAP_init ();
  keygen = GNUNET_CRYPTO_ecc_key_create_start (keyfile, &key_generation_cb, NULL);
  GNUNET_free (keyfile);
  if (NULL == keygen)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Transport service is unable to access hostkey. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * The main function for the transport service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "core", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-core.c */

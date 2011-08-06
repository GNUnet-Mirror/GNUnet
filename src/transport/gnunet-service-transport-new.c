/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport-new.c
 * @brief 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"

/* globals */

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Configuration handle.
 */
struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Handle to peerinfo service.
 */
struct GNUNET_PEERINFO_Handle *GST_peerinfo;

/**
 * Our public key.
 */
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded GST_my_public_key;

/**
 * Our private key.
 */
struct GNUNET_CRYPTO_RsaPrivateKey *GST_my_private_key;


/**
 * My HELLO has changed. Tell everyone who should know.
 *
 * @param cls unused
 * @param hello new HELLO
 */
static void
process_hello_update (void *cls,
		      const struct GNUNET_MessageHeader *hello)
{
  GST_clients_broadcast (hello, GNUNET_NO);
#if 0
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					 &transmit_our_hello_if_pong,
					 NULL);
#endif
}


/**
 * Function that will be called for each address the transport
 * is aware that it might be reachable under.  Update our HELLO.
 *
 * @param cls name of the plugin (const char*)
 * @param add_remove should the address added (YES) or removed (NO) from the
 *                   set of valid addresses?
 * @param addr one of the addresses of the host
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 */
static void 
plugin_env_address_change_notification (void *cls,
					int add_remove,
					const void *addr,
					size_t addrlen)
{
  const char *plugin_name = cls;

  GST_hello_modify_addresses (add_remove,
			      plugin_name,
			      addr,
			      addrlen);
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
shutdown_task (void *cls, 
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  GST_blacklist_stop ();
  GST_plugins_unload ();
  GST_hello_stop ();

  if (GST_peerinfo != NULL)
    {
      GNUNET_PEERINFO_disconnect (GST_peerinfo);
      GST_peerinfo = NULL;
    }
  if (GST_stats != NULL)
    {
      GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
      GST_stats = NULL;
    }  
  if (GST_my_private_key != NULL)
    {
      GNUNET_CRYPTO_rsa_key_free (GST_my_private_key);
      GST_my_private_key = NULL;
    }
}


/**
 * Initiate transport service.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
#if 0
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {NULL, NULL, 0, 0}
  };
#endif
  char *keyfile;

  /* setup globals */
  GST_cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c,
					       "GNUNETD",
					       "HOSTKEY", &keyfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Transport service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  GST_my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (GST_my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Transport service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  GST_stats = GNUNET_STATISTICS_create ("transport", c);
  GST_peerinfo = GNUNET_PEERINFO_connect (c);
  GNUNET_CRYPTO_rsa_key_get_public (GST_my_private_key, &GST_my_public_key);
  GNUNET_CRYPTO_hash (&GST_my_public_key,
                      sizeof (GST_my_public_key), &GST_my_identity.hashPubKey);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
  if (GST_peerinfo == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not access PEERINFO service.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  
  /* start subsystems */
  GST_hello_start (&process_hello_update, NULL);
  GST_blacklist_start (server);
  GST_plugins_load (NULL,  // FIXME...
		    &plugin_env_address_change_notification, 
		    NULL, // FIXME...
		    NULL, // FIXME...
		    NULL); // FIXME...
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
          GNUNET_SERVICE_run (argc,
                              argv,
                              "transport",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of file gnunet-service-transport-new.c */

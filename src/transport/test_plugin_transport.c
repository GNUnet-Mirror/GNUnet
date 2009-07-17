/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_api.c
 * @brief testcase for transport_api.c
 * @author Sailor Siraj
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_plugin_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "plugin_transport.h"
#include "transport.h"

/**
 * Our public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *my_public_key;

/**
 * Our identity.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * Our scheduler.
 */
struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
struct GNUNET_CONFIGURATION_Handle *cfg;



/**
 * All loaded plugins.
 */
static struct TransportPlugin *plugins;

/**
 * Our server.
 */
static struct GNUNET_SERVER_Handle *server;



/**
 * Number of neighbours we'd like to have.
 */
static uint32_t max_connect_per_transport;

/**
 * Environment for this plugin.
 */
struct GNUNET_TRANSPORT_PluginEnvironment env;

/**
 *handle for the api provided by this plugin
 */
struct GNUNET_TRANSPORT_PluginFunctions *api;

/**
 * Initialize Environment for this plugin
 */
struct ReadyList * 
receive(void *cls,void *plugin_context,
	struct ReadyList *
	service_context,
	struct GNUNET_TIME_Relative
	latency,
	const struct GNUNET_PeerIdentity
	* peer,
	const struct GNUNET_MessageHeader
	* message)
{
  return NULL;
}

void notify_address(void *cls,
		    const char *name,
		    const void *addr,
		    size_t addrlen,
		    struct
		    GNUNET_TIME_Relative
		    expires)
{
}

void lookup (void *cls,
	     struct GNUNET_TIME_Relative
	     timeout,
	     const struct
	     GNUNET_PeerIdentity * target,
	     GNUNET_TRANSPORT_AddressCallback
	     iter, void *iter_cls)
{	
}


static void setup_plugin_environment()
{
  env.cfg  = cfg;
  env.sched = sched;
  env.my_public_key = my_public_key;
  env.cls=&env;
  env.receive=&receive;
  env.lookup=&lookup;
  env.notify_address=&notify_address;
  env.max_connections = max_connect_per_transport;       
}	


/**
 * Initiate transport service.
 *
 * @param cls closure
 * @param s scheduler to use
 * @param serv the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     struct GNUNET_SERVER_Handle *serv, struct GNUNET_CONFIGURATION_Handle *c)
{ 
  unsigned long long tneigh;
  char *keyfile;
  char *libname;

  sched = s;
  cfg = c;
  server = serv;
  /* parse configuration */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (c,
                                              "TRANSPORT",
                                              "NEIGHBOUR_LIMIT",
                                              &tneigh)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (c,
                                                "GNUNETD",
                                                "HOSTKEY", &keyfile)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Transport service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  max_connect_per_transport = (uint32_t) tneigh;
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Transport service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);
  

  
  /* load plugins... */  
  setup_plugin_environment();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading tcp transport plugin\n"));
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_tcp");

  api = GNUNET_PLUGIN_load(libname, &env);
  if (api == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load transport plugin for tcp\n"));
    } 
  
}


/**
 * Function called when the service shuts
 * down.  Unloads our plugins.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
static void
unload_plugins (void *cls, struct GNUNET_CONFIGURATION_Handle *cfg)
{  
  GNUNET_assert (NULL == GNUNET_PLUGIN_unload ("libgnunet_plugin_transport_tcp",api));
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
  
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
  GNUNET_log_setup ("test-puglin-transport",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);       
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "transport",
                              &run, NULL, &unload_plugins, NULL)) ? 0 : 1;
}

/* end of test_plugin_transport.c */

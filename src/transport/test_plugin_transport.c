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
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_plugin_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_program_lib.h"
#include "gnunet_signatures.h"
#include "plugin_transport.h"
#include "transport.h"

#define VERBOSE GNUNET_NO

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Our public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

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
const struct GNUNET_CONFIGURATION_Handle *cfg;

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
 * Did the test pass or fail?
 */
static int ok;

/**
 * Initialize Environment for this plugin
 */
struct ReadyList * 
receive(void *cls,
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

/**
 * Function called when the service shuts
 * down.  Unloads our plugins.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
static void
unload_plugins (void *cls, 
		const struct GNUNET_CONFIGURATION_Handle *cfg)
{  
  GNUNET_assert (NULL == GNUNET_PLUGIN_unload ("libgnunet_plugin_transport_tcp",api));
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
  
}


static void
unload_task (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  unload_plugins (NULL, cfg);
}


static GNUNET_SCHEDULER_TaskIdentifier validation_timeout_task;


static void 
validation_notification (void *cls,
			 const char *name,
			 const struct GNUNET_PeerIdentity *peer,
			 uint32_t challenge,
			 const char *sender_addr)
{
  if (validation_timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, validation_timeout_task);
      validation_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }

  GNUNET_assert (challenge == 42);
  
  ok = 0; /* if the last test succeeded, report success */
  GNUNET_SCHEDULER_add_continuation (sched,
				     &unload_task,
				     (void*) cfg,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


static void
validation_failed (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  validation_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_break (0); /* output error */
  /* the "validation_notification" was not called
     in a timely fashion; we should set an error
     code for main and shut down */  
  unload_plugins (NULL, cfg);
}


/**
 * Simple example test that invokes
 * the "validate" function of the plugin
 * and tries to see if the plugin would
 * succeed to validate its own address.
 * (This test is not well-written since
 *  we hand-compile the address which
 *  kind-of works for TCP but would not
 *  work for other plugins; we should ask
 *  the plugin about its address instead...).
 */
/* FIXME: won't work on IPv6 enabled systems where IPv4 mapping
 * isn't enabled (eg. FreeBSD > 4)
 */
static void
test_validation ()
{
  struct sockaddr_in soaddr;
  
  memset (&soaddr, 0, sizeof(soaddr));
#if HAVE_SOCKADDR_IN_SIN_LEN
  soaddr.sin_len = sizeof (soaddr);
#endif
  soaddr.sin_family = AF_INET;
  soaddr.sin_port = htons(2368 /* FIXME: get from config! */);
  soaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  api->validate (api->cls,
		 &my_identity,
		 42,
		 TIMEOUT,
		 &soaddr,
		 sizeof(soaddr));		 
  /* add job to catch failure (timeout) */
  validation_timeout_task =
    GNUNET_SCHEDULER_add_delayed (sched,
				  TIMEOUT,
				  &validation_failed,
				  NULL);
}


static void setup_plugin_environment()
{
  env.cfg  = cfg;
  env.sched = sched;
  env.my_public_key = &my_public_key;
  env.my_private_key = my_private_key;
  env.my_identity = &my_identity;
  env.cls=&env;
  env.receive=&receive;
  env.notify_address=&notify_address;
  env.notify_validation = &validation_notification;
  env.max_connections = max_connect_per_transport;       
}	


/**
 * Runs the test.
 *
 * @param cls closure
 * @param s scheduler to use
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{ 
  unsigned long long tneigh;
  char *keyfile;
  char *libname;

  sched = s;
  cfg = c;
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
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, 
				    &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key),
		      &my_identity.hashPubKey);
  

  
  /* load plugins... */  
  setup_plugin_environment();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading tcp transport plugin\n"));
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_tcp");

  api = GNUNET_PLUGIN_load(libname, &env);
  GNUNET_free (libname);
  if (api == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load transport plugin for tcp\n"));
      /* FIXME: set some error code for main */
      return;
    } 
  test_validation ();
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
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;
  char *const argv_prog[] = {
    "test_plugin_transport",
    "-c",
    "test_plugin_transport_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };  
  GNUNET_log_setup ("test-plugin-transport",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);       
  ok = 1; /* set to fail */
  ret = (GNUNET_OK ==
          GNUNET_PROGRAM_run (5,
                              argv_prog,
                              "test-plugin-transport",
			      "testcase",
			      options,
                              &run, NULL)) ? ok : 1;
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-plugin-transport");
  return ret;
}

/* end of test_plugin_transport.c */

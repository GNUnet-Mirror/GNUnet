/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_plugin_transport_http.c
 * @brief testcase for plugin_transport_http.c
 * @author Matthias Wachs
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
#include "gnunet_service_lib.h"
#include "plugin_transport.h"
#include "gnunet_statistics_service.h"
#include "transport.h"
#include <curl/curl.h>

#define VERBOSE GNUNET_YES
#define DEBUG GNUNET_YES

#define PLUGIN libgnunet_plugin_transport_template

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)

/**
 * How long until we give up on transmitting the message?
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

/**
 * How long between recieve and send?
 */
#define WAIT_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Our public key.
 */
/* static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key; */

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
 * Our statistics handle.
 */
struct GNUNET_STATISTICS_Handle *stats;


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
static struct GNUNET_TRANSPORT_PluginEnvironment env;

/**
 *handle for the api provided by this plugin
 */
static struct GNUNET_TRANSPORT_PluginFunctions *api;

/**
 * ID of the task controlling the testcase timeout
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_timeout;


static GNUNET_SCHEDULER_TaskIdentifier ti_send;

const struct GNUNET_PeerIdentity * p;

/**
 * Did the test pass or fail?
 */
static int fail;

/**
 * Recieved message already returned to sender?
 */
static int sent;

/**
 * Shutdown testcase
 */
static void
shutdown_clean ()
{
  if (ti_send != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(sched,ti_send);
    ti_send = GNUNET_SCHEDULER_NO_TASK;
  }

  if (ti_timeout != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(sched,ti_timeout);
    ti_timeout = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Unloading http plugin\n");
  GNUNET_assert (NULL == GNUNET_PLUGIN_unload ("libgnunet_plugin_transport_http", api));

  GNUNET_SCHEDULER_shutdown(sched);
  /* FIXME: */ fail = GNUNET_NO;
  return;
}

/**
 * Continuation called after plugin send message
 * @cls closure
 * @target target
 * @result GNUNET_OK or GNUNET_SYSERR
 */
static void task_send_cont (void *cls,
                            const struct GNUNET_PeerIdentity * target,
                            int result)
{
  fail = GNUNET_NO;
  shutdown_clean();
}

/**
 * Task sending recieved message back to peer
 * @cls closure
 * @tc task context
 */
static void
task_send (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_timeout = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  if (GNUNET_YES==sent)
    return;

  struct GNUNET_MessageHeader * msg = cls;
  unsigned int len = ntohs(msg->size);
  const char * msgc = (const char *) msg;

  api->send(api->cls,p,msgc, len, 0, TIMEOUT, NULL,NULL, 0, GNUNET_NO, &task_send_cont, NULL);
  sent = GNUNET_YES;

}

/**
 * Recieves messages from plugin, in real world transport
 */
static struct GNUNET_TIME_Relative
receive (void *cls,
         const struct GNUNET_PeerIdentity * peer,
         const struct GNUNET_MessageHeader * message,
         uint32_t distance,
         struct Session *session,
         const char *sender_address,
         uint16_t sender_address_len)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testcase recieved new message from peer `%s' with type %u and length %u\n",  GNUNET_i2s(peer),ntohs(message->type),ntohs(message->size));

  /* take recieved message and send it back to peer */
  p = peer;
  void * c = (void *) message;
  ti_send =GNUNET_SCHEDULER_add_delayed (sched, WAIT_INTERVALL, &task_send, c);

  return GNUNET_TIME_UNIT_ZERO;
}

void
notify_address (void *cls,
                const char *name,
                const void *addr,
                uint16_t addrlen,
                struct GNUNET_TIME_Relative expires)
{

}

/**
 * Setup plugin environment
 */
static void
setup_plugin_environment ()
{
  env.cfg = cfg;
  env.sched = sched;
  env.stats = stats;
  env.my_identity = &my_identity;
  env.cls = &env;
  env.receive = &receive;
  env.notify_address = &notify_address;
  env.max_connections = max_connect_per_transport;
}


/**
 * Task shutting down testcase if it a timeout occurs
 */
static void
task_timeout (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ti_timeout = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testcase timeout\n");
  fail = GNUNET_YES;
  shutdown_clean();
  return;
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
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *c)
{
  char * libname;
  sched = s;
  cfg = c;
  char *keyfile;
  unsigned long long tneigh;

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
                  _
                  ("Transport service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  max_connect_per_transport = (uint32_t) tneigh;
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Transport service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown (s);
      return;
    }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key,
                      sizeof (my_public_key), &my_identity.hashPubKey);

  /* load plugins... */
  setup_plugin_environment ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading HTTP transport plugin `%s'\n"),"libgnunet_plugin_transport_http");
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_http");
  api = GNUNET_PLUGIN_load (libname, &env);
  GNUNET_free (libname);
  if (api == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load transport plugin for http\n"));
    fail = GNUNET_YES;
    return;
  }

  ti_timeout = GNUNET_SCHEDULER_add_delayed (sched, TEST_TIMEOUT, &task_timeout, NULL);
  return;
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
    "test_plugin_transport_http",
    "-c",
    "test_plugin_transport_data_http.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  GNUNET_log_setup ("test_plugin_transport_http",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (5,
                             argv_prog,
                             "test_plugin_transport_http",
                             "testcase", options, &run, NULL)) ? GNUNET_NO : GNUNET_YES;

    GNUNET_DISK_directory_remove ("/tmp/test_plugin_transport_http");

  return fail;
}

/* end of test_plugin_transport_http.c */

/*
 This file is part of GNUnet.
 Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_plugin_transport.c
 * @brief testcase for transport_api.c
 * @author Sailor Siraj
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

/**
 * How long until we give up on transmitting the message?
 */
#define WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define HOSTKEY_FILE "test_plugin_hostkey.ecc"

/**
 * Our public key.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our configuration.
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our HELLO
 */
struct GNUNET_HELLO_Message *hello;

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
 * Helper handler
 */
struct GNUNET_HELPER_Handle *suid_helper;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task * timeout_endbadly;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task * timeout_wait;

/**
 * Library name
 */
static char *libname;

/**
 * Plugin addresses head
 */
struct AddressWrapper *head;

/**
 * Plugin addresses tail
 */
struct AddressWrapper *tail;

unsigned int addresses_reported;

unsigned int pretty_printers_running;

/**
 * Did the test pass or fail?
 */
static int ok;

struct AddressWrapper
{
  struct AddressWrapper *next;

  struct AddressWrapper *prev;

  struct GNUNET_HELLO_Address *address;

  char *addrstring;

  struct GNUNET_SCHEDULER_Task *test_task;

};


static void
end ()
{
  struct AddressWrapper *w;
  int c = 0;
  ok = 0;

  if (NULL != timeout_endbadly)
  {
    GNUNET_SCHEDULER_cancel (timeout_endbadly);
    timeout_endbadly = NULL;
  }
  if (NULL != api)
    GNUNET_PLUGIN_unload (libname, api);

  while (NULL != head)
  {
    w = head;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Plugin did not remove address `%s'\n",
                w->addrstring);
    GNUNET_CONTAINER_DLL_remove(head, tail, w);
    c++;
    GNUNET_HELLO_address_free(w->address);
    GNUNET_free(w->addrstring);
    GNUNET_free(w);
  }
  if (c > 0)
  {
    GNUNET_break(0);
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Plugin did not remove %u addresses \n",
        c);
    ok = 1;
  }

  GNUNET_free(libname);
  libname = NULL;
  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;

  if (NULL != suid_helper)
  {
    GNUNET_HELPER_stop (suid_helper, GNUNET_NO);
    suid_helper = NULL;
  }
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct AddressWrapper *w;
  int c = 0;

  timeout_endbadly = NULL;
  if (NULL != timeout_wait)
  {
    GNUNET_SCHEDULER_cancel (timeout_wait);
    timeout_wait = NULL;
  }

  if (pretty_printers_running > 0)
  {
    timeout_endbadly = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
        &end_badly, &ok);
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Have pending calls to pretty_printer ... deferring shutdown\n");
    return;
  }

  if (NULL != cls)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Test took too long to execute, timeout .... \n");
  }

  if (NULL != libname)
  {
    if (NULL != api)
      GNUNET_PLUGIN_unload (libname, api);
    GNUNET_free(libname);
    libname = NULL;
  }

  while (NULL != head)
  {
    w = head;
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Plugin did not remove address `%s'\n",
        w->addrstring);
    GNUNET_CONTAINER_DLL_remove(head, tail, w);
    c++;
    GNUNET_HELLO_address_free(w->address);
    if (NULL != w->test_task)
      GNUNET_SCHEDULER_cancel (w->test_task);
    GNUNET_free(w->addrstring);
    GNUNET_free(w);
  }
  if (c > 0)
  {
    GNUNET_break(0);
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Plugin did not remove %u addresses\n",
        c);
  }

  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }

  if (NULL != suid_helper)
  {
    GNUNET_HELPER_stop (suid_helper, GNUNET_NO);
    suid_helper = NULL;
  }

  ok = 1;
}

static void
wait_end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  timeout_wait = NULL;
  if (0 == addresses_reported)
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
        "Plugin did not report any addresses, could not check address conversion functions\n");
  end ();
}


static void
end_badly_now ()
{
  if (NULL != timeout_wait)
  {
    GNUNET_SCHEDULER_cancel (timeout_wait);
    timeout_wait = NULL;
  }
  if (NULL != timeout_endbadly)
  {
    GNUNET_SCHEDULER_cancel (timeout_endbadly);
    timeout_endbadly = NULL;
  }
  timeout_endbadly = GNUNET_SCHEDULER_add_now (&end_badly, NULL );
}


static struct GNUNET_TIME_Relative
env_receive (void *cls,
             const struct GNUNET_HELLO_Address *address,
             struct Session *session,
             const struct GNUNET_MessageHeader *message)
{
  /* do nothing */
  return GNUNET_TIME_relative_get_zero_ ();
}

static int got_reply;


/**
 * Take the given address and append it to the set of results sent back to
 * the client.
 *
 * @param cls closure
 * @param address the address to print
 * @param res result code
 */
static void
address_pretty_printer_cb (void *cls, const char *address, int res)
{
  if (NULL != address)
  {
    got_reply = GNUNET_YES;
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Pretty address : `%s'\n", address);
    pretty_printers_running--;
  }
  else
  {
    if (GNUNET_NO == got_reply)
    {
      pretty_printers_running--;
      GNUNET_break(0);
      end_badly_now ();
    }
  }
}


static void
test_addr_string (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct AddressWrapper *w = cls;
  void *s2a;
  size_t s2a_len;

  w->test_task = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Testing: address_to_string \n");
  w->addrstring = GNUNET_strdup (api->address_to_string (api,
                                                         w->address->address,
                                                         w->address->address_length));
  if (NULL == w->addrstring)
  {
    GNUNET_break(0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Plugin cannot convert address to string!\n");
    end_badly_now ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Plugin added address `%s'\n",
              w->addrstring);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Testing address_to_string: OK\n");
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Testing: string_to_address \n");
  s2a = NULL;
  s2a_len = 0;
  if ((GNUNET_OK !=
       api->string_to_address (api, w->addrstring,
                               strlen (w->addrstring) + 1,
                               &s2a, &s2a_len)) ||
      (NULL == s2a))
  {
    GNUNET_break(0);
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Plugin cannot convert string to address!\n");
    end_badly_now ();
    return;
  }

  /*
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
    "Plugin creates `%s' %u\n",api->address_to_string (api, s2a, s2a_len), s2a_len);

    int c1;
    for (c1 = 0; c1 < s2a_len; c1++ )
    fprintf (stderr, "%u == %u\n", ((char *) s2a)[c1], ((char *) w->addr)[c1]);
  */
  if (s2a_len != w->address->address_length)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Plugin creates different address length when converting address->string->address: %u != %u\n",
               w->address->address_length, s2a_len);
  }
  else if (0 != memcmp (s2a, w->address->address, s2a_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Plugin creates different address length when converting back and forth %i!\n",
                memcmp (s2a,
                        w->address->address,
                        s2a_len));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Testing string_to_address: OK\n");
  }
  GNUNET_free(s2a);

  pretty_printers_running++;
  api->address_pretty_printer (api->cls,
                               w->address->transport_name,
                               w->address->address,
                               w->address->address_length,
                               GNUNET_YES,
                               GNUNET_TIME_UNIT_MINUTES,
                               &address_pretty_printer_cb, w);

  if (GNUNET_OK !=
      api->check_address (api->cls,
                          w->address->address,
                          w->address->address_length))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Plugin refuses added address!\n");
    end_badly_now ();
    return;
  }
  if (NULL != timeout_wait)
  {
    GNUNET_SCHEDULER_cancel (timeout_wait);
    timeout_wait = NULL;
  }
  timeout_wait = GNUNET_SCHEDULER_add_delayed (WAIT, &wait_end, NULL);
}


static void
env_notify_address (void *cls,
                    int add_remove,
                    const struct GNUNET_HELLO_Address *address)
{
  struct AddressWrapper *w;
  struct AddressWrapper *wtmp;

  if (GNUNET_YES == add_remove)
  {
    addresses_reported++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
               "Adding address of length %u\n",
                address->address_length);

    for (wtmp = head; NULL != wtmp; wtmp = wtmp->next)
    {
      if ((address->address_length == wtmp->address->address_length) &&
          (0 == memcmp (address->address, wtmp->address->address, address->address_length)))
      {
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                   "Duplicate address notification .... \n");
        return;
      }
    }

    w = GNUNET_new (struct AddressWrapper);
    w->address = GNUNET_HELLO_address_copy (address);
    GNUNET_CONTAINER_DLL_insert (head, tail, w);
    got_reply = GNUNET_NO;
    w->test_task = GNUNET_SCHEDULER_add_now (&test_addr_string,
                                             w);
    return;
  }

  if (GNUNET_NO == add_remove)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Removing address of length %u\n",
                address->address_length);
    w = head;
    while (NULL != w)
    {
      if ((address->address_length == w->address->address_length) &&
          (0 == memcmp (w->address->address, address->address, address->address_length)))
      {
        break;
      }
      w = w->next;
    }

    if (w == NULL)
    {
      GNUNET_break(0);
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          "Plugin removes address never added!\n");
      end_badly_now ();
      return;
    }

    GNUNET_CONTAINER_DLL_remove(head, tail, w);
    GNUNET_HELLO_address_free (w->address);
    GNUNET_free(w->addrstring);
    GNUNET_free(w);
    return;
  }
  GNUNET_break(0);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Invalid operation: %u\n",
              add_remove);
  end_badly_now ();
}


static enum GNUNET_ATS_Network_Type
env_get_address_type (void *cls,
                      const struct sockaddr *addr,
                      size_t addrlen)
{
  return GNUNET_ATS_NET_LOOPBACK;
}


static const struct GNUNET_MessageHeader *
env_get_our_hello ()
{
  return (const struct GNUNET_MessageHeader *) hello;
}


static void
env_session_end (void *cls,
                 const struct GNUNET_HELLO_Address *address,
                 struct Session *session)
{

}


static void
env_update_distance (void *cls,
                     const struct GNUNET_HELLO_Address *address,
                     uint32_t distance)
{
}


static void
setup_plugin_environment ()
{
  env.cfg = cfg;
  env.cls = &env;
  env.my_identity = &my_identity;
  env.max_connections = max_connect_per_transport;
  env.stats = stats;
  env.receive = &env_receive;
  env.notify_address = &env_notify_address;
  env.get_address_type = &env_get_address_type;
  env.update_address_distance = &env_update_distance;
  env.get_our_hello = &env_get_our_hello;
  env.session_end = &env_session_end;
}


static int
handle_helper_message (void *cls, void *client,
                       const struct GNUNET_MessageHeader *hdr)
{
  return GNUNET_OK;
}


/**
 * Runs the test.
 *
 * @param cls closure
 * @param c configuration to use
 */
static void
run (void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *c)
{
  char * const *argv = cls;
  unsigned long long tneigh;
  char *keyfile;
  char *plugin;
  char *sep;

  timeout_endbadly = GNUNET_SCHEDULER_add_delayed (TIMEOUT, end_badly, &ok);

  cfg = c;
  /* parse configuration */
  if ((GNUNET_OK
      != GNUNET_CONFIGURATION_get_value_number (c, "TRANSPORT",
          "NEIGHBOUR_LIMIT", &tneigh))
      || (GNUNET_OK
          != GNUNET_CONFIGURATION_get_value_filename (c, "PEER", "PRIVATE_KEY",
              &keyfile)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Transport service is lacking key configuration settings.  Exiting.\n");
    return;
  }

  if (NULL == (stats = GNUNET_STATISTICS_create ("transport", cfg)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Could not create statistics.  Exiting.\n");
    GNUNET_free(keyfile);
    end_badly_now ();
    return;
  }

  if (GNUNET_OK != GNUNET_DISK_file_test (HOSTKEY_FILE))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Hostkey `%s' missing.  Exiting.\n",
        HOSTKEY_FILE);
    GNUNET_free(keyfile);
    end_badly_now ();
    return;
  }

  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Could not create a directory for hostkey `%s'.  Exiting.\n", keyfile);
    GNUNET_free(keyfile);
    end_badly_now ();
    return;
  }

  if (GNUNET_OK != GNUNET_DISK_file_copy (HOSTKEY_FILE, keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Could not copy hostkey `%s' to destination `%s'.  Exiting.\n",
        HOSTKEY_FILE, keyfile);
    GNUNET_free(keyfile);
    end_badly_now ();
    return;
  }

  max_connect_per_transport = (uint32_t) tneigh;
  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_file (keyfile);
  GNUNET_free(keyfile);
  if (NULL == my_private_key)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Could not access hostkey.  Exiting.\n");
    end_badly_now ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key, &my_identity.public_key);

  hello = GNUNET_HELLO_create (&my_identity.public_key, NULL, NULL, GNUNET_NO);

  /* load plugins... */
  setup_plugin_environment ();

  GNUNET_assert(strlen (argv[0]) > strlen ("test_plugin_"));
  plugin = strstr (argv[0], "test_plugin_");
  sep = strrchr (argv[0], '.');
  if (NULL == plugin)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Not a valid test name\n");
    end_badly_now ();
    return;
  }
  plugin += strlen ("test_plugin_");
  if (NULL != sep)
    sep[0] = '\0';

  /* Hack for WLAN: start a second helper */
  if (0 == strcmp (plugin, "wlan"))
  {
    char * helper_argv[3];
    helper_argv[0] = (char *) "gnunet-helper-transport-wlan-dummy";
    helper_argv[1] = (char *) "2";
    helper_argv[2] = NULL;
    suid_helper = GNUNET_HELPER_start (GNUNET_NO,
        "gnunet-helper-transport-wlan-dummy", helper_argv,
        &handle_helper_message, NULL, NULL );
  }

  /* Loading plugin */
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Loading transport plugin %s\n", plugin);
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", plugin);
  api = GNUNET_PLUGIN_load (libname, &env);
  if (NULL == api)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Failed to load transport plugin for %s\n", plugin);
    end_badly_now ();
    return;
  }

  timeout_wait = GNUNET_SCHEDULER_add_delayed (WAIT, &wait_end, NULL );

  /* Check if all functions are implemented */
  if (NULL == api->address_pretty_printer)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }
  if (NULL == api->address_to_string)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }
  GNUNET_assert(NULL != api->check_address);
  if (NULL == api->check_address)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }
  GNUNET_assert(NULL != api->disconnect_peer);
  if (NULL == api->disconnect_peer)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }
  GNUNET_assert(NULL != api->get_session);
  if (NULL == api->get_session)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }
  if (NULL == api->address_pretty_printer)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }
  if (NULL == api->string_to_address)
  {
    GNUNET_break(0);
    end_badly_now ();
    return;
  }

}

/**
 * The main function for the test
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char * const *argv)
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END };
  int ret;

  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-plugin-transport");

  char * const argv_prog[] = { "test_plugin_transport", "-c",
      "test_plugin_transport_data.conf", NULL };
  GNUNET_log_setup ("test-plugin-transport", "WARNING", NULL );
  ok = 1; /* set to fail */
  ret =
      (GNUNET_OK
          == GNUNET_PROGRAM_run (3, argv_prog, "test-plugin-transport",
              "testcase", options, &run, (void *) argv)) ? ok : 1;
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-plugin-transport");
  return ret;
}

/* end of test_plugin_transport.c */

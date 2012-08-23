/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_plugin_transport.c
 * @brief testcase for transport_api.c
 * @author Sailor Siraj
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_transport_plugin.h"

#include "transport.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

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
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our configuration.
 */
struct GNUNET_STATISTICS_Handle *stats;

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
 * Timeout task
 */
static GNUNET_SCHEDULER_TaskIdentifier timeout_task;

/**
 * Library name
 */
static char *libname;

struct AddressWrapper *head;
struct AddressWrapper *tail;

/**
 * Did the test pass or fail?
 */
static int ok;


struct AddressWrapper
{
  struct AddressWrapper *next;

  struct AddressWrapper *prev;

  void *addr;

  size_t addrlen;
};

static void
end ()
{
  if (NULL != head)
  {

  }

  if (GNUNET_SCHEDULER_NO_TASK != timeout_task)
  {
      GNUNET_SCHEDULER_cancel (timeout_task);
      timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != api)
  {
      GNUNET_PLUGIN_unload (libname, api);
  }
  GNUNET_free (libname);
  libname = NULL;
  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;

  ok = 0;
}

static void

end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct AddressWrapper *w;
  int c = 0;

  timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != libname)
  {
    if (NULL != api)
      GNUNET_PLUGIN_unload (libname, api);
    GNUNET_free (libname);
    libname = NULL;
  }

  w = head;
  while (NULL != head)
  {
      GNUNET_CONTAINER_DLL_remove (head, tail, w);
      c ++;
      GNUNET_free (w->addr);
      GNUNET_free (w);
  }
  if (c > 0)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              _("Plugin did not remove %u addresses \n"), c);
  }

  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }

  ok = 1;
}


static void
end_badly_now ()
{
  if (GNUNET_SCHEDULER_NO_TASK != timeout_task)
  {
      GNUNET_SCHEDULER_cancel (timeout_task);
      timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  timeout_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}


static struct GNUNET_TIME_Relative
env_receive (void *cls,
            const struct GNUNET_PeerIdentity *peer,
            const struct GNUNET_MessageHeader *message,
            const struct GNUNET_ATS_Information *ats,
            uint32_t ats_count,
            struct Session * session,
            const char *sender_address,
            uint16_t sender_address_len)
{
  /* do nothing */
  GNUNET_break (0);
  return GNUNET_TIME_relative_get_zero_();
}


static void
env_notify_address (void *cls,
                    int add_remove,
                    const void *addr,
                    size_t addrlen)
{
  struct AddressWrapper *w;
  char *a2s;
  void *s2a;
  size_t s2a_len;

  if (GNUNET_YES == add_remove)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Adding address of length %u\n"), addrlen);

      w = GNUNET_malloc (sizeof (struct AddressWrapper));
      w->addr = GNUNET_malloc (addrlen);
      w->addrlen = addrlen;
      memcpy (w->addr, addr, addrlen);
      GNUNET_CONTAINER_DLL_insert(head, tail, w);

      a2s = strdup (api->address_to_string (api, w->addr, w->addrlen));
      if (NULL == a2s)
      {
          GNUNET_break (0);
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Plugin cannot convert address to string!\n"));
          end_badly_now();
          return;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Plugin added address `%s'\n"), a2s);

      if (GNUNET_OK != api->string_to_address (api, a2s, strlen (a2s)+1, &s2a, &s2a_len))
      {
          GNUNET_break (0);
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Plugin cannot convert string to address!\n"));
          end_badly_now();
          return;
      }

      if (s2a_len != w->addrlen)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Plugin creates different address length when converting address->string->address: %u != %u\n"), w->addrlen, s2a_len);
      }
      else
      {
          if (0 != memcmp (s2a, w->addr, s2a_len))
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                        _("Plugin creates different address length when connecting back and forth!\n"));
      }

      if (GNUNET_OK != api->check_address (api->cls, w->addr, w->addrlen))
      {
          GNUNET_break (0);
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Plugin refuses added address!\n"));
          end_badly_now();
          return;
      }
  }
  else if (GNUNET_NO == add_remove)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Removing address of length %u\n"), addrlen);

      w = head;
      while (NULL != w)
      {
          if ((addrlen == w->addrlen) && (0 == memcmp (w->addr, addr, addrlen)))
          {
            break;
          }
          w = w->next;
      }

      if (w == NULL)
      {
          GNUNET_break (0);
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Plugin removes address never added!\n"));
          end_badly_now();
          return;
      }

      GNUNET_CONTAINER_DLL_remove (head, tail, w);
      GNUNET_free (w->addr);
      GNUNET_free (w);
  }
  else
  {
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Invalid operation\n"));
      end_badly_now ();
  }
}

struct GNUNET_ATS_Information
env_get_address_type (void *cls,
                     const struct sockaddr *addr,
                     size_t addrlen)
{
  struct GNUNET_ATS_Information ats;
  ats.type = htonl (0);
  ats.value = htonl (0);
  return ats;
}


const struct GNUNET_MessageHeader *
env_get_our_hello (void)
{
  GNUNET_break (0);
  return NULL;
}

void env_session_end (void *cls,
                      const struct GNUNET_PeerIdentity *peer,
                      struct Session * session)
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
  env.get_our_hello = &env_get_our_hello;
  env.session_end = &env_session_end;
}


/**
 * Runs the test.
 *
 * @param cls closure
 * @param c configuration to use
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *const *argv = cls;
  unsigned long long tneigh;
  char *keyfile;
  char *plugin;
  char *sep;

  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, end_badly, NULL);

  cfg = c;
  /* parse configuration */
  if ((GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (c,
                          "TRANSPORT",
                          "NEIGHBOUR_LIMIT",
                          &tneigh)) ||
      (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (c,
                          "GNUNETD", "HOSTKEY",
                          &keyfile)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Transport service is lacking key configuration settings.  Exiting.\n"));

    return;
  }

  stats = GNUNET_STATISTICS_create ("transport", cfg);
  if (NULL == stats)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Could not create statistics.  Exiting.\n"));
      end_badly_now ();
      return;
  }

  max_connect_per_transport = (uint32_t) tneigh;
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Transport service could not access hostkey.  Exiting.\n"));
    end_badly_now ();
    return;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &my_identity.hashPubKey);

  /* load plugins... */
  setup_plugin_environment ();

  plugin = strrchr(argv[0],'_');
  sep = strrchr(argv[0],'.');
  if (NULL == plugin)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Not a valid test name\n"));
      end_badly_now ();
      return;
  }
  plugin++;
  if (NULL != sep)
      sep[0] = '\0';

  /* Loading plugin */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading transport plugin %s\n"), plugin);
  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", plugin);
  api = GNUNET_PLUGIN_load (libname, &env);
  if (api == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load transport plugin for tcp\n"));
    end_badly_now ();
    return;
  }

  /* Check if all functions are implemented */
  if (NULL == api->address_pretty_printer)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
  }
  if (NULL == api->address_to_string)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
  }
  GNUNET_assert (NULL != api->check_address);
  if (NULL == api->check_address)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
  }
  GNUNET_assert (NULL != api->disconnect);
  if (NULL == api->disconnect)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
  }
  GNUNET_assert (NULL != api->get_session);
  if (NULL == api->get_session)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
  }
  if (NULL == api->address_pretty_printer)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
  }
  if (NULL == api->string_to_address)
  {
      GNUNET_break (0);
      end_badly_now ();
      return;
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
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  char *const argv_prog[] = {
    "test_plugin_transport",
    "-c",
    "test_plugin_transport_data.conf",
    "-L", "WARNING",
    NULL
  };
  GNUNET_log_setup ("test-plugin-transport",
                    "WARNING",
                    NULL);
  ok = 1;                       /* set to fail */
  ret = (GNUNET_OK == GNUNET_PROGRAM_run (5,
                           argv_prog,
                           "test-plugin-transport",
                           "testcase",
                           options,
                           &run,
                           (void *) argv)) ? ok : 1;
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-plugin-transport");
  return ret;
}

/* end of test_plugin_transport.c */

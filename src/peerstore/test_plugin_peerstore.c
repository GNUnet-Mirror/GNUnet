/*
     This file is part of GNUnet.
     Copyright (C) 2015 GNUnet e.V.

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
/*
 * @file namestore/test_plugin_namestore.c
 * @brief Test for the namestore plugins
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerstore_plugin.h"
#include "gnunet_testing_lib.h"


static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;


static struct GNUNET_PEERSTORE_PluginFunctions *psp;

static struct GNUNET_PeerIdentity p1;


/**
 * Function called when the service shuts down.  Unloads our namestore
 * plugin.
 *
 * @param api api to unload
 */
static void
unload_plugin (struct GNUNET_PEERSTORE_PluginFunctions *api)
{
  char *libname;

  GNUNET_asprintf (&libname,
                   "libgnunet_plugin_peer_%s",
                   plugin_name);
  GNUNET_break (NULL ==
                GNUNET_PLUGIN_unload (libname,
                                      api));
  GNUNET_free (libname);
}


/**
 * Load the namestore plugin.
 *
 * @param cfg configuration to pass
 * @return NULL on error
 */
static struct GNUNET_PEERSTORE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PEERSTORE_PluginFunctions *ret;
  char *libname;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' peer plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname,
                   "libgnunet_plugin_peerstore_%s",
                   plugin_name);
  if (NULL == (ret = GNUNET_PLUGIN_load (libname,
                                         (void*) cfg)))
  {
    FPRINTF (stderr,
             "Failed to load plugin `%s'!\n",
             plugin_name);
    GNUNET_free (libname);
    return NULL;
  }
  GNUNET_free (libname);
  return ret;
}


static void
test_record (void *cls,
             const struct GNUNET_PEERSTORE_Record *record,
             const char *error)
{
  const struct GNUNET_PeerIdentity *id = cls;
  const char* testval = "test_val";

  if (NULL == record)
  {
    unload_plugin (psp);
    return;
  }
  GNUNET_assert (0 == memcmp (&record->peer,
                              id,
                              sizeof (struct GNUNET_PeerIdentity)));
  GNUNET_assert (0 == strcmp ("subsys",
                              record->sub_system));
  GNUNET_assert (0 == strcmp ("key",
                              record->key));
  GNUNET_assert (0 == memcmp (testval,
                              record->value,
                              strlen (testval)));
  ok = 0;
}


static void
get_record (struct GNUNET_PEERSTORE_PluginFunctions *psp,
            const struct GNUNET_PeerIdentity *identity)
{
  GNUNET_assert (GNUNET_OK ==
                 psp->iterate_records (psp->cls,
                                       "subsys",
                                       identity,
                                       "key",
                                       &test_record,
                                       (void*)identity));
}


static void
store_cont (void *cls,
            int status)
{
  GNUNET_assert (GNUNET_OK == status);
  get_record (psp,
              &p1);
}


static void
put_record (struct GNUNET_PEERSTORE_PluginFunctions *psp,
            const struct GNUNET_PeerIdentity *identity)
{
  GNUNET_assert (GNUNET_OK ==
                 psp->store_record (psp->cls,
                                    "subsys",
                                    identity,
                                    "key",
                                    "test_value",
                                    strlen ("test_value"),
                                    GNUNET_TIME_absolute_get (),
                                    GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                                    &store_cont,
                                    NULL));
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  ok = 1;
  psp = load_plugin (cfg);
  if (NULL == psp)
  {
    FPRINTF (stderr,
             "%s",
	     "Failed to initialize peerstore.  Database likely not setup, skipping test.\n");
    return;
  }
  memset (&p1, 1, sizeof (p1));
  put_record (psp,
              &p1);
}


int
main (int argc, char *argv[])
{
  char cfg_name[128];
  char *const xargv[] = {
    "test-plugin-peerstore",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test-plugin-peerstore",
                    "WARNING",
                    NULL);
  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name,
                   sizeof (cfg_name),
                   "test_plugin_peerstore_%s.conf",
                   plugin_name);
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1,
                      xargv,
                      "test-plugin-peerstore",
                      "nohelp",
                      options,
                      &run,
                      NULL);
  if (ok != 0)
    FPRINTF (stderr,
             "Missed some testcases: %d\n",
             ok);
  return ok;
}

/* end of test_plugin_peerstore.c */

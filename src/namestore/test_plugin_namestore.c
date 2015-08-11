/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
#include "gnunet_namestore_plugin.h"
#include "gnunet_testing_lib.h"


static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;


/**
 * Function called when the service shuts down.  Unloads our namestore
 * plugin.
 *
 * @param api api to unload
 */
static void
unload_plugin (struct GNUNET_NAMESTORE_PluginFunctions *api)
{
  char *libname;

  GNUNET_asprintf (&libname, "libgnunet_plugin_namestore_%s", plugin_name);
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (libname, api));
  GNUNET_free (libname);
}


/**
 * Load the namestore plugin.
 *
 * @param cfg configuration to pass
 * @return NULL on error
 */
static struct GNUNET_NAMESTORE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_PluginFunctions *ret;
  char *libname;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading `%s' namestore plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_namestore_%s", plugin_name);
  if (NULL == (ret = GNUNET_PLUGIN_load (libname, (void*) cfg)))
  {
    FPRINTF (stderr, "Failed to load plugin `%s'!\n", plugin_name);
    GNUNET_free (libname);
    return NULL;
  }
  GNUNET_free (libname);
  return ret;
}


static void
test_record (void *cls,
						 const struct GNUNET_CRYPTO_EcdsaPrivateKey *private_key,
						 const char *label,
						 unsigned int rd_count,
						 const struct GNUNET_GNSRECORD_Data *rd)
{
  int *idp = cls;
  int id = *idp;
  struct GNUNET_CRYPTO_EcdsaPrivateKey tzone_private_key;
  char tname[64];
  unsigned int trd_count = 1 + (id % 1024);
  unsigned int i;

  GNUNET_snprintf (tname, sizeof (tname),
		   "a%u", (unsigned int ) id);
  for (i=0;i<trd_count;i++)
  {
    GNUNET_assert (rd[i].data_size == id % 10);
    GNUNET_assert (0 == memcmp ("Hello World", rd[i].data, id % 10));
    GNUNET_assert (rd[i].record_type == 1 + (id % 13));
    GNUNET_assert (rd[i].flags == 0);
  }
  memset (&tzone_private_key, (id % 241), sizeof (tzone_private_key));
  GNUNET_assert (0 == strcmp (label, tname));
  GNUNET_assert (0 == memcmp (&tzone_private_key, private_key, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)));
}


static void
get_record (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  GNUNET_assert (GNUNET_OK == nsp->iterate_records (nsp->cls,
					    NULL, 0, &test_record, &id));
}


static void
put_record (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone_private_key;
  char label[64];
  unsigned int rd_count = 1 + (id % 1024);
  struct GNUNET_GNSRECORD_Data rd[rd_count];
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  unsigned int i;

  GNUNET_snprintf (label, sizeof (label),
		   "a%u", (unsigned int ) id);
  for (i=0;i<rd_count;i++)
  {
    rd[i].data = "Hello World";
    rd[i].data_size = id % 10;
    rd[i].expiration_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_MINUTES).abs_value_us;
    rd[i].record_type = 1 + (id % 13);
    rd[i].flags = 0;
  }
  memset (&zone_private_key, (id % 241), sizeof (zone_private_key));
  memset (&signature, (id % 243), sizeof (signature));
  GNUNET_assert (GNUNET_OK == nsp->store_records (nsp->cls,
						&zone_private_key,
						label,
						rd_count,
						rd));
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_PluginFunctions *nsp;

  ok = 0;
  nsp = load_plugin (cfg);
  if (NULL == nsp)
  {
    FPRINTF (stderr,
             "%s",
	     "Failed to initialize namestore.  Database likely not setup, skipping test.\n");
    return;
  }
  put_record (nsp, 1);
  get_record (nsp, 1);

  unload_plugin (nsp);
}


int
main (int argc, char *argv[])
{
  char cfg_name[128];
  char *const xargv[] = {
    "test-plugin-namestore",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  //GNUNET_DISK_directory_remove ("/tmp/gnunet-test-plugin-namestore-sqlite");
  GNUNET_log_setup ("test-plugin-namestore",
                    "WARNING",
                    NULL);
  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_plugin_namestore_%s.conf",
                   plugin_name);
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-plugin-namestore", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);
  //GNUNET_DISK_directory_remove ("/tmp/gnunet-test-plugin-namestore-sqlite");
  return ok;
}

/* end of test_plugin_namestore.c */

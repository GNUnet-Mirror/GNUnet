/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
/*
 * @file namestore/test_plugin_namestore.c
 * @brief Test for the namestore plugins
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_plugin.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

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
    return NULL;
  }
  GNUNET_free (libname);
  return ret;
}


/**
 * Function called by for each matching record.
 *
 * @param cls closure
 * @param zone_key public key of the zone
 * @param expire when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
 *        because the user queried for a particular record type only)
 */
static void 
test_record (void *cls,
	     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
	     struct GNUNET_TIME_Absolute expire,
	     const char *name,
	     unsigned int rd_count,
	     const struct GNUNET_NAMESTORE_RecordData *rd,
	     const struct GNUNET_CRYPTO_RsaSignature *signature)
{
}


static void
get_record (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
  GNUNET_assert (1 == nsp->iterate_records (nsp->cls,
					    NULL, NULL, 0,
					    &test_record, &id));
}


static void
put_record (struct GNUNET_NAMESTORE_PluginFunctions *nsp, int id)
{
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_PluginFunctions *nsp;  
  GNUNET_HashCode zone;
  
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

  memset (&zone, 42, sizeof (zone));  
  nsp->delete_zone (nsp->cls, &zone);
  unload_plugin (nsp);
}


int
main (int argc, char *argv[])
{
  char *pos;
  char cfg_name[128];

  char *const xargv[] = {
    "test-plugin-namestore",
    "-c",
    cfg_name,
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-plugin-namestore-sqlite");
  GNUNET_log_setup ("test-plugin-namestore",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  /* determine name of plugin to use */
  plugin_name = argv[0];
  while (NULL != (pos = strstr (plugin_name, "_")))
    plugin_name = pos + 1;
  if (NULL != (pos = strstr (plugin_name, ".")))
    pos[0] = 0;
  else
    pos = (char *) plugin_name;

  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_plugin_namestore_%s.conf",
                   plugin_name);
  if (pos != plugin_name)
    pos[0] = '.';
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-plugin-namestore", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);
  GNUNET_DISK_directory_remove ("/tmp/gnunet-test-plugin-namestore-sqlite");
  return ok;
}

/* end of test_plugin_namestore.c */

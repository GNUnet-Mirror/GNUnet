/*
     This file is part of GNUnet.
     Copyright (C) 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file namestore/test_common.c
 * @brief common functions for testcase setup
 */

/**
 * test if we can load the plugin @a name.
 */
static int
TNC_test_plugin (const char *cfg_name)
{
  char *database;
  char *db_lib_name;
  struct GNUNET_NAMESTORE_PluginFunctions *db;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, cfg_name))
  {
    GNUNET_break (0);
    GNUNET_CONFIGURATION_destroy (cfg);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "namestore",
                                                          "database",
                                                          &database))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");
    GNUNET_CONFIGURATION_destroy (cfg);
    return GNUNET_SYSERR;
  }
  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GNUNET_free (database);
  db = GNUNET_PLUGIN_load (db_lib_name, (void *) cfg);
  if (NULL != db)
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, db));
  GNUNET_free (db_lib_name);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (NULL == db)
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * General setup logic for starting the tests.  Obtains the @a
 * plugin_name and initializes the @a cfg_name.
 */
#define SETUP_CFG(plugin_name, cfg_name)                                    \
  do                                                                        \
  {                                                                         \
    plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);    \
    GNUNET_asprintf (&cfg_name, "test_namestore_api_%s.conf", plugin_name); \
    if (! TNC_test_plugin (cfg_name))                                       \
    {                                                                       \
      GNUNET_free (cfg_name);                                               \
      return 77;                                                            \
    }                                                                       \
    GNUNET_DISK_purge_cfg_dir (cfg_name, "GNUNET_TEST_HOME");               \
  } while (0)

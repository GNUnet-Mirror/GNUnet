/*
     This file is part of GNUnet.
     (C) 2006 - 2009 Christian Grothoff (and other contributing authors)

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
 * @file src/dht/dhtlog.c
 * @brief Plugin loaded to load logging
 *        to record DHT operations
 * @author Nathan Evans
 *
 * Database: Loaded by plugin MySQL
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "dhtlog.h"

static char *libname;

/*
 * Provides the dhtlog api
 *
 * @param c the configuration to use to connect to a server
 *
 * @return the handle to the server, or NULL on error
 */
struct GNUNET_DHTLOG_Handle *
GNUNET_DHTLOG_connect (const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_DHTLOG_Plugin *plugin;
  struct GNUNET_DHTLOG_Handle *api;
  char *plugin_name;

  plugin = GNUNET_malloc (sizeof (struct GNUNET_DHTLOG_Plugin));
  plugin->cfg = c;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (c,
                                             "DHTLOG", "PLUGIN", &plugin_name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Loading `%s' dhtlog plugin\n"), plugin_name);
    GNUNET_asprintf (&libname, "libgnunet_plugin_dhtlog_%s", plugin_name);
    GNUNET_PLUGIN_load (libname, plugin);
  }

  if (plugin->dhtlog_api == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to load dhtlog plugin for `%s'\n"), plugin_name);
    GNUNET_free (plugin_name);
    GNUNET_free (plugin);
    return NULL;
  }

  api = plugin->dhtlog_api;
  GNUNET_free (plugin_name);
  GNUNET_free (plugin);
  return api;
}

/**
 * Shutdown the module.
 */
void
GNUNET_DHTLOG_disconnect (struct GNUNET_DHTLOG_Handle *api)
{
#if DEBUG_DHTLOG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MySQL DHT Logger: database shutdown\n");
#endif
  if (api != NULL)
  {
    GNUNET_PLUGIN_unload (libname, api);
  }
  GNUNET_free_non_null (libname);
}

/* end of dhtlog.c */

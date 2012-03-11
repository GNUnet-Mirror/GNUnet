/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo-tool/gnunet-peerinfo_plugins.c
 * @brief plugin management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-peerinfo_plugins.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_hello_lib.h"

/**
 * Entry in doubly-linked list of all of our plugins.
 */
struct TransportPlugin
{
  /**
   * This is a doubly-linked list.
   */
  struct TransportPlugin *next;

  /**
   * This is a doubly-linked list.
   */
  struct TransportPlugin *prev;

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_TRANSPORT_PluginFunctions *api;

  /**
   * Short name for the plugin (i.e. "tcp").
   */
  char *short_name;

  /**
   * Name of the library (i.e. "gnunet_plugin_transport_tcp").
   */
  char *lib_name;

  /**
   * Environment this transport service is using
   * for this plugin.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment env;

};

/**
 * Head of DLL of all loaded plugins.
 */
static struct TransportPlugin *plugins_head;

/**
 * Head of DLL of all loaded plugins.
 */
static struct TransportPlugin *plugins_tail;



/**
 * Load and initialize all plugins.  The respective functions will be
 * invoked by the plugins when the respective events happen.  The
 * closure will be set to a 'const char*' containing the name of the
 * plugin that caused the call.
 *
 * @param cfg configuration to use
 */
void
GPI_plugins_load (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TransportPlugin *plug;
  struct TransportPlugin *next;
  char *libname;
  char *plugs;
  char *pos;

  if (NULL != plugins_head)
    return; /* already loaded */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "TRANSPORT", "PLUGINS",
                                             &plugs))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting transport plugins `%s'\n"),
              plugs);
  for (pos = strtok (plugs, " "); pos != NULL; pos = strtok (NULL, " "))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading `%s' transport plugin\n"),
                pos);
    GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", pos);
    plug = GNUNET_malloc (sizeof (struct TransportPlugin));
    plug->short_name = GNUNET_strdup (pos);
    plug->lib_name = libname;
    plug->env.cfg = cfg;
    plug->env.cls = plug->short_name;
    GNUNET_CONTAINER_DLL_insert (plugins_head, plugins_tail, plug);
  }
  GNUNET_free (plugs);
  next = plugins_head;
  while (next != NULL)
  {
    plug = next;
    next = plug->next;
    plug->api = GNUNET_PLUGIN_load (plug->lib_name, &plug->env);
    if (plug->api == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load transport plugin for `%s'\n"),
                  plug->lib_name);
      GNUNET_CONTAINER_DLL_remove (plugins_head, plugins_tail, plug);
      GNUNET_free (plug->short_name);
      GNUNET_free (plug->lib_name);
      GNUNET_free (plug);
    }
  }
}


/**
 * Unload all plugins
 */
void
GPI_plugins_unload ()
{
  struct TransportPlugin *plug;

  while (NULL != (plug = plugins_head))
  {
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
    GNUNET_free (plug->lib_name);
    GNUNET_free (plug->short_name);
    GNUNET_CONTAINER_DLL_remove (plugins_head, plugins_tail, plug);
    GNUNET_free (plug);
  }
}


/**
 * Obtain the plugin API based on a plugin name.
 *
 * @param name name of the plugin
 * @return the plugin's API, NULL if the plugin is not loaded
 */
struct GNUNET_TRANSPORT_PluginFunctions *
GPI_plugins_find (const char *name)
{
  struct TransportPlugin *head = plugins_head;

  while ((head != NULL) && (0 != strcmp (name, head->short_name)))
    head = head->next;
  if (NULL == head)
    return NULL;
  return head->api;
}


/* end of file gnunet-peerinfo_plugins.c */

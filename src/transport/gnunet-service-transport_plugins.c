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
 * @file transport/gnunet-service-transport_plugins.c
 * @brief plugin management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_plugins.h"

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
 * @param recv_cb function to call when data is received
 * @param address_cb function to call when our public addresses changed
 * @param session_end_cb function to call when a session was terminated
 * @param address_type_cb function to call when a address type is requested
 */
void
GST_plugins_load (GNUNET_TRANSPORT_PluginReceiveCallback recv_cb,
                  GNUNET_TRANSPORT_AddressNotification address_cb,
                  GNUNET_TRANSPORT_SessionEnd session_end_cb,
                  GNUNET_TRANSPORT_AddressToType address_type_cb)
{
  struct TransportPlugin *plug;
  struct TransportPlugin *next;
  unsigned long long tneigh;
  char *libname;
  char *plugs;
  char *pos;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (GST_cfg, "TRANSPORT",
                                             "NEIGHBOUR_LIMIT", &tneigh))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Transport service is lacking NEIGHBOUR_LIMIT option.\n"));
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (GST_cfg, "TRANSPORT", "PLUGINS",
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
    plug->env.cfg = GST_cfg;
    plug->env.my_identity = &GST_my_identity;
    plug->env.get_our_hello = &GST_hello_get;
    plug->env.cls = plug->short_name;
    plug->env.receive = recv_cb;
    plug->env.notify_address = address_cb;
    plug->env.session_end = session_end_cb;
    plug->env.get_address_type = address_type_cb;
    plug->env.max_connections = tneigh;
    plug->env.stats = GST_stats;
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
GST_plugins_unload ()
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
GST_plugins_find (const char *name)
{
  struct TransportPlugin *head = plugins_head;

  while ((head != NULL) && (0 != strcmp (name, head->short_name)))
    head = head->next;
  if (NULL == head)
    return NULL;
  return head->api;
}


/**
 * Convert a given address to a human-readable format.  Note that the
 * return value will be overwritten on the next call to this function.
 *
 * @param address the address to convert
 * @return statically allocated (!) human-readable address
 */
const char *
GST_plugins_a2s (const struct GNUNET_HELLO_Address *address)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  static char unable_to_show[1024];

  if (address == NULL)
    return "<inbound>";
  api = GST_plugins_find (address->transport_name);
  if (NULL == api)
    return "<plugin unknown>";
  if (0 == address->address_length)
  {
    GNUNET_snprintf (unable_to_show, sizeof (unable_to_show),
                     "<unable to stringify %u-byte long address of %s transport>",
                     (unsigned int) address->address_length,
                     address->transport_name);
    return unable_to_show;
  }
  return api->address_to_string (NULL, address->address,
                                 address->address_length);
}


/* end of file gnunet-service-transport_plugins.c */

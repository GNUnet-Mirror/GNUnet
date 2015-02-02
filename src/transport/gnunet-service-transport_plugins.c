/*
  This file is part of GNUnet.
  (C) 2010-2014 Christian Grothoff (and other contributing authors)

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
 * @param session_start_cb function to call when a session was created
 * @param session_end_cb function to call when a session was terminated
 * @param address_type_cb function to call when a address type is requested
 * @param metric_update_cb function to call when address metrics change
 */
void
GST_plugins_load (GNUNET_TRANSPORT_PluginReceiveCallback recv_cb,
                  GNUNET_TRANSPORT_AddressNotification address_cb,
                  GNUNET_TRANSPORT_SessionStart session_start_cb,
                  GNUNET_TRANSPORT_SessionEnd session_end_cb,
                  GNUNET_TRANSPORT_AddressToType address_type_cb,
                  GNUNET_TRANSPORT_UpdateAddressMetrics metric_update_cb)
{
  struct TransportPlugin *plug;
  struct TransportPlugin *next;
  unsigned long long tneigh;
  char *libname;
  char *plugs;
  char *pos;
  int fail;

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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Starting transport plugins `%s'\n"),
              plugs);
  for (pos = strtok (plugs, " "); pos != NULL; pos = strtok (NULL, " "))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Loading `%s' transport plugin\n"),
                pos);
    GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", pos);
    plug = GNUNET_new (struct TransportPlugin);
    plug->short_name = GNUNET_strdup (pos);
    plug->lib_name = libname;
    plug->env.cfg = GST_cfg;
    plug->env.my_identity = &GST_my_identity;
    plug->env.get_our_hello = &GST_hello_get;
    plug->env.cls = plug->short_name;
    plug->env.receive = recv_cb;
    plug->env.notify_address = address_cb;
    plug->env.session_start = session_start_cb;
    plug->env.session_end = session_end_cb;
    plug->env.get_address_type = address_type_cb;
    plug->env.update_address_metrics = metric_update_cb;
    plug->env.max_connections = tneigh;
    plug->env.stats = GST_stats;
    GNUNET_CONTAINER_DLL_insert (plugins_head, plugins_tail, plug);
  }
  GNUNET_free (plugs);
  next = plugins_head;
  while (NULL != next)
  {
    plug = next;
    next = plug->next;
    plug->api = GNUNET_PLUGIN_load (plug->lib_name, &plug->env);
    if (NULL == plug->api)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load transport plugin for `%s'\n"),
                  plug->lib_name);
      GNUNET_CONTAINER_DLL_remove (plugins_head, plugins_tail, plug);
      GNUNET_free (plug->short_name);
      GNUNET_free (plug->lib_name);
      GNUNET_free (plug);
      continue;
    }
    fail = GNUNET_NO;
    if (NULL == plug->api->address_pretty_printer)
    {
    	fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "address_pretty_printer",
                  plug->lib_name);
    }
    if (NULL == plug->api->address_to_string)
    {
    	fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "address_to_string",
                  plug->lib_name);
    }
    if (NULL == plug->api->string_to_address)
    {
    	fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "string_to_address",
                  plug->lib_name);
    }
    if (NULL == plug->api->check_address)
    {
      fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "check_address",
                  plug->lib_name);
    }
    if (NULL == plug->api->get_session)
    {
      fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "get_session",
                  plug->lib_name);
    }
    if (NULL == plug->api->get_network)
    {
      fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "get_network",
                  plug->lib_name);
    }
    if (NULL == plug->api->send)
    {
      fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "send",
                  plug->lib_name);
    }
    if (NULL == plug->api->disconnect_peer)
    {
    	fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "disconnect_peer",
                  plug->lib_name);
    }
    if (NULL == plug->api->disconnect_session)
    {
    	fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "disconnect_session",
                  plug->lib_name);
    }
    if (NULL == plug->api->query_keepalive_factor)
    {
      fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "query_keepalive_factor",
                  plug->lib_name);
    }
    if (NULL == plug->api->update_session_timeout)
    {
        fail = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Missing function `%s' in transport plugin for `%s'\n"),
                  "update_session_timeout",
                  plug->lib_name);
    }
    if (GNUNET_YES == fail)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Did not load plugin `%s' due to missing functions\n"),
                  plug->lib_name);
      GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
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
  struct TransportPlugin *pos;

  for (pos = plugins_head; NULL != pos; pos = pos->next)
    if (0 == strcmp (name, pos->short_name))
      break;
  if (NULL == pos)
    return NULL;
  return pos->api;
}


/**
 * Obtain the plugin API based on a the stripped plugin name after the underscore.
 *
 * Example: GST_plugins_printer_find (http_client) will return all plugins
 * starting with the prefix "http":
 * http_client or server if loaded
 *
 * @param name name of the plugin
 * @return the plugin's API, NULL if the plugin is not loaded
 */
struct GNUNET_TRANSPORT_PluginFunctions *
GST_plugins_printer_find (const char *name)
{
  struct TransportPlugin *pos;
  char *stripped = GNUNET_strdup (name);
  char *sep = strchr (stripped, '_');

  if (NULL != sep)
    sep[0] = '\0';
  for (pos = plugins_head; NULL != pos; pos = pos->next)
    if (pos->short_name == strstr (pos->short_name, stripped))
        break;
  GNUNET_free (stripped);
  if (NULL == pos)
    return NULL;
  return pos->api;
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
  static const char *s;

  if (NULL == address)
    return "<NULL>";
  if (0 == address->address_length)
    return TRANSPORT_SESSION_INBOUND_STRING; /* Addresse with length 0 are inbound, address->address itself may be NULL */
  api = GST_plugins_printer_find (address->transport_name);
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
  return (NULL != (s = api->address_to_string (NULL, address->address,
                                 address->address_length)) ? s : "<invalid>");
}


/**
 * Register callback with all plugins to monitor their status.
 *
 * @param cb callback to register, NULL to unsubscribe
 * @param cb_cls closure for @a cb
 */
void
GST_plugins_monitor_subscribe (GNUNET_TRANSPORT_SessionInfoCallback cb,
			       void *cb_cls)
{
  struct TransportPlugin *pos;

  for (pos = plugins_head; NULL != pos; pos = pos->next)
    if (NULL == pos->api->setup_monitor)
      GNUNET_break (0);
    else
      pos->api->setup_monitor (pos->api->cls,
			       cb, cb_cls);
}


/* end of file gnunet-service-transport_plugins.c */

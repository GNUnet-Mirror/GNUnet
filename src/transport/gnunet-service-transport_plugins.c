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
// static struct TransportPlugin *plugins_tail;



/**
 * Load and initialize all plugins.  The respective functions will be
 * invoked by the plugins when the respective events happen.  The
 * closure will be set to a 'const char*' containing the name of the
 * plugin that caused the call.
 *
 * @param recv_cb function to call when data is received
 * @param address_cb function to call when our public addresses changed
 * @param traffic_cb function to call for flow control
 * @param session_end_cb function to call when a session was terminated
 * @param cost_cb function to call about ATS cost changes
 */
void 
GST_plugins_load (GNUNET_TRANSPORT_PluginReceiveCallback recv_cb,
		  GNUNET_TRANSPORT_AddressNotification address_cb,
		  GNUNET_TRANSPORT_TrafficReport traffic_cb,
		  GNUNET_TRANSPORT_SessionEnd session_end_cb,
		  GNUNET_TRANSPORT_CostReport cost_cb)
{
#if 0
  struct TransportPlugin *plug;
  char *libname;

  /* load plugins... */
  no_transports = 1;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (c,
                                             "TRANSPORT", "PLUGINS", &plugs))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Starting transport plugins `%s'\n"), plugs);
      pos = strtok (plugs, " ");
      while (pos != NULL)
        {
	  
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Loading `%s' transport plugin\n"), name);
	  GNUNET_asprintf (&libname, "libgnunet_plugin_transport_%s", name);
	  plug = GNUNET_malloc (sizeof (struct TransportPlugin));
	  plug->short_name = GNUNET_strdup (name);
	  plug->lib_name = libname;
	  plug->env.cfg = cfg;
	  plug->env.my_identity = &my_identity;
	  plug->env.our_hello = &our_hello;
	  plug->env.cls = plug->short_name;
	  plug->env.receive = &plugin_env_receive;
	  plug->env.notify_address = &plugin_env_notify_address;
	  plug->env.session_end = &plugin_env_session_end;
	  plug->env.max_connections = max_connect_per_transport;
	  plug->env.stats = stats;
	  plug->next = plugins;
	  plugins = plug;
	  plug->api = GNUNET_PLUGIN_load (libname, &plug->env);
	  if (plug->api == NULL)
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			  _("Failed to load transport plugin for `%s'\n"), name);
	      GNUNET_free (plug->short_name);
	      plugins = plug->next;
	      GNUNET_free (libname);
	      GNUNET_free (plug);
	    }
          start_transport (server, pos);
          no_transports = 0;
          pos = strtok (NULL, " ");
        }
      GNUNET_free (plugs);
    }
#endif
}


/**
 * Unload all plugins
 */
void
GST_plugins_unload ()
{
#if 0
  while (NULL != (plug = plugins))
    {
      if (plug->address_update_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (plug->address_update_task);
	  plug->address_update_task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
      GNUNET_free (plug->lib_name);
      GNUNET_free (plug->short_name);
      while (NULL != (al = plug->addresses))
        {
          plug->addresses = al->next;
          GNUNET_free (al);
        }
      plugins = plug->next;
      GNUNET_free (plug);
    }
#endif
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
 * @param name plugin name
 * @param addr binary address in plugin-specific format
 * @param addrlen number of bytes in 'addr'
 * @return statically allocated (!) human-readable address
 */
const char *
GST_plugins_a2s (const char *name,
		 const void *addr,
		 size_t addrlen)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api;

  if (name == NULL)
    return NULL;
  api = GST_plugins_find (name);
  if ( (api == NULL) || (addrlen == 0) || (addr == NULL) )
    return NULL;
  return api->address_to_string (NULL,
				 addr,
				 addrlen);
}


/* end of file gnunet-service-transport_plugins.c */

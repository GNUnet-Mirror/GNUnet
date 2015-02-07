/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_plugins.h
 * @brief plugin management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_PLUGINS_H
#define GNUNET_SERVICE_TRANSPORT_PLUGINS_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"


/**
 * Load and initialize all plugins.  The respective functions will be
 * invoked by the plugins when the respective events happen.  The
 * closure will be set to a 'const char*' containing the name of the
 * plugin that caused the call.
 *
 * @param recv_cb function to call when data is received
 * @param register_quota_cb function to call to register a quota callback
 * @param unregister_quota_cb function to call to unregister a quota callback
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
                  GNUNET_TRANSPORT_UpdateAddressMetrics metric_update_cb);

/**
 * Unload all plugins
 */
void
GST_plugins_unload (void);


/**
 * Obtain the plugin API based on a plugin name.
 *
 * @param name name of the plugin
 * @return the plugin's API, NULL if the plugin is not loaded
 */
struct GNUNET_TRANSPORT_PluginFunctions *
GST_plugins_find (const char *name);


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
GST_plugins_printer_find (const char *name);


/**
 * Convert a given address to a human-readable format.  Note that the
 * return value will be overwritten on the next call to this function.
 *
 * @param address address to convert
 * @return statically allocated (!) human-readable address
 */
const char *
GST_plugins_a2s (const struct GNUNET_HELLO_Address *address);


/**
 * Register callback with all plugins to monitor their status.
 *
 * @param cb callback to register, NULL to unsubscribe
 * @param cb_cls closure for @a cb
 */
void
GST_plugins_monitor_subscribe (GNUNET_TRANSPORT_SessionInfoCallback cb,
			       void *cb_cls);


#endif
/* end of file gnunet-service-transport_plugins.h */

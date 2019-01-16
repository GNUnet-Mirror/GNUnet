/*
   This file is part of GNUnet.
   Copyright (C) 2012-2018 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file gns/plugin_rest_copying.c
 * @brief REST plugin that serves licensing information.
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include <gnunet_rest_lib.h>

#define GNUNET_REST_API_NS_COPYING "/copying"

#define GNUNET_REST_COPYING_TEXT "GNU Affero General Public License version 3 or later. See also: <http://www.gnu.org/licenses/>"

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct RequestHandle
{
  /**
   * Handle to rest request
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * HTTP response code
   */
  int response_code;

};


/**
 * Cleanup request handle.
 *
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  GNUNET_free (handle);
}


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
}


/**
 * Handle rest request
 *
 * @param handle the lookup handle
 */
static void
get_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char* url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  resp = GNUNET_REST_create_response (GNUNET_REST_COPYING_TEXT);
  handle->proc (handle->proc_cls,
                resp,
                MHD_HTTP_OK);
  cleanup_handle (handle);
}



/**
 * Handle rest request
 *
 * @param handle the lookup handle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char* url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp,
                           "Access-Control-Allow-Methods",
                           MHD_HTTP_METHOD_GET);
  handle->proc (handle->proc_cls,
                resp,
                MHD_HTTP_OK);
  cleanup_handle (handle);
}


/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK if request accepted
 */
static void
rest_copying_process_request (struct GNUNET_REST_RequestHandle *conndata_handle,
                              GNUNET_REST_ResultProcessor proc,
                              void *proc_cls)
{
  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_COPYING, &get_cont},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_COPYING, &options_cont},
    GNUNET_REST_HANDLER_END
  };
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;

  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = conndata_handle;

  if (GNUNET_NO == GNUNET_REST_handle_request (conndata_handle,
                                               handlers,
                                               &err,
                                               handle))
  {
    handle->response_code = err.error_code;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
  }
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_copying_init (void *cls)
{
  static struct Plugin plugin;
  cfg = cls;
  struct GNUNET_REST_Plugin *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_COPYING;
  api->process_request = &rest_copying_process_request;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("COPYING REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_copying_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "COPYING REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_copying.c */

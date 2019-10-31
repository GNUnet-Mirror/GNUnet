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
 * @file gns/plugin_rest_config.c
 * @brief REST plugin for configuration
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include <gnunet_rest_lib.h>
#include <gnunet_util_lib.h>
#include <jansson.h>

#define GNUNET_REST_API_NS_CONFIG "/config"

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

  /**
   * The URL
   */
  char *url;
};


/**
 * Cleanup request handle.
 *
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->url)
    GNUNET_free (handle->url);
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


static void
add_sections (void *cls,
              const char *section,
              const char *option,
              const char *value)
{
  json_t *sections_obj = cls;
  json_t *sec_obj;

  sec_obj = json_object_get (sections_obj, section);
  if (NULL != sec_obj)
  {
    json_object_set_new (sec_obj, option, json_string (value));
    return;
  }
  sec_obj = json_object ();
  json_object_set_new (sec_obj, option, json_string (value));
  json_object_set_new (sections_obj, section, sec_obj);
}


static void
add_section_contents (void *cls,
                      const char *section,
                      const char *option,
                      const char *value)
{
  json_t *section_obj = cls;

  json_object_set_new (section_obj, option, json_string (value));
}


/**
 * Handle rest request
 *
 * @param handle the lookup handle
 */
static void
get_cont (struct GNUNET_REST_RequestHandle *con_handle,
          const char *url,
          void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;
  const char *section;
  char *response;
  json_t *result;

  if (strlen (GNUNET_REST_API_NS_CONFIG) > strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (strlen (GNUNET_REST_API_NS_CONFIG) == strlen (handle->url))
  {
    result = json_object ();
    GNUNET_CONFIGURATION_iterate (cfg, &add_sections, result);
  }
  else
  {
    result = json_object ();
    section = &handle->url[strlen (GNUNET_REST_API_NS_CONFIG) + 1];
    GNUNET_CONFIGURATION_iterate_section_values (cfg,
                                                 section,
                                                 &add_section_contents,
                                                 result);
  }
  response = json_dumps (result, 0);
  resp = GNUNET_REST_create_response (response);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  GNUNET_free (response);
  json_decref (result);
}


struct GNUNET_CONFIGURATION_Handle *
set_value (struct GNUNET_CONFIGURATION_Handle *config,
           const char *section,
           const char *option,
           json_t *value)
{
  if (json_is_string (value))
    GNUNET_CONFIGURATION_set_value_string (config, section, option,
                                           json_string_value (value));
  else if (json_is_number (value))
    GNUNET_CONFIGURATION_set_value_number (config, section, option,
                                           json_integer_value (value));
  else if (json_is_null (value))
    GNUNET_CONFIGURATION_set_value_string (config, section, option, NULL);
  else if (json_is_true (value))
    GNUNET_CONFIGURATION_set_value_string (config, section, option, "yes");
  else if (json_is_false (value))
    GNUNET_CONFIGURATION_set_value_string (config, section, option, "no");
  else
    return NULL;
  return config; // for error handling (0 -> success, 1 -> error)
}


/**
 * Handle REST POST request
 *
 * @param handle the lookup handle
 */
static void
set_cont (struct GNUNET_REST_RequestHandle *con_handle,
          const char *url,
          void *cls)
{
  struct RequestHandle *handle = cls;
  char term_data[handle->rest_handle->data_size + 1];
  struct GNUNET_CONFIGURATION_Handle *out = GNUNET_CONFIGURATION_dup (cfg);

  json_error_t err;
  json_t *data_json;
  const char *section;
  const char *option;
  json_t *sec_obj;
  json_t *value;
  char *cfg_fn;

  // invalid url
  if (strlen (GNUNET_REST_API_NS_CONFIG) > strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // extract data from handle
  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);

  if (NULL == data_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSON Object from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // POST /config => {<section> : {<option> : <value>}}
  if (strlen (GNUNET_REST_API_NS_CONFIG) == strlen (handle->url))   // POST /config
  {
    // iterate over sections
    json_object_foreach (data_json, section, sec_obj)
    {
      // iterate over options
      json_object_foreach (sec_obj, option, value)
      {
        out = set_value (out, section, option, value);
        if (NULL == out)
        {
          handle->response_code = MHD_HTTP_BAD_REQUEST;
          GNUNET_SCHEDULER_add_now (&do_error, handle);
          json_decref (data_json);
          return;
        }
      }
    }
  }
  else // POST /config/<section> => {<option> : <value>}
  {
    // extract the "<section>" part from the url
    section = &handle->url[strlen (GNUNET_REST_API_NS_CONFIG) + 1];
    // iterate over options
    json_object_foreach (data_json, option, value)
    {
      out = set_value (out, section, option, value);
      if (NULL == out)
      {
        handle->response_code = MHD_HTTP_BAD_REQUEST;
        GNUNET_SCHEDULER_add_now (&do_error, handle);
        json_decref (data_json);
        return;
      }
    }
  }
  json_decref (data_json);


  // get cfg file path
  cfg_fn = NULL;
  const char *xdg = getenv ("XDG_CONFIG_HOME");
  if (NULL != xdg)
    GNUNET_asprintf (&cfg_fn,
                     "%s%s%s",
                     xdg,
                     DIR_SEPARATOR_STR,
                     GNUNET_OS_project_data_get ()->config_file);
  else
    cfg_fn = GNUNET_strdup (GNUNET_OS_project_data_get ()->user_config_file);

  GNUNET_CONFIGURATION_write (out, cfg_fn);
  cfg = out;
  handle->proc (handle->proc_cls,
                GNUNET_REST_create_response (NULL),
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
              const char *url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp,
                           "Access-Control-Allow-Methods",
                           MHD_HTTP_METHOD_GET);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
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
rest_config_process_request (struct GNUNET_REST_RequestHandle *conndata_handle,
                             GNUNET_REST_ResultProcessor proc,
                             void *proc_cls)
{
  static const struct GNUNET_REST_RequestHandler handlers[] = {
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_CONFIG, &get_cont },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_CONFIG, &set_cont },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_CONFIG, &options_cont },
    GNUNET_REST_HANDLER_END
  };
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;

  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = conndata_handle;
  handle->url = GNUNET_strdup (conndata_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';

  if (GNUNET_NO ==
      GNUNET_REST_handle_request (conndata_handle, handlers, &err, handle))
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
libgnunet_plugin_rest_config_init (void *cls)
{
  static struct Plugin plugin;

  cfg = cls;
  struct GNUNET_REST_Plugin *api;

  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_CONFIG;
  api->process_request = &rest_config_process_request;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("CONFIG REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_config_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CONFIG REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_config.c */

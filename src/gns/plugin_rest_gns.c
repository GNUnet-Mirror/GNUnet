/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 Christian Grothoff (and other contributing authors)

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
 * @author Martin Schanzenbach
 * @file gns/plugin_rest_gns.c
 * @brief GNUnet GNS REST plugin
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include <gnunet_dnsparser_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>
#include <jansson.h>

#define API_NAMESPACE "gns"

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct LookupHandle
{
  /**
   * Handle to GNS service.
   */
  struct GNUNET_GNS_Handle *gns;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Handle to lookup request
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Lookup an ego with the identity service.
   */
  struct GNUNET_IDENTITY_EgoLookup *el;

  /**
   * Handle for identity service.
   */
  struct GNUNET_IDENTITY_Handle *identity;

  /**
   * Active operation on identity service.
   */
  struct GNUNET_IDENTITY_Operation *id_op;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;    

  /**
   * The root of the received JSON or NULL
   */
  json_t *json_root;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The name to look up
   */
  char *name;

  /**
   * The ego to use
   * In string representation from JSON
   */
  const char *ego_str;

  /**
   * The Pkey to use
   * In stirng representation from JSON
   */
  const char *pkey_str;

  /**
   * The record type to look up
   */
  int type;

  /**
   * The public key of to use for lookup
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  /**
   * The public key to use for lookup
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkeym;

  /**
   * The resolver options
   */
  enum GNUNET_GNS_LocalOptions options;

  /**
   * the shorten key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey shorten_key;

};

/**
 * Cleanup lookup handle
 * @praram handle Handle to clean up
 */
void
cleanup_handle (struct LookupHandle *handle)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->json_root)
    json_decref (handle->json_root);

  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (handle->el);
    handle->el = NULL;
  }
  if (NULL != handle->id_op)
  {
    GNUNET_IDENTITY_cancel (handle->id_op);
    handle->id_op = NULL;
  }
  if (NULL != handle->lookup_request)
  {
    GNUNET_GNS_lookup_cancel (handle->lookup_request);
    handle->lookup_request = NULL;
  }
  if (NULL != handle->identity)
  {
    GNUNET_IDENTITY_disconnect (handle->identity);
    handle->identity = NULL;
  }
  if (NULL != handle->gns)
  {
    GNUNET_GNS_disconnect (handle->gns);
    handle->gns = NULL;
  }

  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  }
  GNUNET_free (handle);
}


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_error (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LookupHandle *handle = cls;
  handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
  cleanup_handle (handle);
}

/**
 * Function called with the result of a GNS lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param rd_count number of records returned
 * @param rd array of @a rd_count records with the results
 */
static void
process_lookup_result (void *cls, uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct LookupHandle *handle = cls;
  uint32_t i;
  const char *typename;
  char *string_val;
  char *result;
  const char *exp_str;
  json_t *result_root;
  json_t *result_name;
  json_t *result_array;
  json_t *record_obj;

  result_root = json_object();
  result_name = json_string (handle->name);
  result_array = json_array();
  json_object_set (result_root, "name", result_name);
  json_decref (result_name);
  handle->lookup_request = NULL;

  for (i=0; i<rd_count; i++)
  {
    if ( (rd[i].record_type != handle->type) &&
         (GNUNET_GNSRECORD_TYPE_ANY != handle->type) )
      continue;
    typename = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    string_val = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                   rd[i].data,
                                                   rd[i].data_size);
    if (NULL == string_val)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Record %u of type %d malformed, skipping\n",
                  (unsigned int) i,
                  (int) rd[i].record_type);
      continue;
    }
    else
    {
      record_obj = json_object();
      json_object_set_new (record_obj, "type", json_string (typename));
      json_object_set_new (record_obj, "value", json_string (string_val));

      if (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION & rd[i].flags)
      {
        struct GNUNET_TIME_Relative time_rel;
        time_rel.rel_value_us = rd[i].expiration_time;
        exp_str = GNUNET_STRINGS_relative_time_to_string (time_rel, 1);
      }
      else
      {
        struct GNUNET_TIME_Absolute time_abs;
        time_abs.abs_value_us = rd[i].expiration_time;
        exp_str = GNUNET_STRINGS_absolute_time_to_string (time_abs);
      }
      json_object_set_new (record_obj, "expiration_time", json_string (exp_str));

      json_object_set_new (record_obj, "expired",
                           json_boolean (GNUNET_YES == GNUNET_GNSRECORD_is_expired (&(rd[i]))));

      json_array_append (result_array, record_obj);
      json_decref (record_obj);
    }
    GNUNET_free (string_val);
  }
  json_object_set (result_root, "query_result", result_array);
  json_decref (result_array);
  result = json_dumps (result_root, JSON_COMPACT);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result);
  json_decref (result_root);
  handle->proc (handle->proc_cls, result, strlen (result), GNUNET_OK);
  GNUNET_free (result);
  cleanup_handle (handle);
}

/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key and the shorten zone.
 *
 * @param pkey public key to use for the zone, can be NULL
 * @param shorten_key private key used for shortening, can be NULL
 */
static void
lookup_with_keys (struct LookupHandle *handle, const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_key)
{
  if (UINT32_MAX == handle->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Invalid typename specified, assuming `ANY'\n"));
    handle->type = GNUNET_GNSRECORD_TYPE_ANY;
  }
  if (NULL != handle->name)
  {
    handle->lookup_request = GNUNET_GNS_lookup (handle->gns,
                                                handle->name,
                                                &handle->pkey,
                                                handle->type,
                                                handle->options,
                                                shorten_key,
                                                &process_lookup_result,
                                                handle);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Please specify name to lookup!\n"));
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
}

/**
 * Method called to with the ego we are to use for shortening
 * during the lookup.
 *
 * @param cls closure contains the public key to use
 * @param ego ego handle, NULL if not found
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_shorten_cb (void *cls,
                     struct GNUNET_IDENTITY_Ego *ego,
                     void **ctx,
                     const char *name)
{
  struct LookupHandle *handle = cls;

  handle->id_op = NULL;
  if (NULL == ego)
    lookup_with_keys (handle, NULL);
  else
    lookup_with_keys (handle,
                      GNUNET_IDENTITY_ego_get_private_key (ego));
}

/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key.
 *
 * @param pkey public key to use for the zone
 */
static void
lookup_with_public_key (struct LookupHandle *handle)
{
  handle->pkeym = handle->pkey;
  GNUNET_break (NULL == handle->id_op);
  handle->id_op = GNUNET_IDENTITY_get (handle->identity,
                                       "gns-short",
                                       &identity_shorten_cb,
                                       handle);
  if (NULL == handle->id_op)
  {
    GNUNET_break (0);
    lookup_with_keys (handle, NULL);
  }
}

/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is determined by a name.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 */
static void
identity_zone_cb (void *cls,
                  const struct GNUNET_IDENTITY_Ego *ego)
{
  struct LookupHandle *handle = cls;

  handle->el = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Ego for not found, cannot perform lookup.\n"));
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  else
  {
    GNUNET_IDENTITY_ego_get_public_key (ego, &handle->pkey);
    lookup_with_public_key (handle);
  }
  json_decref(handle->json_root);
}

/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is the one for the default master zone.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_master_cb (void *cls,
                    struct GNUNET_IDENTITY_Ego *ego,
                    void **ctx,
                    const char *name)
{
  const char *dot;
  struct LookupHandle *handle = cls;

  handle->id_op = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Ego for `gns-master' not found, cannot perform lookup.  Did you run gnunet-gns-import.sh?\n"));
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego, &handle->pkey);
  /* main name is our own master zone, do no look for that in the DHT */
  handle->options = GNUNET_GNS_LO_LOCAL_MASTER;
  /* if the name is of the form 'label.gnu', never go to the DHT */
  dot = NULL;
  if (NULL != handle->name)
    dot = strchr (handle->name, '.');
  if ( (NULL != dot) &&
       (0 == strcasecmp (dot, ".gnu")) )
    handle->options = GNUNET_GNS_LO_NO_DHT;
  lookup_with_public_key (handle);
}

/**
 * Parse REST uri for name and record type
 *
 * @param url Url to parse
 * @param handle lookup handle to populate
 * @return GNUNET_SYSERR on error
 */
int
parse_url (const char *url, struct LookupHandle *handle)
{
  char *name;
  char *type;
  char tmp_url[strlen(url)+1];
  char *tok;

  strcpy (tmp_url, url);
  tok = strtok ((char*)tmp_url, "/");
  if (NULL == tok)
    return GNUNET_SYSERR;
  name = strtok (NULL, "/");
  if (NULL == name)
    return GNUNET_SYSERR;
  GNUNET_asprintf (&handle->name,
                   "%s",
                   name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got name: %s\n", handle->name);
  type = strtok (NULL, "/");
  if (NULL == type)
  {
    handle->type = GNUNET_GNSRECORD_TYPE_ANY;
    return GNUNET_OK;
  }
  handle->type = GNUNET_GNSRECORD_typename_to_number (type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got type: %s\n", type);   
  return GNUNET_OK;
}

/**
 * Parse json from REST request
 *
 * @param data REST data
 * @param data_size data size
 * @param handle Handle to populate
 * @return GNUNET_SYSERR on error
 */
int
parse_json (const char *data, size_t data_size, struct LookupHandle *handle)
{
  json_error_t error;
  json_t *pkey_json;
  json_t *ego_json;
  json_t *options_json;

  char term_data[data_size+1];
  term_data[data_size] = '\0';

  memcpy (term_data, data, data_size);

  handle->json_root = json_loads (term_data, 0, &error);

  if (NULL == handle->json_root)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, error.text);
    return GNUNET_SYSERR;
  }

  if(!json_is_object(handle->json_root))
  {
    return GNUNET_SYSERR;
  }

  ego_json = json_object_get (handle->json_root, "ego");

  if(json_is_string(ego_json))
  {
    handle->ego_str = json_string_value (ego_json);
  }

  pkey_json = json_object_get (handle->json_root, "pkey");
  if(json_is_string(pkey_json))
  {
    handle->pkey_str = json_string_value (pkey_json);
  }

  options_json = json_object_get (handle->json_root, "options");
  if(json_is_integer (options_json))
  {
    handle->options = json_integer_value (options_json);
  }
  return GNUNET_OK;
}


/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for callback function
 * @return GNUNET_OK if request accepted
 */
void
rest_gns_process_request(const char *method,
                         const char *url,
                         const char *data,
                         size_t data_size,
                         GNUNET_REST_ResultProcessor proc,
                         void *proc_cls)
{
  struct LookupHandle *handle = GNUNET_new (struct LookupHandle);
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;

  //parse name and type from url
  if (GNUNET_OK != parse_url (url, handle))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error parsing url...\n");
    proc (proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  handle->proc_cls = proc_cls;
  handle->proc = proc;
  if (0 < data_size)
  {
    if (GNUNET_OK != parse_json (data, data_size, handle))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error parsing json...\n");
      proc (proc_cls, NULL, 0, GNUNET_SYSERR);
      cleanup_handle (handle);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting...\n");
  handle->gns = GNUNET_GNS_connect (cfg);
  handle->identity = GNUNET_IDENTITY_connect (cfg, NULL, NULL);
  handle->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                                       &do_error, handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected\n");

  if (NULL == handle->gns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connecting to GNS failed\n");
    proc (proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  if (NULL != handle->pkey_str)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (handle->pkey_str,
                                                    strlen(handle->pkey_str),
                                                    &(handle->pkey)))
    {
      proc (proc_cls, NULL, 0, GNUNET_SYSERR);
      cleanup_handle (handle);
      return;
    }
    lookup_with_public_key (handle);

  }
  if (NULL != handle->ego_str)
  {
    handle->el = GNUNET_IDENTITY_ego_lookup (cfg,
                                             handle->ego_str,
                                             &identity_zone_cb,
                                             handle);
    return;
  }
  if ( (NULL != handle->name) &&
       (strlen (handle->name) > 4) &&
       (0 == strcmp (".zkey",
                     &handle->name[strlen (handle->name) - 4])) )
  {
    /* no zone required, use 'anonymous' zone */
    GNUNET_CRYPTO_ecdsa_key_get_public
      (GNUNET_CRYPTO_ecdsa_key_get_anonymous (),
       &(handle->pkey));
    lookup_with_public_key (handle);
  }
  else
  {
    GNUNET_break (NULL == handle->id_op);
    handle->id_op = GNUNET_IDENTITY_get (handle->identity,
                                         "gns-master",
                                         &identity_master_cb,
                                         handle);
    GNUNET_assert (NULL != handle->id_op);
  }
}

/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_gns_init (void *cls)
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
  api->name = API_NAMESPACE;
  api->process_request = &rest_gns_process_request;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("GNS REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namestore_sqlite_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_gns.c */

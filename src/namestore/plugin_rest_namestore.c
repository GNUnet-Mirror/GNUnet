/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
   */
/**
 * @author Martin Schanzenbach
 * @file namestore/plugin_rest_namestore.c
 * @brief GNUnet Namestore REST plugin
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_jsonapi_lib.h"
#include "gnunet_jsonapi_util.h"
#include "microhttpd.h"
#include <jansson.h>

#define GNUNET_REST_API_NS_NAMESTORE "/names"

#define GNUNET_REST_API_NS_NAMESTORE_ZKEY "/names/zkey"

#define GNUNET_REST_JSONAPI_NAMESTORE_TYPEINFO "record"

#define GNUNET_REST_JSONAPI_NAMESTORE_NAME "name"

#define GNUNET_REST_JSONAPI_NAMESTORE_REVINFO "revinfo"

#define GNUNET_REST_JSONAPI_NAMESTORE_RECORD GNUNET_REST_JSONAPI_NAMESTORE_TYPEINFO

#define GNUNET_REST_JSONAPI_NAMESTORE_RECORD_TYPE "record_type"

#define GNUNET_REST_JSONAPI_NAMESTORE_VALUE "value"

#define GNUNET_REST_JSONAPI_NAMESTORE_PUBLIC "public"

#define GNUNET_REST_JSONAPI_NAMESTORE_SHADOW "shadow"

#define GNUNET_REST_JSONAPI_NAMESTORE_PKEY "pkey"

#define GNUNET_REST_JSONAPI_NAMESTORE_ZKEY "zkey"

#define GNUNET_REST_JSONAPI_NAMESTORE_EXPIRATION "expiration"

#define GNUNET_REST_JSONAPI_NAMESTORE_EGO "ego"

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};


/**
 * HTTP methods allows for this plugin
 */
static char* allow_methods;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct RecordEntry
{
  /**
   * DLL
   */
  struct RecordEntry *next;

  /**
   * DLL
   */
  struct RecordEntry *prev;

};

struct RequestHandle
{
  /**
   * Ego list
   */
  struct RecordEntry *record_head;

  /**
   * Ego list
   */
  struct record_entry *record_tail;

  /**
   * JSON response object
   */
  struct GNUNET_JSONAPI_Document *resp_object;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Handle to GNS service.
   */
  struct GNUNET_IDENTITY_Handle *identity_handle;

  /**
   * Handle to NAMESTORE
   */
  struct GNUNET_NAMESTORE_Handle *ns_handle;

  /**
   * Handle to NAMESTORE it
   */
  struct GNUNET_NAMESTORE_ZoneIterator *list_it;

  /**
   * Private key for the zone
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone_pkey;

  /**
   * Handle to identity lookup
   */
  struct GNUNET_IDENTITY_EgoLookup *ego_lookup;

  /**
   * Default Ego operation
   */
  struct GNUNET_IDENTITY_Operation *get_default;

  /**
   * Name of the ego
   */
  char *ego_name;

  /**
   * Record is public
   */
  int is_public;

  /**
   * Shadow record
   */
  int is_shadow;

  /**
   * Name of the record to modify
   */
  char *name;

  /**
   * Value of the record
   */
  char *value;

  /**
   * Zkey string
   */
  const char* zkey_str;

  /**
   * record type
   */
  uint32_t type;

  /**
   * Records to store
   */
  struct GNUNET_GNSRECORD_Data *rd;

  /**
   * record count
   */
  unsigned int rd_count;

  /**
   * NAMESTORE Operation
   */
  struct GNUNET_NAMESTORE_QueueEntry *add_qe;

  /**
   * NAMESTORE Operation
   */
  struct GNUNET_NAMESTORE_QueueEntry *reverse_qe;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The url
   */
  char *url;

  /**
   * Cfg
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * HTTP response code
   */
  int response_code;

};


/**
 * Cleanup lookup handle
 *
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  struct RecordEntry *record_entry;
  struct RecordEntry *record_tmp;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->resp_object)
    GNUNET_JSONAPI_document_delete (handle->resp_object);
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->ego_lookup)
    GNUNET_IDENTITY_ego_lookup_cancel (handle->ego_lookup);
  if (NULL != handle->get_default)
    GNUNET_IDENTITY_cancel (handle->get_default);
  if (NULL != handle->list_it)
    GNUNET_NAMESTORE_zone_iteration_stop (handle->list_it);
  if (NULL != handle->add_qe)
    GNUNET_NAMESTORE_cancel (handle->add_qe);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);
  if (NULL != handle->ns_handle)
    GNUNET_NAMESTORE_disconnect (handle->ns_handle);
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->value)
    GNUNET_free (handle->value);
  if (NULL != handle->rd)
  {
    for (i = 0; i < handle->rd_count; i++)
    {
      if (NULL != handle->rd[i].data)
        GNUNET_free ((void*)handle->rd[i].data);
    }
    GNUNET_free (handle->rd);
  }
  if (NULL != handle->ego_name)
    GNUNET_free (handle->ego_name);
  for (record_entry = handle->record_head;
       NULL != record_entry;)
  {
    record_tmp = record_entry;
    record_entry = record_entry->next;
    GNUNET_free (record_tmp);
  }
  GNUNET_free (handle);
}


/**
 * Create json representation of a GNSRECORD
 *
 * @param rd the GNSRECORD_Data
 */
static json_t *
gnsrecord_to_json (const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *typename;
  char *string_val;
  const char *exp_str;
  json_t *record_obj;

  typename = GNUNET_GNSRECORD_number_to_typename (rd->record_type);
  string_val = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                                 rd->data,
                                                 rd->data_size);

  if (NULL == string_val)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Record of type %d malformed, skipping\n",
                (int) rd->record_type);
    return NULL;
  }
  record_obj = json_object();
  json_object_set_new (record_obj,
                       GNUNET_REST_JSONAPI_NAMESTORE_RECORD_TYPE,
                       json_string (typename));
  json_object_set_new (record_obj,
                       GNUNET_REST_JSONAPI_NAMESTORE_VALUE,
                       json_string (string_val));
  GNUNET_free (string_val);

  if (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION & rd->flags)
  {
    struct GNUNET_TIME_Relative time_rel;
    time_rel.rel_value_us = rd->expiration_time;
    exp_str = GNUNET_STRINGS_relative_time_to_string (time_rel, 1);
  }
  else
  {
    struct GNUNET_TIME_Absolute time_abs;
    time_abs.abs_value_us = rd->expiration_time;
    exp_str = GNUNET_STRINGS_absolute_time_to_string (time_abs);
  }
  json_object_set_new (record_obj, GNUNET_REST_JSONAPI_NAMESTORE_EXPIRATION, json_string (exp_str));

  json_object_set_new (record_obj, "expired",
                       json_boolean (GNUNET_YES == GNUNET_GNSRECORD_is_expired (rd)));
  return record_obj;
}


/**
 * Task run on error.  Generates error response and cleans up.
 *
 * @param cls the request to generate an error response for
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp = GNUNET_REST_create_response (NULL);

  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
}


/**
 * Task run on timeout.
 *
 * @param cls the request to time out
 */
static void
do_timeout (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->timeout_task = NULL;
  do_error (handle);
}


static void
cleanup_handle_delayed (void *cls)
{
  cleanup_handle (cls);
}


/**
 * Iteration over all results finished, build final
 * response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
namestore_list_finished (void *cls)
{
  struct RequestHandle *handle = cls;
  char *result;
  struct MHD_Response *resp;

  handle->list_it = NULL;
  if (NULL == handle->resp_object)
    handle->resp_object = GNUNET_JSONAPI_document_new ();

  if (GNUNET_SYSERR ==
      GNUNET_JSONAPI_document_serialize (handle->resp_object,
                                         &result))
  {
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error,
                              handle);
    return;
  }
  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls,
                resp,
                MHD_HTTP_OK);
  GNUNET_free_non_null (result);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed,
                            handle);
}



/**
 * Create a response with requested records
 *
 * @param handle the RequestHandle
 */
static void
namestore_list_response (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                         const char *rname,
                         unsigned int rd_len,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_JSONAPI_Resource *json_resource;
  json_t *result_array;
  json_t *record_obj;
  int i;

  if (NULL == handle->resp_object)
    handle->resp_object = GNUNET_JSONAPI_document_new ();

  if ( (NULL != handle->name) &&
       (0 != strcmp (handle->name, rname)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s does not match %s\n", rname, handle->name);
    GNUNET_NAMESTORE_zone_iterator_next (handle->list_it);
    return;
  }

  result_array = json_array ();
  for (i=0; i<rd_len; i++)
  {
    if ( (GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
         (0 != strcmp (rname, "+")) )
      continue;

    if ( (rd[i].record_type != handle->type) &&
         (GNUNET_GNSRECORD_TYPE_ANY != handle->type) )
      continue;
    record_obj = gnsrecord_to_json (&(rd[i]));
    json_array_append (result_array, record_obj);
    json_decref (record_obj);
  }

  if (0 < json_array_size(result_array))
  {
    json_resource = GNUNET_JSONAPI_resource_new (GNUNET_REST_JSONAPI_NAMESTORE_TYPEINFO,
                                                 rname);
    GNUNET_JSONAPI_resource_add_attr (json_resource,
                                      GNUNET_REST_JSONAPI_NAMESTORE_RECORD,
                                      result_array);
    GNUNET_JSONAPI_document_resource_add (handle->resp_object, json_resource);
  }

  json_decref (result_array);
  GNUNET_NAMESTORE_zone_iterator_next (handle->list_it);
}


static void
create_finished (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  handle->add_qe = NULL;
  if (GNUNET_YES != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error storing records%s%s\n",
                (NULL == emsg) ? "" : ": ",
                (NULL == emsg) ? "" : emsg);
    GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
    return;
  }
  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_NO_CONTENT);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


/**
 * We're storing a new record; this requires
 * that no record already exists
 *
 * @param cls closure, unused
 * @param zone_key private key of the zone
 * @param rec_name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
create_new_record_cont (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                        const char *rec_name,
                        unsigned int rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;

  handle->add_qe = NULL;
  if (0 != strcmp (rec_name, handle->name))
  {
    GNUNET_break (0);
    do_error (handle);
    return;
  }

  if (0 != rd_count)
  {
    handle->proc (handle->proc_cls,
                  GNUNET_REST_create_response (NULL),
                  MHD_HTTP_CONFLICT);
    GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
    return;
  }

  GNUNET_assert (NULL != handle->name);
  handle->add_qe = GNUNET_NAMESTORE_records_store (handle->ns_handle,
                                                   &handle->zone_pkey,
                                                   handle->name,
                                                   handle->rd_count,
                                                   handle->rd,
                                                   &create_finished,
                                                   handle);
}


static void
del_finished (void *cls,
              int32_t success,
              const char *emsg)
{
  struct RequestHandle *handle = cls;

  handle->add_qe = NULL;
  if (GNUNET_NO == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Deleting record failed, record does not exist%s%s\n"),
                (NULL != emsg) ? ": " : "",
                (NULL != emsg) ? emsg : "");
    GNUNET_SCHEDULER_add_now (&do_error, handle); //do_not_found TODO
    return;
  }
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Deleting record failed%s%s\n"),
                (NULL != emsg) ? ": " : "",
                (NULL != emsg) ? emsg : "");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls,
                GNUNET_REST_create_response (NULL),
                MHD_HTTP_NO_CONTENT);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


static void
del_cont (void *cls,
          const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
          const char *label,
          unsigned int rd_count,
          const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;

  handle->add_qe = NULL;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("There are no records under label `%s' that could be deleted.\n"),
                label);
    do_error (handle);
    return;
  }

  handle->add_qe = GNUNET_NAMESTORE_records_store (handle->ns_handle,
                                                   &handle->zone_pkey,
                                                   handle->name,
                                                   0, NULL,
                                                   &del_finished,
                                                   handle);
}


static void
namestore_delete_cont (struct GNUNET_REST_RequestHandle *con,
                       const char *url,
                       void *cls)
{
  struct RequestHandle *handle = cls;

  if (NULL == handle->name)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->add_qe = GNUNET_NAMESTORE_records_lookup (handle->ns_handle,
                                                    &handle->zone_pkey,
                                                    handle->name,
                                                    &do_error,
                                                    handle,
                                                    &del_cont,
                                                    handle);
}


static int
json_to_gnsrecord (const json_t *records_json,
                   struct GNUNET_GNSRECORD_Data **rd,
                   unsigned int *rd_count)
{
  struct GNUNET_TIME_Relative etime_rel;
  struct GNUNET_TIME_Absolute etime_abs;
  char *value;
  void *rdata;
  size_t rdata_size;
  const char *typestring;
  const char *expirationstring;
  int i;
  json_t *type_json;
  json_t *value_json;
  json_t *record_json;
  json_t *exp_json;

  *rd_count = json_array_size (records_json);
  *rd = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Data) * *rd_count);
  for (i = 0; i < *rd_count; i++)
  {
    memset (&((*rd)[i]), 0, sizeof (struct GNUNET_GNSRECORD_Data));
    record_json = json_array_get (records_json, i);
    type_json = json_object_get (record_json,
                                 GNUNET_REST_JSONAPI_NAMESTORE_RECORD_TYPE);
    if (!json_is_string (type_json))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Type property is no string\n");
      return GNUNET_SYSERR;
    }
    typestring = json_string_value (type_json);
    (*rd)[i].record_type = GNUNET_GNSRECORD_typename_to_number (typestring);
    if (UINT32_MAX == (*rd)[i].record_type)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Unsupported type `%s'\n"),
                  json_string_value (type_json));
      return GNUNET_SYSERR;
    }
    value_json = json_object_get (record_json,
                                  GNUNET_REST_JSONAPI_NAMESTORE_VALUE);
    if (!json_is_string (value_json))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Value property is no string\n");
      return GNUNET_SYSERR;
    }
    value = GNUNET_strdup (json_string_value (value_json));
    if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value ((*rd)[i].record_type,
                                                       value,
                                                       &rdata,
                                                       &rdata_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Value `%s' invalid for record type `%s'\n"),
                  value, typestring);
      return GNUNET_SYSERR;
    }
    (*rd)[i].data = rdata;
    (*rd)[i].data_size = rdata_size;
    /**TODO
     * if (1 == handle->is_shadow)
     rde->flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
     if (1 != handle->is_public)
     rde->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
     */
    exp_json = json_object_get (record_json,
                                GNUNET_REST_JSONAPI_NAMESTORE_EXPIRATION);
    if (!json_is_string (exp_json))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Expiration property is no string\n");
      return GNUNET_SYSERR;
    }
    expirationstring = json_string_value (exp_json);
    if (0 == strcmp (expirationstring, "never"))
    {
      (*rd)[i].expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
    }
    else if (GNUNET_OK ==
             GNUNET_STRINGS_fancy_time_to_relative (expirationstring,
                                                    &etime_rel))
    {
      (*rd)[i].expiration_time = etime_rel.rel_value_us;
      (*rd)[i].flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    }
    else if (GNUNET_OK ==
             GNUNET_STRINGS_fancy_time_to_absolute (expirationstring,
                                                    &etime_abs))
    {
      (*rd)[i].expiration_time = etime_abs.abs_value_us;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Value `%s' invalid for record type `%s'\n"),
                  value, typestring);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


static void
namestore_create_cont (struct GNUNET_REST_RequestHandle *con,
                       const char *url,
                       void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_JSONAPI_Document *json_obj;
  struct GNUNET_JSONAPI_Resource *json_res;
  json_t *records_json;
  json_t *data_js;
  json_error_t err;
  char term_data[handle->rest_handle->data_size+1];
  struct GNUNET_JSON_Specification docspec[] = {
    GNUNET_JSON_spec_jsonapi_document (&json_obj),
    GNUNET_JSON_spec_end()
  };

  if (strlen (GNUNET_REST_API_NS_NAMESTORE) != strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot create under %s\n", handle->url);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_js = json_loads (term_data,
                        JSON_DECODE_ANY,
                        &err);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (data_js, docspec,
                                    NULL, NULL));
  json_decref (data_js);
  if (NULL == json_obj)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSONAPI Object from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (1 != GNUNET_JSONAPI_document_resource_count (json_obj))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot create more than 1 resource! (Got %d)\n",
                GNUNET_JSONAPI_document_resource_count (json_obj));
    GNUNET_JSONAPI_document_delete (json_obj);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_res = GNUNET_JSONAPI_document_get_resource (json_obj, 0);
  if (GNUNET_NO == GNUNET_JSONAPI_resource_check_type (json_res,
                                                       GNUNET_REST_JSONAPI_NAMESTORE_RECORD))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unsupported JSON data type\n");
    GNUNET_JSONAPI_document_delete (json_obj);
    resp = GNUNET_REST_create_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_CONFLICT);
    cleanup_handle (handle);
    return;
  }
  handle->name = GNUNET_strdup (GNUNET_JSONAPI_resource_get_id (json_res));
  records_json = GNUNET_JSONAPI_resource_read_attr (json_res,
                                                    GNUNET_REST_JSONAPI_NAMESTORE_RECORD);
  if (NULL == records_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No records given\n");
    GNUNET_JSONAPI_document_delete (json_obj);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (GNUNET_SYSERR == json_to_gnsrecord (records_json, &handle->rd, &handle->rd_count))
  {
    GNUNET_JSONAPI_document_delete (json_obj);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_JSONAPI_document_delete (json_obj);

  handle->add_qe = GNUNET_NAMESTORE_records_lookup (handle->ns_handle,
                                                    &handle->zone_pkey,
                                                    handle->name,
                                                    &do_error,
                                                    handle,
                                                    &create_new_record_cont,
                                                    handle);
}


static void
namestore_zkey_response (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                         const char *label,
                         unsigned int rd_count,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_JSONAPI_Document *json_obj;
  struct GNUNET_JSONAPI_Resource *json_res;
  json_t *name_json;
  char* result;

  handle->reverse_qe = NULL;
  json_obj = GNUNET_JSONAPI_document_new ();
  if (NULL != label)
  {
    name_json = json_string (label);
    json_res = GNUNET_JSONAPI_resource_new (GNUNET_REST_JSONAPI_NAMESTORE_REVINFO,
                                            handle->zkey_str);
    GNUNET_JSONAPI_resource_add_attr (json_res,
                                      GNUNET_REST_JSONAPI_NAMESTORE_NAME,
                                      name_json);
    GNUNET_JSONAPI_document_resource_add (json_obj, json_res);
    json_decref (name_json);
  }
  //Handle response
  if (GNUNET_SYSERR == GNUNET_JSONAPI_document_serialize (json_obj, &result))
  {
    GNUNET_JSONAPI_document_delete (json_obj);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_JSONAPI_document_delete (json_obj);
  GNUNET_free (result);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


static void
namestore_zkey_cont (struct GNUNET_REST_RequestHandle *con,
                     const char *url,
                     void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode key;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_NAMESTORE_ZKEY,
                      strlen (GNUNET_REST_JSONAPI_NAMESTORE_ZKEY),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No zkey given %s\n", handle->url);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->zkey_str = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                        &key);
  if ((NULL == handle->zkey_str) ||
      (GNUNET_OK !=
       GNUNET_CRYPTO_ecdsa_public_key_from_string (handle->zkey_str,
                                                   strlen (handle->zkey_str),
                                                   &pubkey)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Zkey invalid %s\n", handle->zkey_str);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->reverse_qe = GNUNET_NAMESTORE_zone_to_name (handle->ns_handle,
                                                      &handle->zone_pkey,
                                                      &pubkey,
                                                      &do_error,
                                                      handle,
                                                      &namestore_zkey_response,
                                                      handle);
}


static void
namestore_info_cont (struct GNUNET_REST_RequestHandle *con,
                     const char *url,
                     void *cls)
{
  struct RequestHandle *handle = cls;

  handle->list_it = GNUNET_NAMESTORE_zone_iteration_start (handle->ns_handle,
                                                           &handle->zone_pkey,
                                                           &do_error,
                                                           handle,
                                                           &namestore_list_response,
                                                           handle,
                                                           &namestore_list_finished,
                                                           handle);
}


static char*
get_name_from_url (const char* url)
{
  if (strlen (url) <= strlen (GNUNET_REST_API_NS_NAMESTORE))
    return NULL;
  return (char*)url + strlen (GNUNET_REST_API_NS_NAMESTORE) + 1;
}

/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char* url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  //For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp,
                           "Access-Control-Allow-Methods",
                           allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
}


/**
 * Callback invoked from identity service with ego information.
 * An @a ego of NULL means the ego was not found.
 *
 * @param cls closure with the configuration
 * @param ego an ego known to identity service, or NULL
 */
static void
identity_cb (void *cls,
             const struct GNUNET_IDENTITY_Ego *ego)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_NAMESTORE_ZKEY, &namestore_zkey_cont}, //reverse
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_NAMESTORE, &namestore_info_cont}, //list
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_NAMESTORE, &namestore_create_cont}, //create
    //    {MHD_HTTP_METHOD_PUT, GNUNET_REST_API_NS_NAMESTORE, &namestore_edit_cont}, //update. TODO this shoul be PATCH
    {MHD_HTTP_METHOD_DELETE, GNUNET_REST_API_NS_NAMESTORE, &namestore_delete_cont}, //delete
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_NAMESTORE, &options_cont},
    GNUNET_REST_HANDLER_END
  };

  handle->ego_lookup = NULL;
  if (NULL == ego)
  {
    if (NULL != handle->ego_name)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Ego `%s' not known to identity service\n"),
                  handle->ego_name);
    }
    resp = GNUNET_REST_create_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_NOT_FOUND);
    cleanup_handle (handle);
    return;
  }
  handle->zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  handle->ns_handle = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == handle->ns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to namestore\n"));
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (GNUNET_OK !=
      GNUNET_JSONAPI_handle_request (handle->rest_handle,
                                     handlers,
                                     &err,
                                     handle))
  {
    handle->response_code = err.error_code;
    GNUNET_SCHEDULER_add_now (&do_error,
                              (void *) handle);
  }
}


static void
default_ego_cb (void *cls,
                struct GNUNET_IDENTITY_Ego *ego,
                void **ctx,
                const char *name)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  handle->get_default = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No default ego configured in identity service\n"));
    resp = GNUNET_REST_create_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_NOT_FOUND);
    cleanup_handle (handle);
    return;
  }
  else
  {
    identity_cb (cls, ego);
  }
}

static void
id_connect_cb (void *cls,
               struct GNUNET_IDENTITY_Ego *ego,
               void **ctx,
               const char *name)
{
  struct RequestHandle *handle = cls;
  if (NULL == ego)
  {
    handle->get_default = GNUNET_IDENTITY_get (handle->identity_handle,
                                               "namestore",
                                               &default_ego_cb, handle);
  }
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
 * @return #GNUNET_OK if request accepted
 */
static void
rest_identity_process_request(struct GNUNET_REST_RequestHandle *rest_handle,
                              GNUNET_REST_ResultProcessor proc,
                              void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct MHD_Response *resp;
  struct GNUNET_HashCode key;
  char *ego;
  char *name;
  char *type;

  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url)-1] == '/')
    handle->url[strlen (handle->url)-1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting...\n");
  handle->cfg = cfg;
  ego = NULL;
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_NAMESTORE_EGO,
                      strlen (GNUNET_REST_JSONAPI_NAMESTORE_EGO),
                      &key);
  if ( GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                               &key) )
  {
    ego = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                             &key);
  }

  handle->type = GNUNET_GNSRECORD_TYPE_ANY;
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_NAMESTORE_RECORD_TYPE,
                      strlen (GNUNET_REST_JSONAPI_NAMESTORE_RECORD_TYPE),
                      &key);
  if ( GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                               &key) )
  {
    type = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                              &key);
    if (NULL != type)
      handle->type = GNUNET_GNSRECORD_typename_to_number (type);
  }
  name = get_name_from_url (handle->url);
  if (NULL != ego)
    handle->ego_name = GNUNET_strdup (ego);
  if (NULL != name)
    handle->name = GNUNET_strdup (name);
  if (NULL == handle->ego_name)
  {
    handle->identity_handle = GNUNET_IDENTITY_connect (handle->cfg, &id_connect_cb, handle);
    if (NULL == handle->identity_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Cannot connect to identity service\n"));
      resp = GNUNET_REST_create_response (NULL);
      handle->proc (handle->proc_cls, resp, MHD_HTTP_NOT_FOUND);
      cleanup_handle (handle);
    }
    return;
  }
  handle->ego_lookup = GNUNET_IDENTITY_ego_lookup (cfg,
                                                   handle->ego_name,
                                                   &identity_cb,
                                                   handle);
  handle->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                                       &do_timeout,
                                                       handle);
}

/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_namestore_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_NAMESTORE;
  api->process_request = &rest_identity_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Namestore REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_namestore_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_free_non_null (allow_methods);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Namestore REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_namestore.c */

/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
 * @file json/json_gnsrecord.c
 * @brief JSON handling of GNS record data
 * @author Philippe Buschmann
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"

#define GNUNET_JSON_GNSRECORD_VALUE "value"
#define GNUNET_JSON_GNSRECORD_RECORD_DATA "data"
#define GNUNET_JSON_GNSRECORD_TYPE "record_type"
#define GNUNET_JSON_GNSRECORD_EXPIRATION_TIME "expiration_time"
#define GNUNET_JSON_GNSRECORD_FLAG "flag"
#define GNUNET_JSON_GNSRECORD_RECORD_NAME "record_name"
#define GNUNET_JSON_GNSRECORD_NEVER "never"

struct GnsRecordInfo
{
  char **name;

  unsigned int *rd_count;

  struct GNUNET_GNSRECORD_Data **rd;
};


static void
cleanup_recordinfo (struct GnsRecordInfo *gnsrecord_info)
{
  if (NULL != *(gnsrecord_info->rd))
  {
    for (int i = 0; i < *(gnsrecord_info->rd_count); i++)
    {
      if (NULL != (*(gnsrecord_info->rd))[i].data)
        GNUNET_free ((char *) (*(gnsrecord_info->rd))[i].data);
    }
    GNUNET_free (*(gnsrecord_info->rd));
    *(gnsrecord_info->rd) = NULL;
  }
  if (NULL != *(gnsrecord_info->name))
    GNUNET_free (*(gnsrecord_info->name));
  *(gnsrecord_info->name) = NULL;
}


/**
 * Parse given JSON object to gns record
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_record (json_t *data, struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_TIME_Absolute abs_expiration_time;
  struct GNUNET_TIME_Relative rel_expiration_time;
  const char *value;
  const char *record_type;
  const char *expiration_time;
  int flag;
  int unpack_state = 0;

  //interpret single gns record
  unpack_state = json_unpack (data,
                              "{s:s, s:s, s:s, s?:i!}",
                              GNUNET_JSON_GNSRECORD_VALUE,
                              &value,
                              GNUNET_JSON_GNSRECORD_TYPE,
                              &record_type,
                              GNUNET_JSON_GNSRECORD_EXPIRATION_TIME,
                              &expiration_time,
                              GNUNET_JSON_GNSRECORD_FLAG,
                              &flag);
  if (0 != unpack_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error gnsdata object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  rd->record_type = GNUNET_GNSRECORD_typename_to_number (record_type);
  if (UINT32_MAX == rd->record_type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unsupported type\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value (rd->record_type,
                                                     value,
                                                     (void**)&rd->data,
                                                     &rd->data_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Value invalid for record type\n");
    return GNUNET_SYSERR;
  }

  if (0 == strcmp (expiration_time, GNUNET_JSON_GNSRECORD_NEVER))
  {
    rd->expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  }
  else if (GNUNET_OK ==
           GNUNET_STRINGS_fancy_time_to_absolute (expiration_time,
                                                  &abs_expiration_time))
  {
    rd->expiration_time = abs_expiration_time.abs_value_us;
  }
  else if (GNUNET_OK ==
           GNUNET_STRINGS_fancy_time_to_relative (expiration_time,
                                                  &rel_expiration_time))
  {
    rd->expiration_time = rel_expiration_time.rel_value_us;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Expiration time invalid\n");
    return GNUNET_SYSERR;
  }
  rd->flags = (enum GNUNET_GNSRECORD_Flags) flag;
  return GNUNET_OK;
}


/**
 * Parse given JSON object to gns record
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_record_data (struct GnsRecordInfo *gnsrecord_info, json_t *data)
{
  GNUNET_assert (NULL != data);
  if (! json_is_array (data))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error gns record data JSON is not an array!\n");
    return GNUNET_SYSERR;
  }
  *(gnsrecord_info->rd_count) = json_array_size (data);
  *(gnsrecord_info->rd) = GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Data) *
                                         json_array_size (data));
  size_t index;
  json_t *value;
  json_array_foreach (data, index, value)
  {
    if (GNUNET_OK != parse_record (value, &(*(gnsrecord_info->rd))[index]))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static int
parse_gnsrecordobject (void *cls,
                       json_t *root,
                       struct GNUNET_JSON_Specification *spec)
{
  struct GnsRecordInfo *gnsrecord_info;
  int unpack_state = 0;
  const char *name;
  json_t *data;

  GNUNET_assert (NULL != root);
  if (! json_is_object (root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error record JSON is not an object!\n");
    return GNUNET_SYSERR;
  }
  //interpret single gns record
  unpack_state = json_unpack (root,
                              "{s:s, s:o!}",
                              GNUNET_JSON_GNSRECORD_RECORD_NAME,
                              &name,
                              GNUNET_JSON_GNSRECORD_RECORD_DATA,
                              &data);
  if (0 != unpack_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error namestore records object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  gnsrecord_info = (struct GnsRecordInfo *) spec->ptr;
  *(gnsrecord_info->name) = GNUNET_strdup (name);
  if (GNUNET_OK != parse_record_data (gnsrecord_info, data))
  {
    cleanup_recordinfo (gnsrecord_info);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing the record.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_gnsrecordobject (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GnsRecordInfo *gnsrecord_info = (struct GnsRecordInfo *) spec->ptr;
  GNUNET_free (gnsrecord_info);
}


/**
 * JSON Specification for GNS Records.
 *
 * @param gnsrecord_object struct of GNUNET_GNSRECORD_Data to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_gnsrecord (struct GNUNET_GNSRECORD_Data **rd,
                            unsigned int *rd_count,
                            char **name)
{
  struct GnsRecordInfo *gnsrecord_info = GNUNET_new (struct GnsRecordInfo);
  gnsrecord_info->rd = rd;
  gnsrecord_info->name = name;
  gnsrecord_info->rd_count = rd_count;
  struct GNUNET_JSON_Specification ret = {.parser = &parse_gnsrecordobject,
    .cleaner = &clean_gnsrecordobject,
    .cls = NULL,
    .field = NULL,
    .ptr = (struct GnsRecordInfo *)
      gnsrecord_info,
    .ptr_size = 0,
    .size_ptr = NULL};
  return ret;
}

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
#define GNUNET_JSON_GNSRECORD_TYPE "record_type"
#define GNUNET_JSON_GNSRECORD_EXPIRATION_TIME "expiration_time"
#define GNUNET_JSON_GNSRECORD_FLAG "flag"
#define GNUNET_JSON_GNSRECORD_RECORD_NAME "record_name"
#define GNUNET_JSON_GNSRECORD_NEVER "never"


/**
 * Parse given JSON object to gns record
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_gnsrecordobject (void *cls,
		       json_t *root,
		       struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_GNSRECORD_Data *gnsrecord_object;
  struct GNUNET_TIME_Absolute abs_expiration_time;
  int unpack_state=0;
  const char *value;
  const char *expiration_time;
  const char *record_type;
  const char *name;
  int flag;
  void *rdata = NULL;
  size_t rdata_size;

  GNUNET_assert(NULL != root);
  if(!json_is_object(root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Error json is not array nor object!\n");
    return GNUNET_SYSERR;
  }
  //interpret single gns record
  unpack_state = json_unpack(root,
			     "{s:s, s:s, s:s, s?:i, s:s!}",
			     GNUNET_JSON_GNSRECORD_VALUE, &value,
			     GNUNET_JSON_GNSRECORD_TYPE, &record_type,
			     GNUNET_JSON_GNSRECORD_EXPIRATION_TIME, &expiration_time,
			     GNUNET_JSON_GNSRECORD_FLAG, &flag,
			     GNUNET_JSON_GNSRECORD_RECORD_NAME, &name);
  if (0 != unpack_state)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
	       "Error json object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  gnsrecord_object = GNUNET_new (struct GNUNET_GNSRECORD_Data);
  gnsrecord_object->record_type = GNUNET_GNSRECORD_typename_to_number(record_type);
  if (UINT32_MAX == gnsrecord_object->record_type)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,"Unsupported type\n");
    GNUNET_free(gnsrecord_object);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK
      != GNUNET_GNSRECORD_string_to_value (gnsrecord_object->record_type,
					   value,
					   &rdata,
					   &rdata_size))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,"Value invalid for record type\n");
    GNUNET_free(gnsrecord_object);
    return GNUNET_SYSERR;
  }

  gnsrecord_object->data = rdata;
  gnsrecord_object->data_size = rdata_size;

  if (0 == strcmp (expiration_time, GNUNET_JSON_GNSRECORD_NEVER))
  {
    gnsrecord_object->expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  }
  else if (GNUNET_OK
      == GNUNET_STRINGS_fancy_time_to_absolute (expiration_time,
						&abs_expiration_time))
  {
    gnsrecord_object->expiration_time = abs_expiration_time.abs_value_us;
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Expiration time invalid\n");
    GNUNET_free_non_null(rdata);
    GNUNET_free(gnsrecord_object);
    return GNUNET_SYSERR;
  }
  // check if flag is a valid enum value
  if ((GNUNET_GNSRECORD_RF_NONE != flag)
      && (GNUNET_GNSRECORD_RF_PRIVATE != flag)
      && (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION != flag)
      && (GNUNET_GNSRECORD_RF_SHADOW_RECORD) != flag)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Flag invalid\n");
    GNUNET_free_non_null(rdata);
    GNUNET_free(gnsrecord_object);
    return GNUNET_SYSERR;
  }
  gnsrecord_object->flags = (enum GNUNET_GNSRECORD_Flags)flag;
  *(struct GNUNET_GNSRECORD_Data **) spec->ptr = gnsrecord_object;
  return GNUNET_OK;
}

/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_gnsrecordobject (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_GNSRECORD_Data **gnsrecord_object;
  gnsrecord_object = (struct GNUNET_GNSRECORD_Data **) spec->ptr;
  if (NULL != *gnsrecord_object)
  {
    if (NULL != (*gnsrecord_object)->data)
      GNUNET_free((char*)(*gnsrecord_object)->data);

    GNUNET_free(*gnsrecord_object);
    *gnsrecord_object = NULL;
  }
}

/**
 * JSON Specification for GNS Records.
 *
 * @param gnsrecord_object struct of GNUNET_GNSRECORD_Data to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_gnsrecord_data (struct GNUNET_GNSRECORD_Data **gnsrecord_object)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_gnsrecordobject,
    .cleaner = &clean_gnsrecordobject,
    .cls = NULL,
    .field = NULL,
    .ptr = gnsrecord_object,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *gnsrecord_object = NULL;
  return ret;
}

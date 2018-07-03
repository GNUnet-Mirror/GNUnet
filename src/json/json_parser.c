/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
*/
/**
 * @file json/json_helper.c
 * @brief functions for REST JSON parsing
 * @author Philippe Buschmann
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"

#define GNUNET_REST_JSON_PUBKEY_ENTRY "pubkey"
#define GNUNET_REST_JSON_NAME_ENTRY "name"
#define GNUNET_REST_JSON_NICKNAME_ENTRY "nickname"
#define GNUNET_REST_JSON_NEWNAME_ENTRY "newname"
#define GNUNET_REST_JSON_SUBSYSTEM_ENTRY "subsystem"
#define GNUNET_REST_JSON_IS_PUBLIC_ENTRY "is_public"
#define GNUNET_REST_JSON_EXPIRATION_DATE_ENTRY "expiration_time"
#define GNUNET_REST_JSON_TYPE_ENTRY "type"
#define GNUNET_REST_JSON_VALUE_ENTRY "value"
#define GNUNET_REST_JSON_ZONE_ENTRY "zone"


int
GNUNET_REST_JSON_parse (struct GNUNET_REST_JSON_Data** output_data ,json_t *json_data)
{
  struct GNUNET_REST_JSON_Data *rest_json_data;
  json_t *cache;

  rest_json_data = GNUNET_malloc(sizeof(struct GNUNET_REST_JSON_Data));

  cache = json_object_get (json_data, GNUNET_REST_JSON_EXPIRATION_DATE_ENTRY);
  rest_json_data->expiration_time = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->expiration_time = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_NAME_ENTRY);
  rest_json_data->name = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->name = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_NEWNAME_ENTRY);
  rest_json_data->new_name = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->new_name = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_NICKNAME_ENTRY);
  rest_json_data->nickname = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->nickname = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_PUBKEY_ENTRY);
  rest_json_data->pubkey = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->pubkey = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_SUBSYSTEM_ENTRY);
  rest_json_data->subsystem = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->subsystem = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_TYPE_ENTRY);
  rest_json_data->type = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->type = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_VALUE_ENTRY);
  rest_json_data->value = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->value = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_ZONE_ENTRY);
  rest_json_data->zone = NULL;
  if (NULL != cache)
  {
    if (json_is_string(cache))
    {
      rest_json_data->zone = GNUNET_strdup(json_string_value(cache));
    }
  }
  cache = json_object_get (json_data, GNUNET_REST_JSON_IS_PUBLIC_ENTRY);
  if (NULL != cache)
  {
    if (json_is_integer(cache))
    {
      rest_json_data->is_public = json_integer_value(cache);
    }
  }
  *output_data = rest_json_data;
  return GNUNET_OK;
}



int
GNUNET_REST_JSON_free (struct GNUNET_REST_JSON_Data* rest_json_data)
{
  if (rest_json_data != NULL)
  {
    GNUNET_free_non_null(rest_json_data->expiration_time);
    GNUNET_free_non_null(rest_json_data->name);
    GNUNET_free_non_null(rest_json_data->new_name);
    GNUNET_free_non_null(rest_json_data->nickname);
    GNUNET_free_non_null(rest_json_data->pubkey);
    GNUNET_free_non_null(rest_json_data->subsystem);
    GNUNET_free_non_null(rest_json_data->type);
    GNUNET_free_non_null(rest_json_data->value);
    GNUNET_free_non_null(rest_json_data->zone);
  }
  GNUNET_free_non_null(rest_json_data);
  return GNUNET_OK;
}










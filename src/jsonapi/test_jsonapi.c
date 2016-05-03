/*
  This file is part of GNUnet
  (C) 2015, 2016 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/

/**
 * @file json/test_jsonapi.c
 * @brief Tests for jsonapi conversion functions
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_jsonapi_lib.h"
#include "gnunet_json_lib.h"

static int
test_serialize ()
{
  struct GNUNET_JSONAPI_Object *obj;
  char* data = "{\"data\":[{\"id\":\"1\", \"type\":\"test\"}]}";
  char* tmp_data;
  json_t* data_js;
  json_t* tmp_data_js;
  json_error_t err;
  struct GNUNET_JSON_Specification jsonapispec[] = {
    GNUNET_JSON_spec_jsonapi (&obj),
    GNUNET_JSON_spec_end()
  };
  data_js = json_loads (data, JSON_DECODE_ANY, &err);
  GNUNET_assert (NULL != data_js);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (data_js, jsonapispec,
                                    NULL, NULL));
  GNUNET_assert (GNUNET_OK == GNUNET_JSONAPI_data_serialize (obj,
                                                             &tmp_data));
  GNUNET_JSON_parse_free (jsonapispec);
  tmp_data_js = json_loads (tmp_data, JSON_DECODE_ANY, &err);
  GNUNET_assert (NULL != tmp_data_js);
  GNUNET_assert (0 != json_equal (tmp_data_js, data_js));
  json_decref (data_js);
  json_decref (tmp_data_js);
  GNUNET_free (tmp_data);
  return 0;
}

/**
 * Test rsa conversions from/to JSON.
 *
 * @return 0 on success
 */
static int
test_spec_jsonapi ()
{
  struct GNUNET_JSONAPI_Object *obj;
  struct GNUNET_JSONAPI_Resource *res;
  const char* data = "{\"data\":{\"id\":\"1\", \"type\":\"test\"}}";
  json_t* data_js;
  json_error_t err;

  struct GNUNET_JSON_Specification jsonapispec[] = {
    GNUNET_JSON_spec_jsonapi (&obj),
    GNUNET_JSON_spec_end()
  };
  data_js = json_loads (data, JSON_DECODE_ANY, &err);
  GNUNET_assert (NULL != data_js);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (data_js, jsonapispec,
                                    NULL, NULL));
  json_decref (data_js);
  res = GNUNET_JSONAPI_object_get_resource (obj, 0);
  GNUNET_assert (GNUNET_YES == GNUNET_JSONAPI_resource_check_id (res, "1"));
  GNUNET_assert (GNUNET_YES == GNUNET_JSONAPI_resource_check_type (res, "test"));
  GNUNET_assert (1 == GNUNET_JSONAPI_object_resource_count (obj));
  GNUNET_JSON_parse_free (jsonapispec);
  return 0;
}


int
main(int argc,
     const char *const argv[])
{
  GNUNET_log_setup ("test-jsonapi",
                    "WARNING",
                    NULL);
  if (0 != test_spec_jsonapi ())
    return 1;
  if (0 != test_serialize ())
    return 1;
  return 0;
}

/* end of test_json.c */

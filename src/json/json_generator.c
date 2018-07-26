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
 * @file json/json_generator.c
 * @brief helper functions for generating JSON from GNUnet data structures
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"


/**
 * Convert binary data to a JSON string
 * with the base32crockford encoding.
 *
 * @param data binary data
 * @param size size of @a data in bytes
 * @return json string that encodes @a data
 */
json_t *
GNUNET_JSON_from_data (const void *data,
                       size_t size)
{
  char *buf;
  json_t *json;

  buf = GNUNET_STRINGS_data_to_string_alloc (data, size);
  json = json_string (buf);
  GNUNET_free (buf);
  return json;
}


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs (struct GNUNET_TIME_Absolute stamp)
{
  json_t *j;
  char *mystr;
  int ret;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_TIME_round_abs (&stamp));
  if (stamp.abs_value_us == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
    return json_string ("/never/");
  ret = GNUNET_asprintf (&mystr,
                         "/Date(%llu)/",
                         (unsigned long long) (stamp.abs_value_us / (1000LL * 1000LL)));
  GNUNET_assert (ret > 0);
  j = json_string (mystr);
  GNUNET_free (mystr);
  return j;
}


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs_nbo (struct GNUNET_TIME_AbsoluteNBO stamp)
{
  return GNUNET_JSON_from_time_abs (GNUNET_TIME_absolute_ntoh (stamp));
}


/**
 * Convert relative timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_rel (struct GNUNET_TIME_Relative stamp)
{
  json_t *j;
  char *mystr;
  int ret;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_TIME_round_rel (&stamp));
  if (stamp.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    return json_string ("/forever/");
  ret = GNUNET_asprintf (&mystr,
                         "/Delay(%llu)/",
                         (unsigned long long) (stamp.rel_value_us / (1000LL * 1000LL)));
  GNUNET_assert (ret > 0);
  j = json_string (mystr);
  GNUNET_free (mystr);
  return j;
}


/**
 * Convert RSA public key to JSON.
 *
 * @param pk public key to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *pk)
{
  char *buf;
  size_t buf_len;
  json_t *ret;

  buf_len = GNUNET_CRYPTO_rsa_public_key_encode (pk,
                                                 &buf);
  ret = GNUNET_JSON_from_data (buf,
                               buf_len);
  GNUNET_free (buf);
  return ret;
}


/**
 * Convert RSA signature to JSON.
 *
 * @param sig signature to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *sig)
{
  char *buf;
  size_t buf_len;
  json_t *ret;

  buf_len = GNUNET_CRYPTO_rsa_signature_encode (sig,
                                                &buf);
  ret = GNUNET_JSON_from_data (buf,
                               buf_len);
  GNUNET_free (buf);
  return ret;
}

/**
 * Convert Gns record to JSON.
 *
 * @param rname name of record
 * @param rd record data
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_gns_record (const char* rname,
				const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_TIME_Absolute expiration_time;
  const char *expiration_time_str;
  const char *record_type_str;
  char *value_str;
  json_t *ret;
  int flags;

  value_str = GNUNET_GNSRECORD_value_to_string(rd->record_type,rd->data,rd->data_size);
  expiration_time = GNUNET_GNSRECORD_record_get_expiration_time(1, rd);
  expiration_time_str = GNUNET_STRINGS_absolute_time_to_string(expiration_time);
  flags = (int)rd->flags; //maybe necessary
  record_type_str = GNUNET_GNSRECORD_number_to_typename(rd->record_type);

  // ? for possible NULL values
  ret = json_pack("{s:s?,s:s?,s:s?,s:i,s:s?}",
		  "value", value_str,
		  "type", record_type_str,
		  "expiration_time", expiration_time_str,
		  "flag", flags,
		  "label", rname);
  GNUNET_free_non_null(value_str);
  return ret;
}


/* End of json/json_generator.c */

/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
 * @file json/json_helper.c
 * @brief functions to generate specifciations for JSON parsing
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_json_lib.h"


/**
 * End of a parser specification.
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_end ()
{
  struct GNUNET_JSON_Specification ret = {
    .parser = NULL,
    .cleaner = NULL,
    .cls = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to fixed size data
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_fixed_data (void *cls,
                  json_t *root,
                  struct GNUNET_JSON_Specification *spec)
{
  const char *enc;
  unsigned int len;

  if (NULL == (enc = json_string_value (root)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  len = strlen (enc);
  if (((len * 5) / 8) != spec->ptr_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     len,
                                     spec->ptr,
                                     spec->ptr_size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Variable size object (in network byte order, encoded using Crockford
 * Base32hex encoding).
 *
 * @param name name of the JSON field
 * @param[out] obj pointer where to write the data, must have @a size bytes
 * @param size number of bytes expected in @a obj
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_fixed (const char *name,
                        void *obj,
                        size_t size)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_fixed_data,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = obj,
    .ptr_size = size,
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to variable size data
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_variable_data (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  const char *str;
  size_t size;
  void *data;
  int res;

  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  size = (strlen (str) * 5) / 8;
  if (size >= 1024)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  data = GNUNET_malloc (size);
  res = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       data,
                                       size);
  if (GNUNET_OK != res)
  {
    GNUNET_break_op (0);
    GNUNET_free (data);
    return GNUNET_SYSERR;
  }
  *(void**) spec->ptr = data;
  *spec->size_ptr = size;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing variable size data
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_variable_data (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  if (0 != *spec->size_ptr)
  {
    GNUNET_free (*(void **) spec->ptr);
    *(void**) spec->ptr = NULL;
    *spec->size_ptr = 0;
  }
}


/**
 * Variable size object (in network byte order, encoded using
 * Crockford Base32hex encoding).
 *
 * @param name name of the JSON field
 * @param[out] obj pointer where to write the data, will be allocated
 * @param[out] size where to store the number of bytes allocated for @a obj
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_varsize (const char *name,
                          void **obj,
                          size_t *size)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_variable_data,
    .cleaner = &clean_variable_data,
    .cls = NULL,
    .field = name,
    .ptr = obj,
    .ptr_size = 0,
    .size_ptr = size
  };
  *obj = NULL;
  *size = 0;
  return ret;
}


/**
 * Parse given JSON object to string.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_string (void *cls,
              json_t *root,
              struct GNUNET_JSON_Specification *spec)
{
  const char *str;

  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *(const char **) spec->ptr = str;
  return GNUNET_OK;
}


/**
 * The expected field stores a string.
 *
 * @param name name of the JSON field
 * @param strptr where to store a pointer to the field
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_string (const char *name,
                         const char **strptr)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_string,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = strptr,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *strptr = NULL;
  return ret;
}


/**
 * Parse given JSON object to a JSON object. (Yes, trivial.)
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_object (void *cls,
              json_t *root,
              struct GNUNET_JSON_Specification *spec)
{
  if (! (json_is_object (root) || json_is_array (root)) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  json_incref (root);
  *(json_t **) spec->ptr = root;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing JSON object.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_object (void *cls,
              struct GNUNET_JSON_Specification *spec)
{
  json_t **ptr = (json_t **) spec->ptr;

  if (NULL != *ptr)
  {
    json_decref (*ptr);
    *ptr = NULL;
  }
}


/**
 * JSON object.
 *
 * @param name name of the JSON field
 * @param[out] jsonp where to store the JSON found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_json (const char *name,
                       json_t **jsonp)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_object,
    .cleaner = &clean_object,
    .cls = NULL,
    .field = name,
    .ptr = jsonp,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *jsonp = NULL;
  return ret;
}


/**
 * Parse given JSON object to a uint8_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_u8 (void *cls,
          json_t *root,
          struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint8_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ( (0 > val) || (val > UINT8_MAX) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (uint8_t) val;
  return GNUNET_OK;
}


/**
 * 8-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u8 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint8 (const char *name,
                        uint8_t *u8)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u8,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = u8,
    .ptr_size = sizeof (uint8_t),
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to a uint16_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_u16 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint16_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ( (0 > val) || (val > UINT16_MAX) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (uint16_t) val;
  return GNUNET_OK;
}


/**
 * 16-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u16 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint16 (const char *name,
                         uint16_t *u16)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u16,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = u16,
    .ptr_size = sizeof (uint16_t),
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to a uint32_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_u32 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint32_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  if ( (0 > val) || (val > UINT32_MAX) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *up = (uint32_t) val;
  return GNUNET_OK;
}


/**
 * 32-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u32 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint32 (const char *name,
                         uint32_t *u32)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u32,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = u32,
    .ptr_size = sizeof (uint32_t),
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to a uint8_t.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_u64 (void *cls,
           json_t *root,
           struct GNUNET_JSON_Specification *spec)
{
  json_int_t val;
  uint64_t *up = spec->ptr;

  if (! json_is_integer (root))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  val = json_integer_value (root);
  *up = (uint64_t) val;
  return GNUNET_OK;
}


/**
 * 64-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u64 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint64 (const char *name,
                         uint64_t *u64)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_u64,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = u64,
    .ptr_size = sizeof (uint64_t),
    .size_ptr = NULL
  };
  return ret;
}


/* ************ GNUnet-specific parser specifications ******************* */

/**
 * Parse given JSON object to absolute time.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_abs_time (void *cls,
                json_t *root,
                struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_TIME_Absolute *abs = spec->ptr;
  const char *val;
  unsigned long long int tval;

  val = json_string_value (root);
  if (NULL == val)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ( (0 == strcasecmp (val,
                         "/forever/")) ||
       (0 == strcasecmp (val,
                         "/end of time/")) ||
       (0 == strcasecmp (val,
                         "/never/")) )
  {
    *abs = GNUNET_TIME_UNIT_FOREVER_ABS;
    return GNUNET_OK;
  }
  if (1 != sscanf (val,
                   "/Date(%llu)/",
                   &tval))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* Time is in seconds in JSON, but in microseconds in GNUNET_TIME_Absolute */
  abs->abs_value_us = tval * 1000LL * 1000LL;
  if ( (abs->abs_value_us) / 1000LL / 1000LL != tval)
  {
    /* Integer overflow */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Absolute time.
 *
 * @param name name of the JSON field
 * @param[out] at where to store the absolute time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_absolute_time (const char *name,
                                struct GNUNET_TIME_Absolute *at)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_abs_time,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = at,
    .ptr_size = sizeof (uint64_t),
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to absolute time.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_abs_time_nbo (void *cls,
		    json_t *root,
		    struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_TIME_AbsoluteNBO *abs = spec->ptr;
  const char *val;
  unsigned long long int tval;
  struct GNUNET_TIME_Absolute a;

  val = json_string_value (root);
  if (NULL == val)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ( (0 == strcasecmp (val,
                         "/forever/")) ||
       (0 == strcasecmp (val,
                         "/end of time/")) ||
       (0 == strcasecmp (val,
                         "/never/")) )
  {
    *abs = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS);
    return GNUNET_OK;
  }
  if (1 != sscanf (val,
                   "/Date(%llu)/",
                   &tval))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* Time is in seconds in JSON, but in microseconds in GNUNET_TIME_Absolute */
  a.abs_value_us = tval * 1000LL * 1000LL;
  if ( (a.abs_value_us) / 1000LL / 1000LL != tval)
  {
    /* Integer overflow */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  *abs = GNUNET_TIME_absolute_hton (a);
  return GNUNET_OK;
}


/**
 * Absolute time in network byte order.
 *
 * @param name name of the JSON field
 * @param[out] at where to store the absolute time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_absolute_time_nbo (const char *name,
				    struct GNUNET_TIME_AbsoluteNBO *at)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_abs_time_nbo,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = at,
    .ptr_size = sizeof (uint64_t),
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to relative time.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_rel_time (void *cls,
                json_t *root,
                struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_TIME_Relative *rel = spec->ptr;
  const char *val;
  unsigned long long int tval;

  val = json_string_value (root);
  if (NULL == val)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ( (0 == strcasecmp (val,
                         "/forever/")) )
  {
    *rel = GNUNET_TIME_UNIT_FOREVER_REL;
    return GNUNET_OK;
  }
  if (1 != sscanf (val,
                   "/Delay(%llu)/",
                   &tval))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* Time is in seconds in JSON, but in microseconds in GNUNET_TIME_Relative */
  rel->rel_value_us = tval * 1000LL * 1000LL;
  if ( (rel->rel_value_us) / 1000LL / 1000LL != tval)
  {
    /* Integer overflow */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Relative time.
 *
 * @param name name of the JSON field
 * @param[out] rt where to store the relative time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_relative_time (const char *name,
                                struct GNUNET_TIME_Relative *rt)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_rel_time,
    .cleaner = NULL,
    .cls = NULL,
    .field = name,
    .ptr = rt,
    .ptr_size = sizeof (uint64_t),
    .size_ptr = NULL
  };
  return ret;
}


/**
 * Parse given JSON object to RSA public key.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_rsa_public_key (void *cls,
                      json_t *root,
                      struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = spec->ptr;
  const char *enc;
  char *buf;
  size_t len;
  size_t buf_len;

  if (NULL == (enc = json_string_value (root)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  len = strlen (enc);
  buf_len =  (len * 5) / 8;
  buf = GNUNET_malloc (buf_len);
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     len,
                                     buf,
                                     buf_len))
  {
    GNUNET_break_op (0);
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  if (NULL == (*pk = GNUNET_CRYPTO_rsa_public_key_decode (buf,
                                                          buf_len)))
  {
    GNUNET_break_op (0);
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_rsa_public_key (void *cls,
                      struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = spec->ptr;

  if (NULL != *pk)
  {
    GNUNET_CRYPTO_rsa_public_key_free (*pk);
    *pk = NULL;
  }
}


/**
 * Specification for parsing an RSA public key.
 *
 * @param name name of the JSON field
 * @param pk where to store the RSA key found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_public_key (const char *name,
                                 struct GNUNET_CRYPTO_RsaPublicKey **pk)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_rsa_public_key,
    .cleaner = &clean_rsa_public_key,
    .cls = NULL,
    .field = name,
    .ptr = pk,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *pk = NULL;
  return ret;
}


/**
 * Parse given JSON object to RSA signature.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_rsa_signature (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = spec->ptr;
  size_t size;
  const char *str;
  int res;
  void *buf;

  str = json_string_value (root);
  if (NULL == str)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  size = (strlen (str) * 5) / 8;
  buf = GNUNET_malloc (size);
  res = GNUNET_STRINGS_string_to_data (str,
                                       strlen (str),
                                       buf,
                                       size);
  if (GNUNET_OK != res)
  {
    GNUNET_free (buf);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == (*sig = GNUNET_CRYPTO_rsa_signature_decode (buf,
                                                          size)))
  {
    GNUNET_break_op (0);
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA signature.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_rsa_signature (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_CRYPTO_RsaSignature  **sig = spec->ptr;

  if (NULL != *sig)
  {
    GNUNET_CRYPTO_rsa_signature_free (*sig);
    *sig = NULL;
  }
}


/**
 * Specification for parsing an RSA signature.
 *
 * @param name name of the JSON field
 * @param sig where to store the RSA signature found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_signature (const char *name,
                                struct GNUNET_CRYPTO_RsaSignature **sig)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_rsa_signature,
    .cleaner = &clean_rsa_signature,
    .cls = NULL,
    .field = name,
    .ptr = sig,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *sig = NULL;
  return ret;
}


/* end of json_helper.c */

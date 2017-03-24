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
 * @file gnunet_json_lib.h
 * @brief functions to parse JSON objects into GNUnet objects
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#ifndef GNUNET_JSON_LIB_H
#define GNUNET_JSON_LIB_H

#include "gnunet_util_lib.h"
#include <jansson.h>


/* ****************** Generic parser interface ******************* */

/**
 * @brief Entry in parser specification for #GNUNET_JSON_parse().
 */
struct GNUNET_JSON_Specification;


/**
 * Function called to parse JSON argument.
 *
 * @param cls closure
 * @param root JSON to parse
 * @param spec our specification entry with further details
 * @return #GNUNET_SYSERR on error,
 *         #GNUNET_OK on success
 */
typedef int
(*GNUNET_JSON_Parser)(void *cls,
                      json_t *root,
                      struct GNUNET_JSON_Specification *spec);


/**
 * Function called to clean up data from earlier parsing.
 *
 * @param cls closure
 * @param spec our specification entry with data to clean.
 */
typedef void
(*GNUNET_JSON_Cleaner)(void *cls,
                       struct GNUNET_JSON_Specification *spec);


/**
 * @brief Entry in parser specification for #GNUNET_JSON_parse().
 */
struct GNUNET_JSON_Specification
{
  /**
   * Function for how to parse this type of entry.
   */
  GNUNET_JSON_Parser parser;

  /**
   * Function for how to clean up this type of entry.
   */
  GNUNET_JSON_Cleaner cleaner;

  /**
   * Closure for @e parser and @e cleaner.
   */
  void *cls;

  /**
   * Name of the field to parse, use NULL to get the JSON
   * of the main object instead of the JSON of an individual field.
   */
  const char *field;

  /**
   * Pointer, details specific to the @e parser.
   */
  void *ptr;

  /**
   * Number of bytes available in @e ptr.
   */
  size_t ptr_size;

  /**
   * Where should we store the final size of @e ptr.
   */
  size_t *size_ptr;

};


/**
 * Navigate and parse data in a JSON tree.  Tries to parse the @a root
 * to find all of the values given in the @a spec.  If one of the
 * entries in @a spec cannot be found or parsed, the name of the JSON
 * field is returned in @a error_json_name, and the offset of the
 * entry in @a spec is returned in @a error_line.
 *
 * @param root the JSON node to start the navigation at.
 * @param spec parse specification array
 * @param[out] error_json_name which JSON field was problematic
 * @param[out] which index into @a spec did we encounter an error
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_JSON_parse (const json_t *root,
                   struct GNUNET_JSON_Specification *spec,
                   const char **error_json_name,
                   unsigned int *error_line);


/**
 * Frees all elements allocated during a #GNUNET_JSON_parse()
 * operation.
 *
 * @param spec specification of the parse operation
 */
void
GNUNET_JSON_parse_free (struct GNUNET_JSON_Specification *spec);



/* ****************** Canonical parser specifications ******************* */


/**
 * End of a parser specification.
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_end (void);


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
                        size_t size);


/**
 * Fixed size object (in network byte order, encoded using Crockford
 * Base32hex encoding).
 *
 * @param name name of the JSON field
 * @param obj pointer where to write the data (type of `*obj` will determine size)
 */
#define GNUNET_JSON_spec_fixed_auto(name,obj) GNUNET_JSON_spec_fixed (name, obj, sizeof (*obj))


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
                          size_t *size);


/**
 * The expected field stores a string.
 *
 * @param name name of the JSON field
 * @param strptr where to store a pointer to the field
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_string (const char *name,
                         const char **strptr);

/**
 * JSON object.
 *
 * @param name name of the JSON field
 * @param[out] jsonp where to store the JSON found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_json (const char *name,
                       json_t **jsonp);


/**
 * 8-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u8 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint8 (const char *name,
                        uint8_t *u8);


/**
 * 16-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u16 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint16 (const char *name,
                         uint16_t *u16);


/**
 * 32-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u32 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint32 (const char *name,
                         uint32_t *u32);


/**
 * 64-bit integer.
 *
 * @param name name of the JSON field
 * @param[out] u64 where to store the integer found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_uint64 (const char *name,
                         uint64_t *u64);


/* ************ GNUnet-specific parser specifications ******************* */

/**
 * Absolute time.
 *
 * @param name name of the JSON field
 * @param[out] at where to store the absolute time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_absolute_time (const char *name,
                                struct GNUNET_TIME_Absolute *at);


/**
 * Relative time.
 *
 * @param name name of the JSON field
 * @param[out] rt where to store the relative time found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_relative_time (const char *name,
                                struct GNUNET_TIME_Relative *rt);


/**
 * Specification for parsing an RSA public key.
 *
 * @param name name of the JSON field
 * @param pk where to store the RSA key found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_public_key (const char *name,
                                 struct GNUNET_CRYPTO_RsaPublicKey **pk);


/**
 * Specification for parsing an RSA signature.
 *
 * @param name name of the JSON field
 * @param sig where to store the RSA signature found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_rsa_signature (const char *name,
                                struct GNUNET_CRYPTO_RsaSignature **sig);


/* ****************** Generic generator interface ******************* */


/**
 * Convert binary data to a JSON string with the base32crockford
 * encoding.
 *
 * @param data binary data
 * @param size size of @a data in bytes
 * @return json string that encodes @a data
 */
json_t *
GNUNET_JSON_from_data (const void *data,
                       size_t size);


/**
 * Convert binary data to a JSON string with the base32crockford
 * encoding.
 *
 * @param ptr binary data, sizeof (*ptr) must yield correct size
 * @return json string that encodes @a data
 */
#define GNUNET_JSON_from_data_auto(ptr) GNUNET_JSON_from_data(ptr, sizeof (*ptr))


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs (struct GNUNET_TIME_Absolute stamp);


/**
 * Convert relative timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_rel (struct GNUNET_TIME_Relative stamp);


/**
 * Convert RSA public key to JSON.
 *
 * @param pk public key to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *pk);


/**
 * Convert RSA signature to JSON.
 *
 * @param sig signature to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *sig);


/* ******************* Helpers for MHD upload handling ******************* */

/**
 * Return codes from #GNUNET_JSON_post_parser().
 */
enum GNUNET_JSON_PostResult {
  /**
   * Parsing successful, JSON result is in `*json`.
   */
  GNUNET_JSON_PR_SUCCESS,

  /**
   * Parsing continues, call again soon!
   */
  GNUNET_JSON_PR_CONTINUE,

  /**
   * Sorry, memory allocation (malloc()) failed.
   */
  GNUNET_JSON_PR_OUT_OF_MEMORY,

  /**
   * Request size exceeded `buffer_max` argument.
   */
  GNUNET_JSON_PR_REQUEST_TOO_LARGE,

  /**
   * JSON parsing failed. This was not a JSON upload.
   */
  GNUNET_JSON_PR_JSON_INVALID
};


/**
 * Process a POST request containing a JSON object.  This function
 * realizes an MHD POST processor that will (incrementally) process
 * JSON data uploaded to the HTTP server.  It will store the required
 * state in the @a con_cls, which must be cleaned up using
 * #GNUNET_JSON_post_parser_callback().
 *
 * @param buffer_max maximum allowed size for the buffer
 * @param con_cls the closure (will point to a `struct Buffer *`)
 * @param upload_data the POST data
 * @param upload_data_size number of bytes in @a upload_data
 * @param json the JSON object for a completed request
 * @return result code indicating the status of the operation
 */
enum GNUNET_JSON_PostResult
GNUNET_JSON_post_parser (size_t buffer_max,
                         void **con_cls,
                         const char *upload_data,
                         size_t *upload_data_size,
                         json_t **json);


/**
 * Function called whenever we are done with a request
 * to clean up our state.
 *
 * @param con_cls value as it was left by
 *        #GNUNET_JSON_post_parser(), to be cleaned up
 */
void
GNUNET_JSON_post_parser_cleanup (void *con_cls);


/* ****************** GETOPT JSON helper ******************* */


/**
 * Allow user to specify a JSON input value.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the JSON specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_JSON_getopt (char shortName,
                    const char *name,
                    const char *argumentHelp,
                    const char *description,
                    json_t **json);


#endif

/* end of gnunet_json_lib.h */

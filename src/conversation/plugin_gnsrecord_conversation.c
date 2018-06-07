/*
     This file is part of GNUnet
     Copyright (C) 2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file conversation/plugin_gnsrecord_conversation.c
 * @brief gnsrecord plugin to provide the API for fundamental GNS records
 *                  This includes the VPN record because GNS resolution
 *                  is expected to understand VPN records and (if needed)
 *                  map the result to A/AAAA.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_conversation_service.h"
#include "gnunet_gnsrecord_plugin.h"


/**
 * Convert the 'value' of a record to a string.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
static char *
conversation_value_to_string (void *cls,
                              uint32_t type,
                              const void *data,
                              size_t data_size)
{
  char *s;

  (void) cls;
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PHONE:
    {
      const struct GNUNET_CONVERSATION_PhoneRecord *pr;
      char *ret;
      char *pkey;

      if (data_size != sizeof (struct GNUNET_CONVERSATION_PhoneRecord))
      {
	GNUNET_break_op (0);
	return NULL;
      }
      pr = data;
      if (1 != ntohl (pr->version))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("PHONE version %u not supported\n"),
		    ntohl (pr->version));
	return NULL;
      }
      pkey = GNUNET_CRYPTO_eddsa_public_key_to_string (&pr->peer.public_key);
      s = GNUNET_STRINGS_data_to_string_alloc (&pr->line_port,
                                               sizeof (struct GNUNET_HashCode));

      GNUNET_asprintf (&ret,
		       "%s-%s",
		       s,
		       pkey);
      GNUNET_free (s);
      GNUNET_free (pkey);
      return ret;
    }
  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
conversation_string_to_value (void *cls,
                              uint32_t type,
                              const char *s,
                              void **data,
                              size_t *data_size)
{
  (void) cls;
  if (NULL == s)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PHONE:
    {
      struct GNUNET_CONVERSATION_PhoneRecord *pr;
      char line_port[103];
      const char *dash;
      struct GNUNET_PeerIdentity peer;

      if ( (NULL == (dash = strchr (s, '-'))) ||
	   (1 != sscanf (s, "%103s-", line_port)) ||
	   (GNUNET_OK !=
	    GNUNET_CRYPTO_eddsa_public_key_from_string (dash + 1,
                                                        strlen (dash + 1),
                                                        &peer.public_key)) )
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Unable to parse PHONE record `%s'\n"),
                    s);
	return GNUNET_SYSERR;
      }
      pr = GNUNET_new (struct GNUNET_CONVERSATION_PhoneRecord);
      pr->version = htonl (1);
      pr->reserved = htonl (0);
      if (GNUNET_OK !=
          GNUNET_STRINGS_string_to_data (line_port,
                                         strlen (line_port),
                                         &pr->line_port,
                                         sizeof (struct GNUNET_HashCode)))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Unable to parse PHONE record `%s'\n"),
                    s);
        GNUNET_free (pr);
        return GNUNET_SYSERR;
      }
      pr->peer = peer;
      *data = pr;
      *data_size = sizeof (struct GNUNET_CONVERSATION_PhoneRecord);
      return GNUNET_OK;
    }
  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of record type numbers to human-readable
 * record type names.
 */
static struct {
  const char *name;
  uint32_t number;
} name_map[] = {
  { "PHONE",  GNUNET_GNSRECORD_TYPE_PHONE },
  { NULL, UINT32_MAX }
};


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param cls closure, unused
 * @param gns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
conversation_typename_to_number (void *cls,
                                 const char *gns_typename)
{
  unsigned int i;

  (void) cls;
  i=0;
  while ( (name_map[i].name != NULL) &&
	  (0 != strcasecmp (gns_typename, name_map[i].name)) )
    i++;
  return name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
conversation_number_to_typename (void *cls,
                                 uint32_t type)
{
  unsigned int i;

  (void) cls;
  i=0;
  while ( (name_map[i].name != NULL) &&
	  (type != name_map[i].number) )
    i++;
  return name_map[i].name;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_gnsrecord_conversation_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  (void) cls;
  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &conversation_value_to_string;
  api->string_to_value = &conversation_string_to_value;
  api->typename_to_number = &conversation_typename_to_number;
  api->number_to_typename = &conversation_number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_conversation_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_gnsrecord_conversation.c */

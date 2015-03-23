/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @file gns/plugin_gnsrecord_gns.c
 * @brief gnsrecord plugin to provide the API for fundamental GNS records
 *                  This includes the VPN record because GNS resolution
 *                  is expected to understand VPN records and (if needed)
 *                  map the result to A/AAAA.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
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
gns_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  const char *cdata;

  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_PKEY:
    if (data_size != sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))
      return NULL;
    return GNUNET_CRYPTO_ecdsa_public_key_to_string (data);
  case GNUNET_GNSRECORD_TYPE_NICK:
    return GNUNET_strndup (data, data_size);
  case GNUNET_GNSRECORD_TYPE_LEHO:
    return GNUNET_strndup (data, data_size);
  case GNUNET_GNSRECORD_TYPE_GNS2DNS:
    {
      char *ns;
      char *ip;
      size_t off;
      char *nstr;

      off = 0;
      ns = GNUNET_DNSPARSER_parse_name (data,
					data_size,
					&off);
      ip = GNUNET_DNSPARSER_parse_name (data,
					data_size,
					&off);
      if ( (NULL == ns) ||
           (NULL == ip) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
	GNUNET_free_non_null (ns);
	GNUNET_free_non_null (ip);
	return NULL;
      }
      GNUNET_asprintf (&nstr,
                       "%s@%s",
                       ns,
                       ip);
      GNUNET_free_non_null (ns);
      GNUNET_free_non_null (ip);
      return nstr;
    }
  case GNUNET_GNSRECORD_TYPE_VPN:
    {
      const struct GNUNET_TUN_GnsVpnRecord *vpn;
      char* vpn_str;

      cdata = data;
      if ( (data_size <= sizeof (struct GNUNET_TUN_GnsVpnRecord)) ||
	   ('\0' != cdata[data_size - 1]) )
	return NULL; /* malformed */
      vpn = data;
      GNUNET_asprintf (&vpn_str,
                       "%u %s %s",
                       (unsigned int) ntohs (vpn->proto),
                       (const char*) GNUNET_i2s_full (&vpn->peer),
                       (const char*) &vpn[1]);
      return vpn_str;
    }
  case GNUNET_GNSRECORD_TYPE_BOX:
    {
      const struct GNUNET_GNSRECORD_BoxRecord *box;
      uint32_t rt;
      char *box_str;
      char *ival;

      if (data_size < sizeof (struct GNUNET_GNSRECORD_BoxRecord))
	return NULL; /* malformed */
      box = data;
      rt = ntohl (box->record_type);
      ival = GNUNET_GNSRECORD_value_to_string (rt,
                                               &box[1],
                                               data_size - sizeof (struct GNUNET_GNSRECORD_BoxRecord));
      if (NULL == ival)
        return NULL; /* malformed */
      GNUNET_asprintf (&box_str,
                       "%u %u %u %s",
                       (unsigned int) ntohs (box->protocol),
                       (unsigned int) ntohs (box->service),
                       (unsigned int) rt,
                       ival);
      GNUNET_free (ival);
      return box_str;
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
gns_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {

  case GNUNET_GNSRECORD_TYPE_PKEY:
    if (GNUNET_OK !=
	GNUNET_CRYPTO_ecdsa_public_key_from_string (s, strlen (s), &pkey))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           _("Unable to parse PKEY record `%s'\n"),
           s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
    memcpy (*data, &pkey, sizeof (pkey));
    *data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
    return GNUNET_OK;

  case GNUNET_GNSRECORD_TYPE_NICK:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_GNSRECORD_TYPE_LEHO:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_GNSRECORD_TYPE_GNS2DNS:
    {
      char nsbuf[514];
      char *cpy;
      char *at;
      size_t off;

      cpy = GNUNET_strdup (s);
      at = strchr (cpy, '@');
      if (NULL == at)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Unable to parse GNS2DNS record `%s'\n"),
                    s);
        GNUNET_free (cpy);
        return GNUNET_SYSERR;
      }
      *at = '\0';
      at++;

      off = 0;
      if ( (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_name (nsbuf,
                                               sizeof (nsbuf),
                                               &off,
                                               cpy)) ||
           (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_name (nsbuf,
                                               sizeof (nsbuf),
                                               &off,
                                               at)) )
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to serialize GNS2DNS record with value `%s'\n"),
                    s);
        GNUNET_free (cpy);
	return GNUNET_SYSERR;
      }
      GNUNET_free (cpy);
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, nsbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_GNSRECORD_TYPE_VPN:
    {
      struct GNUNET_TUN_GnsVpnRecord *vpn;
      char s_peer[103 + 1];
      char s_serv[253 + 1];
      unsigned int proto;

      if (3 != SSCANF (s,
                       "%u %103s %253s",
                       &proto, s_peer, s_serv))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Unable to parse VPN record string `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      *data_size = sizeof (struct GNUNET_TUN_GnsVpnRecord) + strlen (s_serv) + 1;
      *data = vpn = GNUNET_malloc (*data_size);
      if (GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string ((char*) s_peer,
                                                                   strlen (s_peer),
                                                                   &vpn->peer.public_key))
      {
        GNUNET_free (vpn);
        *data_size = 0;
        return GNUNET_SYSERR;
      }
      vpn->proto = htons ((uint16_t) proto);
      strcpy ((char*)&vpn[1], s_serv);
      return GNUNET_OK;
    }
  case GNUNET_GNSRECORD_TYPE_BOX:
    {
      struct GNUNET_GNSRECORD_BoxRecord *box;
      size_t rest;
      unsigned int protocol;
      unsigned int service;
      unsigned int record_type;
      void *bval;
      size_t bval_size;

      if (3 != SSCANF (s,
                       "%u %u %u ",
                       &protocol,
                       &service,
                       &record_type))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Unable to parse BOX record string `%s'\n"),
                    s);
        return GNUNET_SYSERR;
      }
      rest = snprintf (NULL, 0,
                       "%u %u %u ",
                       protocol,
                       service,
                       record_type);
      if (GNUNET_OK !=
          GNUNET_GNSRECORD_string_to_value (record_type,
                                            &s[rest],
                                            &bval,
                                            &bval_size))
        return GNUNET_SYSERR;
      *data_size = sizeof (struct GNUNET_GNSRECORD_BoxRecord) + bval_size;
      *data = box = GNUNET_malloc (*data_size);
      box->protocol = htons (protocol);
      box->service = htons (service);
      box->record_type = htonl (record_type);
      memcpy (&box[1],
              bval,
              bval_size);
      GNUNET_free (bval);
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
} gns_name_map[] = {
  { "PKEY",  GNUNET_GNSRECORD_TYPE_PKEY },
  { "NICK",  GNUNET_GNSRECORD_TYPE_NICK },
  { "LEHO",  GNUNET_GNSRECORD_TYPE_LEHO },
  { "VPN", GNUNET_GNSRECORD_TYPE_VPN },
  { "GNS2DNS", GNUNET_GNSRECORD_TYPE_GNS2DNS },
  { "BOX", GNUNET_GNSRECORD_TYPE_BOX },
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
gns_typename_to_number (void *cls,
                        const char *gns_typename)
{
  unsigned int i;

  i=0;
  while ( (NULL != gns_name_map[i].name) &&
	  (0 != strcasecmp (gns_typename,
                            gns_name_map[i].name)) )
    i++;
  return gns_name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
gns_number_to_typename (void *cls,
                        uint32_t type)
{
  unsigned int i;

  i=0;
  while ( (NULL != gns_name_map[i].name) &&
	  (type != gns_name_map[i].number) )
    i++;
  return gns_name_map[i].name;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_gnsrecord_gns_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &gns_value_to_string;
  api->string_to_value = &gns_string_to_value;
  api->typename_to_number = &gns_typename_to_number;
  api->number_to_typename = &gns_number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_gns_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_gnsrecord_gns.c */

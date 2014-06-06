/*
     This file is part of GNUnet
     (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @file gnsrecord/plugin_gnsrecord_dns.c
 * @brief gnsrecord plugin to provide the API for basic DNS records
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
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
dns_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  const char *cdata;
  char* result;
  char tmp[INET6_ADDRSTRLEN];

  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    if (data_size != sizeof (struct in_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET, data, tmp, sizeof (tmp)))
      return NULL;
    return GNUNET_strdup (tmp);
  case GNUNET_DNSPARSER_TYPE_NS:
    {
      char *ns;
      size_t off;

      off = 0;
      ns = GNUNET_DNSPARSER_parse_name (data,
					data_size,
					&off);
      if ( (NULL == ns) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
        GNUNET_free_non_null (ns);
	return NULL;
      }
      return ns;
    }
  case GNUNET_DNSPARSER_TYPE_CNAME:
    {
      char *cname;
      size_t off;

      off = 0;
      cname = GNUNET_DNSPARSER_parse_name (data,
					   data_size,
					   &off);
      if ( (NULL == cname) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
	GNUNET_free_non_null (cname);
	return NULL;
      }
      return cname;
    }
  case GNUNET_DNSPARSER_TYPE_SOA:
    {
      struct GNUNET_DNSPARSER_SoaRecord *soa;
      size_t off;

      off = 0;
      soa = GNUNET_DNSPARSER_parse_soa (data,
					data_size,
					&off);
      if ( (NULL == soa) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
        if (NULL != soa)
          GNUNET_DNSPARSER_free_soa (soa);
	return NULL;
      }
      GNUNET_asprintf (&result,
		       "rname=%s mname=%s %lu,%lu,%lu,%lu,%lu",
		       soa->rname,
		       soa->mname,
		       soa->serial,
		       soa->refresh,
		       soa->retry,
		       soa->expire,
		       soa->minimum_ttl);
      GNUNET_DNSPARSER_free_soa (soa);
      return result;
    }
  case GNUNET_DNSPARSER_TYPE_PTR:
    {
      char *ptr;
      size_t off;

      off = 0;
      ptr = GNUNET_DNSPARSER_parse_name (data,
					   data_size,
					   &off);
      if ( (NULL == ptr) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
	GNUNET_free_non_null (ptr);
	return NULL;
      }
      return ptr;
    }
  case GNUNET_DNSPARSER_TYPE_CERT:
    {
      struct GNUNET_DNSPARSER_CertRecord *cert;
      size_t off;
      char *base64;
      int len;

      off = 0;
      cert = GNUNET_DNSPARSER_parse_cert (data,
                                          data_size,
                                          &off);
      if ( (NULL == cert) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
        GNUNET_DNSPARSER_free_cert (cert);
	return NULL;
      }
      len = GNUNET_STRINGS_base64_encode (cert->certificate_data,
                                          cert->certificate_size,
                                          &base64);
      GNUNET_asprintf (&result,
		       "%u %u %u %.*s",
                       cert->cert_type,
                       cert->cert_tag,
                       cert->algorithm,
                       len,
                       base64);
      GNUNET_free (base64);
      GNUNET_DNSPARSER_free_cert (cert);
      return result;
    }
  case GNUNET_DNSPARSER_TYPE_MX:
    {
      struct GNUNET_DNSPARSER_MxRecord *mx;
      size_t off;

      off = 0;
      mx = GNUNET_DNSPARSER_parse_mx (data,
				      data_size,
				      &off);
      if ( (NULL == mx) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
        GNUNET_DNSPARSER_free_mx (mx);
	return NULL;
      }
      GNUNET_asprintf (&result,
		       "%u,%s",
		       (unsigned int) mx->preference,
		       mx->mxhost);
      GNUNET_DNSPARSER_free_mx (mx);
      return result;
    }
  case GNUNET_DNSPARSER_TYPE_TXT:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (data_size != sizeof (struct in6_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET6, data, tmp, sizeof (tmp)))
      return NULL;
    return GNUNET_strdup (tmp);
  case GNUNET_DNSPARSER_TYPE_SRV:
    {
      struct GNUNET_DNSPARSER_SrvRecord *srv;
      size_t off;

      off = 0;
      srv = GNUNET_DNSPARSER_parse_srv (data,
					data_size,
					&off);
      if ( (NULL == srv) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
        if (NULL != srv)
          GNUNET_DNSPARSER_free_srv (srv);
	return NULL;
      }
      GNUNET_asprintf (&result,
		       "%d %d %d %s",
		       srv->priority,
		       srv->weight,
		       srv->port,
		       srv->target);
      GNUNET_DNSPARSER_free_srv (srv);
      return result;
    }
  case GNUNET_DNSPARSER_TYPE_TLSA:
    {
      const struct GNUNET_TUN_DnsTlsaRecord *tlsa;
      char* tlsa_str;

      cdata = data;
      if ( (data_size <= sizeof (struct GNUNET_TUN_DnsTlsaRecord)) ||
	   ('\0' != cdata[data_size - 1]) )
	return NULL; /* malformed */
      tlsa = data;
      if (0 == GNUNET_asprintf (&tlsa_str,
				"%c %c %c %s",
				tlsa->usage,
				tlsa->selector,
				tlsa->matching_type,
				(const char *) &tlsa[1]))
      {
	GNUNET_free (tlsa_str);
	return NULL;
      }
      return tlsa_str;
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
dns_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  struct in_addr value_a;
  struct in6_addr value_aaaa;
  struct GNUNET_TUN_DnsTlsaRecord *tlsa;

  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    if (1 != inet_pton (AF_INET, s, &value_a))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse IPv4 address `%s'\n"),
                  s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct in_addr);
    memcpy (*data, &value_a, sizeof (value_a));
    *data_size = sizeof (value_a);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_NS:
    {
      char nsbuf[256];
      size_t off;

      off = 0;
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_name (nsbuf,
					     sizeof (nsbuf),
					     &off,
					     s))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize NS record with value `%s'\n"),
             s);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, nsbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_CNAME:
    {
      char cnamebuf[256];
      size_t off;

      off = 0;
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_name (cnamebuf,
					     sizeof (cnamebuf),
					     &off,
					     s))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize CNAME record with value `%s'\n"),
             s);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, cnamebuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_CERT:
    {
      char *sdup;
      const char *typep;
      const char *keyp;
      const char *algp;
      const char *certp;
      unsigned int type;
      unsigned int key;
      unsigned int alg;
      size_t cert_size;
      char *cert_data;
      struct GNUNET_DNSPARSER_CertRecord cert;

      sdup = GNUNET_strdup (s);
      typep = strtok (sdup, " ");
      /* TODO: add typep mnemonic conversion according to RFC 4398 */
      if ( (NULL == typep) ||
           (1 != sscanf (typep,
                         "%u",
                         &type)) ||
           (type > UINT16_MAX) )
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      keyp = strtok (NULL, " ");
      if ( (NULL == keyp) ||
           (1 != sscanf (keyp,
                         "%u",
                         &key)) ||
           (key > UINT16_MAX) )
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      algp = strtok (NULL, " ");
      /* TODO: add algp mnemonic conversion according to RFC 4398/RFC 4034 */
      if ( (NULL == algp) ||
           (1 != sscanf (algp,
                         "%u",
                         &alg)) ||
           (alg > UINT8_MAX) )
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      certp = strtok (NULL, " ");
      if ( (NULL == certp) ||
           (0 == strlen (certp) ) )
      {
        GNUNET_free (sdup);
        return GNUNET_SYSERR;
      }
      cert_size = GNUNET_STRINGS_base64_decode (certp,
                                                strlen (certp),
                                                &cert_data);
      GNUNET_free (sdup);
      cert.cert_type = type;
      cert.cert_tag = key;
      cert.algorithm = alg;
      cert.certificate_size = cert_size;
      cert.certificate_data = cert_data;
      {
        char certbuf[cert_size + sizeof (struct GNUNET_TUN_DnsCertRecord)];
        size_t off;

        off = 0;
        if (GNUNET_OK !=
            GNUNET_DNSPARSER_builder_add_cert (certbuf,
                                               sizeof (certbuf),
                                               &off,
                                               &cert))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Failed to serialize CERT record with %u bytes\n"),
                      (unsigned int) cert_size);
          GNUNET_free (cert_data);
          return GNUNET_SYSERR;
        }
        GNUNET_free (cert_data);
        *data_size = off;
        *data = GNUNET_malloc (off);
        memcpy (*data, certbuf, off);
      }
      GNUNET_free (cert_data);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_SOA:
    {
      struct GNUNET_DNSPARSER_SoaRecord soa;
      char soabuf[540];
      char soa_rname[253 + 1];
      char soa_mname[253 + 1];
      unsigned int soa_serial;
      unsigned int soa_refresh;
      unsigned int soa_retry;
      unsigned int soa_expire;
      unsigned int soa_min;
      size_t off;

      if (7 != SSCANF (s,
		       "rname=%253s mname=%253s %u,%u,%u,%u,%u",
		       soa_rname, soa_mname,
		       &soa_serial, &soa_refresh, &soa_retry, &soa_expire, &soa_min))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Unable to parse SOA record `%s'\n"),
             s);
	return GNUNET_SYSERR;
      }
      soa.mname = soa_mname;
      soa.rname = soa_rname;
      soa.serial = (uint32_t) soa_serial;
      soa.refresh =(uint32_t)  soa_refresh;
      soa.retry = (uint32_t) soa_retry;
      soa.expire = (uint32_t) soa_expire;
      soa.minimum_ttl = (uint32_t) soa_min;
      off = 0;
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_soa (soabuf,
					    sizeof (soabuf),
					    &off,
					    &soa))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize SOA record with mname `%s' and rname `%s'\n"),
             soa_mname,
             soa_rname);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, soabuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_PTR:
    {
      char ptrbuf[256];
      size_t off;

      off = 0;
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_name (ptrbuf,
					     sizeof (ptrbuf),
					     &off,
					     s))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize PTR record with value `%s'\n"),
             s);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, ptrbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_MX:
    {
      struct GNUNET_DNSPARSER_MxRecord mx;
      char mxbuf[258];
      char mxhost[253 + 1];
      unsigned int mx_pref;
      size_t off;

      if (2 != SSCANF(s,
                      "%u,%253s",
                      &mx_pref,
                      mxhost))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Unable to parse MX record `%s'\n"),
             s);
      return GNUNET_SYSERR;
      }
      mx.preference = (uint16_t) mx_pref;
      mx.mxhost = mxhost;
      off = 0;

      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_mx (mxbuf,
					   sizeof (mxbuf),
					   &off,
					   &mx))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize MX record with hostname `%s'\n"),
             mxhost);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, mxbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_SRV:
    {
      struct GNUNET_DNSPARSER_SrvRecord srv;
      char srvbuf[270];
      char srvtarget[253 + 1];
      unsigned int priority;
      unsigned int weight;
      unsigned int port;
      size_t off;

      if (2 != SSCANF(s,
                      "%u %u %u %253s",
                      &priority,
                      &weight,
                      &port,
                      srvtarget))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
             _("Unable to parse SRV record `%s'\n"),
             s);
        return GNUNET_SYSERR;
      }
      srv.priority = (uint16_t) priority;
      srv.weight = (uint16_t) weight;
      srv.port = (uint16_t) port;
      srv.target = srvtarget;
      off = 0;
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_srv (srvbuf,
                                            sizeof (srvbuf),
                                            &off,
                                            &srv))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to serialize SRV record with target `%s'\n"),
                    srvtarget);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, srvbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_TXT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (1 != inet_pton (AF_INET6, s, &value_aaaa))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
           _("Unable to parse IPv6 address `%s'\n"),
           s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct in6_addr);
    *data_size = sizeof (struct in6_addr);
    memcpy (*data, &value_aaaa, sizeof (value_aaaa));
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_TLSA:
    *data_size = sizeof (struct GNUNET_TUN_DnsTlsaRecord) + strlen (s) - 6;
    *data = tlsa = GNUNET_malloc (*data_size);
    if (4 != SSCANF (s, "%c %c %c %s",
		     &tlsa->usage,
		     &tlsa->selector,
		     &tlsa->matching_type,
		     (char*)&tlsa[1]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse TLSA record string `%s'\n"),
                  s);
      *data_size = 0;
      GNUNET_free (tlsa);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
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
  { "A", GNUNET_DNSPARSER_TYPE_A },
  { "NS", GNUNET_DNSPARSER_TYPE_NS },
  { "CNAME", GNUNET_DNSPARSER_TYPE_CNAME },
  { "SOA", GNUNET_DNSPARSER_TYPE_SOA },
  { "PTR", GNUNET_DNSPARSER_TYPE_PTR },
  { "MX", GNUNET_DNSPARSER_TYPE_MX },
  { "TXT", GNUNET_DNSPARSER_TYPE_TXT },
  { "AAAA", GNUNET_DNSPARSER_TYPE_AAAA },
  { "TLSA", GNUNET_DNSPARSER_TYPE_TLSA },
  { NULL, UINT32_MAX }
};


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param cls closure, unused
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
dns_typename_to_number (void *cls,
                        const char *dns_typename)
{
  unsigned int i;

  i=0;
  while ( (name_map[i].name != NULL) &&
	  (0 != strcasecmp (dns_typename, name_map[i].name)) )
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
dns_number_to_typename (void *cls,
                        uint32_t type)
{
  unsigned int i;

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
libgnunet_plugin_gnsrecord_dns_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &dns_value_to_string;
  api->string_to_value = &dns_string_to_value;
  api->typename_to_number = &dns_typename_to_number;
  api->number_to_typename = &dns_number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_dns_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_gnsrecord_dns.c */

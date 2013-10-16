/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file gnsrecord/gnsrecord.c
 * @brief API to access GNS record data
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_conversation_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_tun_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "gnsrecord",__VA_ARGS__)


/**
 * Convert the 'value' of a record to a string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_NAMESTORE_value_to_string (uint32_t type,
				  const void *data,
				  size_t data_size)
{
  const char *cdata;
  char* result;
  char tmp[INET6_ADDRSTRLEN];

  switch (type)
  {
  case 0:
    return NULL;
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
	GNUNET_free_non_null (mx);
	return NULL;
      }
      GNUNET_asprintf (&result,
		       "%hu,%s",
		       mx->preference,
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
  case GNUNET_NAMESTORE_TYPE_PKEY:
    if (data_size != sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))
      return NULL;
    return GNUNET_CRYPTO_ecdsa_public_key_to_string (data);
  case GNUNET_NAMESTORE_TYPE_PHONE:
    {
      const struct GNUNET_CONVERSATION_PhoneRecord *pr;
      char *ret;
      char *pkey;

      if (data_size != sizeof (struct GNUNET_CONVERSATION_PhoneRecord))
	return NULL;
      pr = data;
      if (0 != ntohl (pr->version))
	return NULL;
      pkey = GNUNET_CRYPTO_eddsa_public_key_to_string (&pr->peer.public_key);
      GNUNET_asprintf (&ret,
		       "%u-%s",
		       ntohl (pr->line),
		       pkey);
      GNUNET_free (pkey);
      return ret;
    }
  case GNUNET_NAMESTORE_TYPE_PSEU:
    return GNUNET_strndup (data, data_size);
  case GNUNET_NAMESTORE_TYPE_LEHO:
    return GNUNET_strndup (data, data_size);
  case GNUNET_NAMESTORE_TYPE_VPN:
    {
      const struct GNUNET_TUN_GnsVpnRecord *vpn;
      char* vpn_str;

      cdata = data;
      if ( (data_size <= sizeof (struct GNUNET_TUN_GnsVpnRecord)) ||
	   ('\0' != cdata[data_size - 1]) )
	return NULL; /* malformed */
      vpn = data;
      if (0 == GNUNET_asprintf (&vpn_str, "%u %s %s",
				(unsigned int) ntohs (vpn->proto),
				(const char*) GNUNET_i2s_full (&vpn->peer),
				(const char*) &vpn[1]))
      {
	GNUNET_free (vpn_str);
	return NULL;
      }
      return vpn_str;
    }
  case GNUNET_NAMESTORE_TYPE_GNS2DNS:
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
  case GNUNET_DNSPARSER_TYPE_SRV:
    {
      struct GNUNET_DNSPARSER_SrvRecord *srv;
      size_t off;

      off = 0;
      srv = GNUNET_DNSPARSER_parse_srv ("+", /* FIXME: is this OK? */
					data,
					data_size,
					&off);
      if ( (NULL == srv) ||
	   (off != data_size) )
      {
	GNUNET_break_op (0);
	return NULL;
      }
      GNUNET_asprintf (&result,
		       "%d %d %d _%s._%s.%s",
		       srv->priority,
		       srv->weight,
		       srv->port,
		       srv->service,
		       srv->proto,
		       srv->domain_name);
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
    GNUNET_break (0);
  }
  GNUNET_break (0); // not implemented
  return NULL;
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_NAMESTORE_string_to_value (uint32_t type,
				  const char *s,
				  void **data,
				  size_t *data_size)
{
  struct in_addr value_a;
  struct in6_addr value_aaaa;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  struct GNUNET_TUN_GnsVpnRecord *vpn;
  struct GNUNET_TUN_DnsTlsaRecord *tlsa;
  char s_peer[103 + 1];
  char s_serv[253 + 1];
  unsigned int proto;

  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case 0:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Unsupported record type %d\n"),
         (int) type);
    return GNUNET_SYSERR;
  case GNUNET_DNSPARSER_TYPE_A:
    if (1 != inet_pton (AF_INET, s, &value_a))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Unable to parse IPv4 address `%s'\n"),
           s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_malloc (sizeof (struct in_addr));
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
	LOG (GNUNET_ERROR_TYPE_ERROR,
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
	LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize CNAME record with value `%s'\n"),
             s);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, cnamebuf, off);
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
	LOG (GNUNET_ERROR_TYPE_ERROR,
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
	LOG (GNUNET_ERROR_TYPE_ERROR,
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
	LOG (GNUNET_ERROR_TYPE_ERROR,
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
      uint16_t mx_pref;
      size_t off;

      if (2 != SSCANF(s, "%hu,%253s", &mx_pref, mxhost))
      {
	LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Unable to parse MX record `%s'\n"),
             s);
      return GNUNET_SYSERR;
      }
      mx.preference = mx_pref;
      mx.mxhost = mxhost;
      off = 0;

      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_builder_add_mx (mxbuf,
					   sizeof (mxbuf),
					   &off,
					   &mx))
      {
	LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize MX record with hostname `%s'\n"),
             mxhost);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, mxbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_TXT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (1 != inet_pton (AF_INET6, s, &value_aaaa))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Unable to parse IPv6 address `%s'\n"),
           s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_malloc (sizeof (struct in6_addr));
    *data_size = sizeof (struct in6_addr);
    memcpy (*data, &value_aaaa, sizeof (value_aaaa));
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_PKEY:
    if (GNUNET_OK !=
	GNUNET_CRYPTO_ecdsa_public_key_from_string (s, strlen (s), &pkey))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Unable to parse PKEY record `%s'\n"),
           s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
    memcpy (*data, &pkey, sizeof (pkey));
    *data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_PHONE:
    {
      struct GNUNET_CONVERSATION_PhoneRecord *pr;
      unsigned int line;
      const char *dash;
      struct GNUNET_PeerIdentity peer;

      if ( (NULL == (dash = strchr (s, '-'))) ||
	   (1 != sscanf (s, "%u-", &line)) ||
	   (GNUNET_OK !=
	    GNUNET_CRYPTO_eddsa_public_key_from_string (dash + 1,
							   strlen (dash + 1),
							   &peer.public_key)) )
      {
	LOG (GNUNET_ERROR_TYPE_ERROR,
	     _("Unable to parse PHONE record `%s'\n"),
	     s);
	return GNUNET_SYSERR;
      }
      pr = GNUNET_new (struct GNUNET_CONVERSATION_PhoneRecord);
      pr->version = htonl (0);
      pr->line = htonl ((uint32_t) line);
      pr->peer = peer;
      *data = pr;
      *data_size = sizeof (struct GNUNET_CONVERSATION_PhoneRecord);
      return GNUNET_OK;
    }
  case GNUNET_NAMESTORE_TYPE_PSEU:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_LEHO:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_VPN:
    if (3 != SSCANF (s,"%u %103s %253s",
		     &proto, s_peer, s_serv))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
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
  case GNUNET_NAMESTORE_TYPE_GNS2DNS:
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
	LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Failed to serialize GNS2DNS record with value `%s'\n"),
             s);
	return GNUNET_SYSERR;
      }
      *data_size = off;
      *data = GNUNET_malloc (off);
      memcpy (*data, nsbuf, off);
      return GNUNET_OK;
    }
  case GNUNET_DNSPARSER_TYPE_TLSA:
    *data_size = sizeof (struct GNUNET_TUN_DnsTlsaRecord) + strlen (s) - 6;
    *data = tlsa = GNUNET_malloc (*data_size);
    if (4 != SSCANF (s, "%c %c %c %s",
		     &tlsa->usage,
		     &tlsa->selector,
		     &tlsa->matching_type,
		     (char*)&tlsa[1]))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Unable to parse TLSA record string `%s'\n"),
           s);
      *data_size = 0;
      GNUNET_free (tlsa);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Unsupported record type %d\n"),
         (int) type);
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
  { "PKEY",  GNUNET_NAMESTORE_TYPE_PKEY },
  { "PSEU",  GNUNET_NAMESTORE_TYPE_PSEU },
  { "LEHO",  GNUNET_NAMESTORE_TYPE_LEHO },
  { "VPN", GNUNET_NAMESTORE_TYPE_VPN },
  { "GNS2DNS", GNUNET_NAMESTORE_TYPE_GNS2DNS },
  { "PHONE", GNUNET_NAMESTORE_TYPE_PHONE },
  { "TLSA", GNUNET_DNSPARSER_TYPE_TLSA },
  { NULL, UINT32_MAX }
};


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_NAMESTORE_typename_to_number (const char *dns_typename)
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
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_NAMESTORE_number_to_typename (uint32_t type)
{
  unsigned int i;

  i=0;
  while ( (name_map[i].name != NULL) &&
	  (type != name_map[i].number) )
    i++;
  return name_map[i].name;
}



/* end of namestore_common.c */

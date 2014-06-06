/*
      This file is part of GNUnet
      (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file dns/dnsparser.c
 * @brief helper library to parse DNS packets.
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#include "platform.h"
#include <idna.h>
#if WINDOWS
#include <idn-free.h>
#endif
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"


/**
 * Check if a label in UTF-8 format can be coded into valid IDNA.
 * This can fail if the ASCII-conversion becomes longer than 63 characters.
 *
 * @param label label to check (UTF-8 string)
 * @return #GNUNET_OK if the label can be converted to IDNA,
 *         #GNUNET_SYSERR if the label is not valid for DNS names
 */
int
GNUNET_DNSPARSER_check_label (const char *label)
{
  char *output;
  size_t slen;

  if (NULL != strchr (label, '.'))
    return GNUNET_SYSERR; /* not a label! Did you mean GNUNET_DNSPARSER_check_name? */
  if (IDNA_SUCCESS !=
      idna_to_ascii_8z (label, &output, IDNA_ALLOW_UNASSIGNED))
    return GNUNET_SYSERR;
  slen = strlen (output);
#if WINDOWS
  idn_free (output);
#else
  free (output);
#endif
  return (slen > 63) ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Check if a label in UTF-8 format can be coded into valid IDNA.
 * This can fail if the ASCII-conversion becomes longer than 253 characters.
 *
 * @param name name to check (UTF-8 string)
 * @return #GNUNET_OK if the label can be converted to IDNA,
 *         #GNUNET_SYSERR if the label is not valid for DNS names
 */
int
GNUNET_DNSPARSER_check_name (const char *name)
{
  char *ldup;
  char *output;
  size_t slen;
  char *tok;

  ldup = GNUNET_strdup (name);
  for (tok = strtok (ldup, "."); NULL != tok; tok = strtok (NULL, "."))
    if (GNUNET_OK !=
	GNUNET_DNSPARSER_check_label (tok))
    {
      GNUNET_free (ldup);
      return GNUNET_SYSERR;
    }
  GNUNET_free (ldup);
  if (IDNA_SUCCESS !=
      idna_to_ascii_8z (name, &output, IDNA_ALLOW_UNASSIGNED))
    return GNUNET_SYSERR;
  slen = strlen (output);
#if WINDOWS
  idn_free (output);
#else
  free (output);
#endif
  return (slen > 253) ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Free SOA information record.
 *
 * @param soa record to free
 */
void
GNUNET_DNSPARSER_free_soa (struct GNUNET_DNSPARSER_SoaRecord *soa)
{
  if (NULL == soa)
    return;
  GNUNET_free_non_null (soa->mname);
  GNUNET_free_non_null (soa->rname);
  GNUNET_free (soa);
}


/**
 * Free CERT information record.
 *
 * @param cert record to free
 */
void
GNUNET_DNSPARSER_free_cert (struct GNUNET_DNSPARSER_CertRecord *cert)
{
  if (NULL == cert)
    return;
  GNUNET_free_non_null (cert->certificate_data);
  GNUNET_free (cert);
}


/**
 * Free SRV information record.
 *
 * @param srv record to free
 */
void
GNUNET_DNSPARSER_free_srv (struct GNUNET_DNSPARSER_SrvRecord *srv)
{
  if (NULL == srv)
    return;
  GNUNET_free_non_null (srv->target);
  GNUNET_free (srv);
}


/**
 * Free MX information record.
 *
 * @param mx record to free
 */
void
GNUNET_DNSPARSER_free_mx (struct GNUNET_DNSPARSER_MxRecord *mx)
{
  if (NULL == mx)
    return;
  GNUNET_free_non_null (mx->mxhost);
  GNUNET_free (mx);
}


/**
 * Free the given DNS record.
 *
 * @param r record to free
 */
void
GNUNET_DNSPARSER_free_record (struct GNUNET_DNSPARSER_Record *r)
{
  GNUNET_free_non_null (r->name);
  switch (r->type)
  {
  case GNUNET_DNSPARSER_TYPE_MX:
    GNUNET_DNSPARSER_free_mx (r->data.mx);
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    GNUNET_DNSPARSER_free_soa (r->data.soa);
    break;
  case GNUNET_DNSPARSER_TYPE_SRV:
    GNUNET_DNSPARSER_free_srv (r->data.srv);
    break;
  case GNUNET_DNSPARSER_TYPE_CERT:
    GNUNET_DNSPARSER_free_cert (r->data.cert);
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    GNUNET_free_non_null (r->data.hostname);
    break;
  default:
    GNUNET_free_non_null (r->data.raw.data);
    break;
  }
}


/**
 * Parse name inside of a DNS query or record.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the name to parse in the udp_payload (to be
 *                    incremented by the size of the name)
 * @param depth current depth of our recursion (to prevent stack overflow)
 * @return name as 0-terminated C string on success, NULL if the payload is malformed
 */
static char *
parse_name (const char *udp_payload,
	    size_t udp_payload_length,
	    size_t *off,
	    unsigned int depth)
{
  const uint8_t *input = (const uint8_t *) udp_payload;
  char *ret;
  char *tmp;
  char *xstr;
  uint8_t len;
  size_t xoff;
  char *utf8;
  Idna_rc rc;

  ret = GNUNET_strdup ("");
  while (1)
  {
    if (*off >= udp_payload_length)
    {
      GNUNET_break_op (0);
      goto error;
    }
    len = input[*off];
    if (0 == len)
    {
      (*off)++;
      break;
    }
    if (len < 64)
    {
      if (*off + 1 + len > udp_payload_length)
      {
	GNUNET_break_op (0);
	goto error;
      }
      GNUNET_asprintf (&tmp,
		       "%.*s",
		       (int) len,
		       &udp_payload[*off + 1]);
      if (IDNA_SUCCESS !=
	  (rc = idna_to_unicode_8z8z (tmp, &utf8, IDNA_ALLOW_UNASSIGNED)))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Failed to convert DNS IDNA name `%s' to UTF-8: %s\n"),
		    tmp,
		    idna_strerror (rc));
	GNUNET_free (tmp);
	GNUNET_asprintf (&tmp,
			 "%s%.*s.",
			 ret,
			 (int) len,
			 &udp_payload[*off + 1]);
      }
      else
      {
	GNUNET_free (tmp);
	GNUNET_asprintf (&tmp,
			 "%s%s.",
			 ret,
			 utf8);
#if WINDOWS
	idn_free (utf8);
#else
	free (utf8);
#endif
      }
      GNUNET_free (ret);
      ret = tmp;
      *off += 1 + len;
    }
    else if ((64 | 128) == (len & (64 | 128)) )
    {
      if (depth > 32)
      {
	GNUNET_break_op (0);
	goto error; /* hard bound on stack to prevent "infinite" recursion, disallow! */
      }
      /* pointer to string */
      if (*off + 1 > udp_payload_length)
      {
	GNUNET_break_op (0);
	goto error;
      }
      xoff = ((len - (64 | 128)) << 8) + input[*off+1];
      xstr = parse_name (udp_payload,
			 udp_payload_length,
			 &xoff,
			 depth + 1);
      if (NULL == xstr)
      {
	GNUNET_break_op (0);
	goto error;
      }
      GNUNET_asprintf (&tmp,
		       "%s%s.",
		       ret,
		       xstr);
      GNUNET_free (ret);
      GNUNET_free (xstr);
      ret = tmp;
      if (strlen (ret) > udp_payload_length)
      {
	GNUNET_break_op (0);
	goto error; /* we are looping (building an infinite string) */
      }
      *off += 2;
      /* pointers always terminate names */
      break;
    }
    else
    {
      /* neither pointer nor inline string, not supported... */
      GNUNET_break_op (0);
      goto error;
    }
  }
  if (0 < strlen(ret))
    ret[strlen(ret)-1] = '\0'; /* eat tailing '.' */
  return ret;
 error:
  GNUNET_break_op (0);
  GNUNET_free (ret);
  return NULL;
}


/**
 * Parse name inside of a DNS query or record.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the name to parse in the udp_payload (to be
 *                    incremented by the size of the name)
 * @return name as 0-terminated C string on success, NULL if the payload is malformed
 */
char *
GNUNET_DNSPARSER_parse_name (const char *udp_payload,
			     size_t udp_payload_length,
			     size_t *off)
{
  return parse_name (udp_payload, udp_payload_length, off, 0);
}


/**
 * Parse a DNS query entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the udp_payload (to be
 *                    incremented by the size of the query)
 * @param q where to write the query information
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the query is malformed
 */
int
GNUNET_DNSPARSER_parse_query (const char *udp_payload,
			      size_t udp_payload_length,
			      size_t *off,
			      struct GNUNET_DNSPARSER_Query *q)
{
  char *name;
  struct GNUNET_TUN_DnsQueryLine ql;

  name = GNUNET_DNSPARSER_parse_name (udp_payload,
				      udp_payload_length,
				      off);
  if (NULL == name)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  q->name = name;
  if (*off + sizeof (struct GNUNET_TUN_DnsQueryLine) > udp_payload_length)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  memcpy (&ql, &udp_payload[*off], sizeof (ql));
  *off += sizeof (ql);
  q->type = ntohs (ql.type);
  q->dns_traffic_class = ntohs (ql.dns_traffic_class);
  return GNUNET_OK;
}


/**
 * Parse a DNS SOA record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the SOA record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed SOA record, NULL on error
 */
struct GNUNET_DNSPARSER_SoaRecord *
GNUNET_DNSPARSER_parse_soa (const char *udp_payload,
			    size_t udp_payload_length,
			    size_t *off)
{
  struct GNUNET_DNSPARSER_SoaRecord *soa;
  struct GNUNET_TUN_DnsSoaRecord soa_bin;
  size_t old_off;

  old_off = *off;
  soa = GNUNET_new (struct GNUNET_DNSPARSER_SoaRecord);
  soa->mname = GNUNET_DNSPARSER_parse_name (udp_payload,
					    udp_payload_length,
					    off);
  soa->rname = GNUNET_DNSPARSER_parse_name (udp_payload,
					    udp_payload_length,
					    off);
  if ( (NULL == soa->mname) ||
       (NULL == soa->rname) ||
       (*off + sizeof (struct GNUNET_TUN_DnsSoaRecord) > udp_payload_length) )
  {
    GNUNET_break_op (0);
    GNUNET_DNSPARSER_free_soa (soa);
    *off = old_off;
    return NULL;
  }
  memcpy (&soa_bin,
	  &udp_payload[*off],
	  sizeof (struct GNUNET_TUN_DnsSoaRecord));
  soa->serial = ntohl (soa_bin.serial);
  soa->refresh = ntohl (soa_bin.refresh);
  soa->retry = ntohl (soa_bin.retry);
  soa->expire = ntohl (soa_bin.expire);
  soa->minimum_ttl = ntohl (soa_bin.minimum);
  (*off) += sizeof (struct GNUNET_TUN_DnsSoaRecord);
  return soa;
}


/**
 * Parse a DNS MX record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the MX record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed MX record, NULL on error
 */
struct GNUNET_DNSPARSER_MxRecord *
GNUNET_DNSPARSER_parse_mx (const char *udp_payload,
			   size_t udp_payload_length,
			   size_t *off)
{
  struct GNUNET_DNSPARSER_MxRecord *mx;
  uint16_t mxpref;
  size_t old_off;

  old_off = *off;
  if (*off + sizeof (uint16_t) > udp_payload_length)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  memcpy (&mxpref, &udp_payload[*off], sizeof (uint16_t));
  (*off) += sizeof (uint16_t);
  mx = GNUNET_new (struct GNUNET_DNSPARSER_MxRecord);
  mx->preference = ntohs (mxpref);
  mx->mxhost = GNUNET_DNSPARSER_parse_name (udp_payload,
					    udp_payload_length,
					    off);
  if (NULL == mx->mxhost)
  {
    GNUNET_break_op (0);
    GNUNET_DNSPARSER_free_mx (mx);
    *off = old_off;
    return NULL;
  }
  return mx;
}


/**
 * Parse a DNS SRV record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the SRV record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed SRV record, NULL on error
 */
struct GNUNET_DNSPARSER_SrvRecord *
GNUNET_DNSPARSER_parse_srv (const char *udp_payload,
			    size_t udp_payload_length,
			    size_t *off)
{
  struct GNUNET_DNSPARSER_SrvRecord *srv;
  struct GNUNET_TUN_DnsSrvRecord srv_bin;
  size_t old_off;

  old_off = *off;
  if (*off + sizeof (struct GNUNET_TUN_DnsSrvRecord) > udp_payload_length)
    return NULL;
  memcpy (&srv_bin,
	  &udp_payload[*off],
	  sizeof (struct GNUNET_TUN_DnsSrvRecord));
  (*off) += sizeof (struct GNUNET_TUN_DnsSrvRecord);
  srv = GNUNET_new (struct GNUNET_DNSPARSER_SrvRecord);
  srv->priority = ntohs (srv_bin.prio);
  srv->weight = ntohs (srv_bin.weight);
  srv->port = ntohs (srv_bin.port);
  srv->target = GNUNET_DNSPARSER_parse_name (udp_payload,
					     udp_payload_length,
					     off);
  if (NULL == srv->target)
  {
    GNUNET_DNSPARSER_free_srv (srv);
    *off = old_off;
    return NULL;
  }
  return srv;
}


/**
 * Parse a DNS CERT record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the CERT record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed CERT record, NULL on error
 */
struct GNUNET_DNSPARSER_CertRecord *
GNUNET_DNSPARSER_parse_cert (const char *udp_payload,
                             size_t udp_payload_length,
                             size_t *off)
{
  struct GNUNET_DNSPARSER_CertRecord *cert;
  struct GNUNET_TUN_DnsCertRecord dcert;

  if (*off + sizeof (struct GNUNET_TUN_DnsCertRecord) >= udp_payload_length)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  memcpy (&dcert, &udp_payload[*off], sizeof (struct GNUNET_TUN_DnsCertRecord));
  (*off) += sizeof (sizeof (struct GNUNET_TUN_DnsCertRecord));
  cert = GNUNET_new (struct GNUNET_DNSPARSER_CertRecord);
  cert->cert_type = ntohs (dcert.cert_type);
  cert->cert_tag = ntohs (dcert.cert_tag);
  cert->algorithm = dcert.algorithm;
  cert->certificate_size = udp_payload_length - (*off);
  cert->certificate_data = GNUNET_malloc (cert->certificate_size);
  memcpy (cert->certificate_data,
          &udp_payload[*off],
          cert->certificate_size);
  (*off) += cert->certificate_size;
  return cert;
}


/**
 * Parse a DNS record entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the record to parse in the udp_payload (to be
 *                    incremented by the size of the record)
 * @param r where to write the record information
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the record is malformed
 */
int
GNUNET_DNSPARSER_parse_record (const char *udp_payload,
			       size_t udp_payload_length,
			       size_t *off,
			       struct GNUNET_DNSPARSER_Record *r)
{
  char *name;
  struct GNUNET_TUN_DnsRecordLine rl;
  size_t old_off;
  uint16_t data_len;

  name = GNUNET_DNSPARSER_parse_name (udp_payload,
				      udp_payload_length,
				      off);
  if (NULL == name)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  r->name = name;
  if (*off + sizeof (struct GNUNET_TUN_DnsRecordLine) > udp_payload_length)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  memcpy (&rl, &udp_payload[*off], sizeof (rl));
  (*off) += sizeof (rl);
  r->type = ntohs (rl.type);
  r->dns_traffic_class = ntohs (rl.dns_traffic_class);
  r->expiration_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
											ntohl (rl.ttl)));
  data_len = ntohs (rl.data_len);
  if (*off + data_len > udp_payload_length)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  old_off = *off;
  switch (r->type)
  {
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    r->data.hostname = GNUNET_DNSPARSER_parse_name (udp_payload,
						    udp_payload_length,
						    off);
    if ( (NULL == r->data.hostname) ||
	 (old_off + data_len != *off) )
      return GNUNET_SYSERR;
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_SOA:
    r->data.soa = GNUNET_DNSPARSER_parse_soa (udp_payload,
					      udp_payload_length,
					      off);
    if ( (NULL == r->data.soa) ||
	 (old_off + data_len != *off) )
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_MX:
    r->data.mx = GNUNET_DNSPARSER_parse_mx (udp_payload,
					    udp_payload_length,
					    off);
    if ( (NULL == r->data.mx) ||
	 (old_off + data_len != *off) )
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_SRV:
    r->data.srv = GNUNET_DNSPARSER_parse_srv (udp_payload,
					      udp_payload_length,
					      off);
    if ( (NULL == r->data.srv) ||
	 (old_off + data_len != *off) )
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  default:
    r->data.raw.data = GNUNET_malloc (data_len);
    r->data.raw.data_len = data_len;
    memcpy (r->data.raw.data, &udp_payload[*off], data_len);
    break;
  }
  (*off) += data_len;
  return GNUNET_OK;
}


/**
 * Parse a UDP payload of a DNS packet in to a nice struct for further
 * processing and manipulation.
 *
 * @param udp_payload wire-format of the DNS packet
 * @param udp_payload_length number of bytes in @a udp_payload
 * @return NULL on error, otherwise the parsed packet
 */
struct GNUNET_DNSPARSER_Packet *
GNUNET_DNSPARSER_parse (const char *udp_payload,
			size_t udp_payload_length)
{
  struct GNUNET_DNSPARSER_Packet *p;
  const struct GNUNET_TUN_DnsHeader *dns;
  size_t off;
  unsigned int n;
  unsigned int i;

  if (udp_payload_length < sizeof (struct GNUNET_TUN_DnsHeader))
    return NULL;
  dns = (const struct GNUNET_TUN_DnsHeader *) udp_payload;
  off = sizeof (struct GNUNET_TUN_DnsHeader);
  p = GNUNET_new (struct GNUNET_DNSPARSER_Packet);
  p->flags = dns->flags;
  p->id = dns->id;
  n = ntohs (dns->query_count);
  if (n > 0)
  {
    p->queries = GNUNET_malloc (n * sizeof (struct GNUNET_DNSPARSER_Query));
    p->num_queries = n;
    for (i=0;i<n;i++)
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_parse_query (udp_payload,
					udp_payload_length,
					&off,
					&p->queries[i]))
	goto error;
  }
  n = ntohs (dns->answer_rcount);
  if (n > 0)
  {
    p->answers = GNUNET_malloc (n * sizeof (struct GNUNET_DNSPARSER_Record));
    p->num_answers = n;
    for (i=0;i<n;i++)
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_parse_record (udp_payload,
					 udp_payload_length,
					 &off,
					 &p->answers[i]))
	goto error;
  }
  n = ntohs (dns->authority_rcount);
  if (n > 0)
  {
    p->authority_records = GNUNET_malloc (n * sizeof (struct GNUNET_DNSPARSER_Record));
    p->num_authority_records = n;
    for (i=0;i<n;i++)
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_parse_record (udp_payload,
					 udp_payload_length,
					 &off,
					 &p->authority_records[i]))
	goto error;
  }
  n = ntohs (dns->additional_rcount);
  if (n > 0)
  {
    p->additional_records = GNUNET_malloc (n * sizeof (struct GNUNET_DNSPARSER_Record));
    p->num_additional_records = n;
    for (i=0;i<n;i++)
      if (GNUNET_OK !=
	  GNUNET_DNSPARSER_parse_record (udp_payload,
					 udp_payload_length,
					 &off,
					 &p->additional_records[i]))
	goto error;
  }
  return p;
 error:
  GNUNET_break_op (0);
  GNUNET_DNSPARSER_free_packet (p);
  return NULL;
}


/**
 * Free memory taken by a packet.
 *
 * @param p packet to free
 */
void
GNUNET_DNSPARSER_free_packet (struct GNUNET_DNSPARSER_Packet *p)
{
  unsigned int i;

  for (i=0;i<p->num_queries;i++)
    GNUNET_free_non_null (p->queries[i].name);
  GNUNET_free_non_null (p->queries);
  for (i=0;i<p->num_answers;i++)
    GNUNET_DNSPARSER_free_record (&p->answers[i]);
  GNUNET_free_non_null (p->answers);
  for (i=0;i<p->num_authority_records;i++)
    GNUNET_DNSPARSER_free_record (&p->authority_records[i]);
  GNUNET_free_non_null (p->authority_records);
  for (i=0;i<p->num_additional_records;i++)
    GNUNET_DNSPARSER_free_record (&p->additional_records[i]);
  GNUNET_free_non_null (p->additional_records);
  GNUNET_free (p);
}


/* ********************** DNS packet assembly code **************** */


/**
 * Add a DNS name to the UDP packet at the given location, converting
 * the name to IDNA notation as necessary.
 *
 * @param dst where to write the name (UDP packet)
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the name (increment by bytes used)
 *            must not be changed if there is an error
 * @param name name to write
 * @return #GNUNET_SYSERR if @a name is invalid
 *         #GNUNET_NO if @a name did not fit
 *         #GNUNET_OK if @a name was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_name (char *dst,
				   size_t dst_len,
				   size_t *off,
				   const char *name)
{
  const char *dot;
  const char *idna_name;
  char *idna_start;
  size_t start;
  size_t pos;
  size_t len;
  Idna_rc rc;

  if (NULL == name)
    return GNUNET_SYSERR;

  if (IDNA_SUCCESS !=
      (rc = idna_to_ascii_8z (name, &idna_start, IDNA_ALLOW_UNASSIGNED)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to convert UTF-8 name `%s' to DNS IDNA format: %s\n"),
		name,
		idna_strerror (rc));
    return GNUNET_NO;
  }
  idna_name = idna_start;
  start = *off;
  if (start + strlen (idna_name) + 2 > dst_len)
    goto fail;
  pos = start;
  do
  {
    dot = strchr (idna_name, '.');
    if (NULL == dot)
      len = strlen (idna_name);
    else
      len = dot - idna_name;
    if ( (len >= 64) || (0 == len) )
    {
      GNUNET_break (0);
      goto fail; /* segment too long or empty */
    }
    dst[pos++] = (char) (uint8_t) len;
    memcpy (&dst[pos], idna_name, len);
    pos += len;
    idna_name += len + 1; /* also skip dot */
  }
  while (NULL != dot);
  dst[pos++] = '\0'; /* terminator */
  *off = pos;
#if WINDOWS
  idn_free (idna_start);
#else
  free (idna_start);
#endif
  return GNUNET_OK;
 fail:
#if WINDOWS
  idn_free (idna_start);
#else
  free (idna_start);
#endif
  return GNUNET_NO;
}


/**
 * Add a DNS query to the UDP packet at the given location.
 *
 * @param dst where to write the query
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the query (increment by bytes used)
 *            must not be changed if there is an error
 * @param query query to write
 * @return #GNUNET_SYSERR if @a query is invalid
 *         #GNUNET_NO if @a query did not fit
 *         #GNUNET_OK if @a query was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_query (char *dst,
				    size_t dst_len,
				    size_t *off,
				    const struct GNUNET_DNSPARSER_Query *query)
{
  int ret;
  struct GNUNET_TUN_DnsQueryLine ql;

  ret = GNUNET_DNSPARSER_builder_add_name (dst, dst_len - sizeof (struct GNUNET_TUN_DnsQueryLine), off, query->name);
  if (ret != GNUNET_OK)
    return ret;
  ql.type = htons (query->type);
  ql.dns_traffic_class = htons (query->dns_traffic_class);
  memcpy (&dst[*off], &ql, sizeof (ql));
  (*off) += sizeof (ql);
  return GNUNET_OK;
}


/**
 * Add an MX record to the UDP packet at the given location.
 *
 * @param dst where to write the mx record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the mx information (increment by bytes used);
 *            can also change if there was an error
 * @param mx mx information to write
 * @return #GNUNET_SYSERR if @a mx is invalid
 *         #GNUNET_NO if @a mx did not fit
 *         #GNUNET_OK if @a mx was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_mx (char *dst,
				 size_t dst_len,
				 size_t *off,
				 const struct GNUNET_DNSPARSER_MxRecord *mx)
{
  uint16_t mxpref;

  if (*off + sizeof (uint16_t) > dst_len)
    return GNUNET_NO;
  mxpref = htons (mx->preference);
  memcpy (&dst[*off], &mxpref, sizeof (mxpref));
  (*off) += sizeof (mxpref);
  return GNUNET_DNSPARSER_builder_add_name (dst, dst_len, off, mx->mxhost);
}


/**
 * Add a CERT record to the UDP packet at the given location.
 *
 * @param dst where to write the CERT record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the CERT information (increment by bytes used);
 *            can also change if there was an error
 * @param cert CERT information to write
 * @return #GNUNET_SYSERR if @a cert is invalid
 *         #GNUNET_NO if @a cert did not fit
 *         #GNUNET_OK if @a cert was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_cert (char *dst,
                                   size_t dst_len,
                                   size_t *off,
                                   const struct GNUNET_DNSPARSER_CertRecord *cert)
{
  struct GNUNET_TUN_DnsCertRecord dcert;

  if ( (cert->cert_type > UINT16_MAX) ||
       (cert->cert_tag > UINT16_MAX) ||
       (cert->algorithm > UINT8_MAX) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (*off + sizeof (struct GNUNET_TUN_DnsCertRecord) + cert->certificate_size > dst_len)
    return GNUNET_NO;
  dcert.cert_type = htons ((uint16_t) cert->cert_type);
  dcert.cert_tag = htons ((uint16_t) cert->cert_tag);
  dcert.algorithm = (uint8_t) cert->algorithm;
  memcpy (&dst[*off], &dcert, sizeof (dcert));
  (*off) += sizeof (dcert);
  memcpy (&dst[*off], cert->certificate_data, cert->certificate_size);
  (*off) += cert->certificate_size;
  return GNUNET_OK;
}


/**
 * Add an SOA record to the UDP packet at the given location.
 *
 * @param dst where to write the SOA record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the SOA information (increment by bytes used)
 *            can also change if there was an error
 * @param soa SOA information to write
 * @return #GNUNET_SYSERR if @a soa is invalid
 *         #GNUNET_NO if @a soa did not fit
 *         #GNUNET_OK if @a soa was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_soa (char *dst,
				  size_t dst_len,
				  size_t *off,
				  const struct GNUNET_DNSPARSER_SoaRecord *soa)
{
  struct GNUNET_TUN_DnsSoaRecord sd;
  int ret;

  if ( (GNUNET_OK != (ret = GNUNET_DNSPARSER_builder_add_name (dst,
                                                               dst_len,
                                                               off,
                                                               soa->mname))) ||
       (GNUNET_OK != (ret = GNUNET_DNSPARSER_builder_add_name (dst,
                                                               dst_len,
                                                               off,
                                                               soa->rname)) ) )
    return ret;
  if (*off + sizeof (struct GNUNET_TUN_DnsSoaRecord) > dst_len)
    return GNUNET_NO;
  sd.serial = htonl (soa->serial);
  sd.refresh = htonl (soa->refresh);
  sd.retry = htonl (soa->retry);
  sd.expire = htonl (soa->expire);
  sd.minimum = htonl (soa->minimum_ttl);
  memcpy (&dst[*off], &sd, sizeof (sd));
  (*off) += sizeof (sd);
  return GNUNET_OK;
}


/**
 * Add an SRV record to the UDP packet at the given location.
 *
 * @param dst where to write the SRV record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the SRV information (increment by bytes used)
 *            can also change if there was an error
 * @param srv SRV information to write
 * @return #GNUNET_SYSERR if @a srv is invalid
 *         #GNUNET_NO if @a srv did not fit
 *         #GNUNET_OK if @a srv was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_srv (char *dst,
				  size_t dst_len,
				  size_t *off,
				  const struct GNUNET_DNSPARSER_SrvRecord *srv)
{
  struct GNUNET_TUN_DnsSrvRecord sd;
  int ret;

  if (*off + sizeof (struct GNUNET_TUN_DnsSrvRecord) > dst_len)
    return GNUNET_NO;
  sd.prio = htons (srv->priority);
  sd.weight = htons (srv->weight);
  sd.port = htons (srv->port);
  memcpy (&dst[*off], &sd, sizeof (sd));
  (*off) += sizeof (sd);
  if (GNUNET_OK != (ret = GNUNET_DNSPARSER_builder_add_name (dst,
				    dst_len,
				    off,
				    srv->target)))
    return ret;
  return GNUNET_OK;
}


/**
 * Add a DNS record to the UDP packet at the given location.
 *
 * @param dst where to write the query
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the query (increment by bytes used)
 *            must not be changed if there is an error
 * @param record record to write
 * @return #GNUNET_SYSERR if @a record is invalid
 *         #GNUNET_NO if @a record did not fit
 *         #GNUNET_OK if @a record was added to @a dst
 */
static int
add_record (char *dst,
	    size_t dst_len,
	    size_t *off,
	    const struct GNUNET_DNSPARSER_Record *record)
{
  int ret;
  size_t start;
  size_t pos;
  struct GNUNET_TUN_DnsRecordLine rl;

  start = *off;
  ret = GNUNET_DNSPARSER_builder_add_name (dst,
                                           dst_len - sizeof (struct GNUNET_TUN_DnsRecordLine),
                                           off,
                                           record->name);
  if (GNUNET_OK != ret)
    return ret;
  /* '*off' is now the position where we will need to write the record line */

  pos = *off + sizeof (struct GNUNET_TUN_DnsRecordLine);
  switch (record->type)
  {
  case GNUNET_DNSPARSER_TYPE_MX:
    ret = GNUNET_DNSPARSER_builder_add_mx (dst, dst_len, &pos, record->data.mx);
    break;
  case GNUNET_DNSPARSER_TYPE_CERT:
    ret = GNUNET_DNSPARSER_builder_add_cert (dst, dst_len, &pos, record->data.cert);
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    ret = GNUNET_DNSPARSER_builder_add_soa (dst, dst_len, &pos, record->data.soa);
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    ret = GNUNET_DNSPARSER_builder_add_name (dst, dst_len, &pos, record->data.hostname);
    break;
  case GNUNET_DNSPARSER_TYPE_SRV:
    ret = GNUNET_DNSPARSER_builder_add_srv (dst, dst_len, &pos, record->data.srv);
    break;
  default:
    if (pos + record->data.raw.data_len > dst_len)
    {
      ret = GNUNET_NO;
      break;
    }
    memcpy (&dst[pos], record->data.raw.data, record->data.raw.data_len);
    pos += record->data.raw.data_len;
    ret = GNUNET_OK;
    break;
  }
  if (GNUNET_OK != ret)
  {
    *off = start;
    return GNUNET_NO;
  }

  if (pos - (*off + sizeof (struct GNUNET_TUN_DnsRecordLine)) > UINT16_MAX)
  {
    /* record data too long */
    *off = start;
    return GNUNET_NO;
  }
  rl.type = htons (record->type);
  rl.dns_traffic_class = htons (record->dns_traffic_class);
  rl.ttl = htonl (GNUNET_TIME_absolute_get_remaining (record->expiration_time).rel_value_us / 1000LL / 1000LL); /* in seconds */
  rl.data_len = htons ((uint16_t) (pos - (*off + sizeof (struct GNUNET_TUN_DnsRecordLine))));
  memcpy (&dst[*off], &rl, sizeof (struct GNUNET_TUN_DnsRecordLine));
  *off = pos;
  return GNUNET_OK;
}


/**
 * Given a DNS packet @a p, generate the corresponding UDP payload.
 * Note that we do not attempt to pack the strings with pointers
 * as this would complicate the code and this is about being
 * simple and secure, not fast, fancy and broken like bind.
 *
 * @param p packet to pack
 * @param max maximum allowed size for the resulting UDP payload
 * @param buf set to a buffer with the packed message
 * @param buf_length set to the length of @a buf
 * @return #GNUNET_SYSERR if @a p is invalid
 *         #GNUNET_NO if @a p was truncated (but there is still a result in @a buf)
 *         #GNUNET_OK if @a p was packed completely into @a buf
 */
int
GNUNET_DNSPARSER_pack (const struct GNUNET_DNSPARSER_Packet *p,
		       uint16_t max,
		       char **buf,
		       size_t *buf_length)
{
  struct GNUNET_TUN_DnsHeader dns;
  size_t off;
  char tmp[max];
  unsigned int i;
  int ret;
  int trc;

  if ( (p->num_queries > UINT16_MAX) ||
       (p->num_answers > UINT16_MAX) ||
       (p->num_authority_records > UINT16_MAX) ||
       (p->num_additional_records > UINT16_MAX) )
    return GNUNET_SYSERR;
  dns.id = p->id;
  dns.flags = p->flags;
  dns.query_count = htons (p->num_queries);
  dns.answer_rcount = htons (p->num_answers);
  dns.authority_rcount = htons (p->num_authority_records);
  dns.additional_rcount = htons (p->num_additional_records);

  off = sizeof (struct GNUNET_TUN_DnsHeader);
  trc = GNUNET_NO;
  for (i=0;i<p->num_queries;i++)
  {
    ret = GNUNET_DNSPARSER_builder_add_query (tmp, sizeof (tmp), &off, &p->queries[i]);
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;
    if (GNUNET_NO == ret)
    {
      dns.query_count = htons ((uint16_t) (i-1));
      trc = GNUNET_YES;
      break;
    }
  }
  for (i=0;i<p->num_answers;i++)
  {
    ret = add_record (tmp, sizeof (tmp), &off, &p->answers[i]);
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;
    if (GNUNET_NO == ret)
    {
      dns.answer_rcount = htons ((uint16_t) (i-1));
      trc = GNUNET_YES;
      break;
    }
  }
  for (i=0;i<p->num_authority_records;i++)
  {
    ret = add_record (tmp, sizeof (tmp), &off, &p->authority_records[i]);
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;
    if (GNUNET_NO == ret)
    {
      dns.authority_rcount = htons ((uint16_t) (i-1));
      trc = GNUNET_YES;
      break;
    }
  }
  for (i=0;i<p->num_additional_records;i++)
  {
    ret = add_record (tmp, sizeof (tmp), &off, &p->additional_records[i]);
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;
    if (GNUNET_NO == ret)
    {
      dns.additional_rcount = htons (i-1);
      trc = GNUNET_YES;
      break;
    }
  }

  if (GNUNET_YES == trc)
    dns.flags.message_truncated = 1;
  memcpy (tmp, &dns, sizeof (struct GNUNET_TUN_DnsHeader));

  *buf = GNUNET_malloc (off);
  *buf_length = off;
  memcpy (*buf, tmp, off);
  if (GNUNET_YES == trc)
    return GNUNET_NO;
  return GNUNET_OK;
}

/* end of dnsparser.c */

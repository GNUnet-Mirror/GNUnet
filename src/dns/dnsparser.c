/*
      This file is part of GNUnet
      (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"


// DNS-Stuff
GNUNET_NETWORK_STRUCT_BEGIN
/* FIXME: replace this one with the one from tcpip_tun.h! */
struct GNUNET_TUN_DnsHeader
{
  uint16_t id GNUNET_PACKED;
  struct GNUNET_DNSPARSER_Flags flags; 
  uint16_t query_count GNUNET_PACKED;       // number of questions
  uint16_t answer_rcount GNUNET_PACKED;       // number of answers
  uint16_t authority_rcount GNUNET_PACKED;       // number of authority-records
  uint16_t additional_rcount GNUNET_PACKED;       // number of additional records
};

struct query_line
{
  uint16_t type GNUNET_PACKED;
  uint16_t class GNUNET_PACKED;
};

struct record_line
{
  uint16_t type GNUNET_PACKED;
  uint16_t class GNUNET_PACKED;
  uint32_t ttl GNUNET_PACKED;
  uint16_t data_len GNUNET_PACKED;
};

struct soa_data
{
  uint32_t serial GNUNET_PACKED;
  uint32_t refresh GNUNET_PACKED;
  uint32_t retry GNUNET_PACKED;
  uint32_t expire GNUNET_PACKED;
  uint32_t minimum GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Parse name inside of a DNS query or record.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of udp_payload
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
  
  ret = GNUNET_strdup ("");
  while (1)
  {
    if (*off >= udp_payload_length)
      goto error;
    len = input[*off];
    if (0 == len)
    {
      (*off)++;
      break;
    }
    if (len < 64)
    {
      if (*off + 1 + len > udp_payload_length)
	goto error;
      GNUNET_asprintf (&tmp,
		       "%s%.*s.",
		       ret,
		       (int) len,
		       &udp_payload[*off + 1]);
      GNUNET_free (ret);
      ret = tmp;
      *off += 1 + len;
    }
    else if ((64 | 128) == (len & (64 | 128)) )
    {
      if (depth > 32)
	goto error; /* hard bound on stack to prevent "infinite" recursion, disallow! */
      /* pointer to string */
      if (*off + 1 > udp_payload_length)
	goto error;
      xoff = ((len - (64 | 128)) << 8) + input[*off+1];
      xstr = parse_name (udp_payload,
			 udp_payload_length,
			 &xoff,
			 depth + 1);
      if (NULL == xstr)
	goto error;
      GNUNET_asprintf (&tmp,
		       "%s%s.",
		       ret,
		       xstr);
      GNUNET_free (ret);
      GNUNET_free (xstr);
      ret = tmp;
      if (strlen (ret) > udp_payload_length)
	goto error; /* we are looping (building an infinite string) */
      *off += 2;
      /* pointers always terminate names */
      break;
    } 
    else
    {
      /* neither pointer nor inline string, not supported... */
      goto error;
    }
  }
  if (0 < strlen(ret))
    ret[strlen(ret)-1] = '\0'; /* eat tailing '.' */
  return ret;
 error:  
  GNUNET_free (ret);
  return NULL;
}


/**
 * Parse a DNS query entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of udp_payload
 * @param off pointer to the offset of the query to parse in the udp_payload (to be
 *                    incremented by the size of the query)
 * @param q where to write the query information
 * @return GNUNET_OK on success, GNUNET_SYSERR if the query is malformed
 */
static int
parse_query (const char *udp_payload,
	     size_t udp_payload_length,
	     size_t *off,
	     struct GNUNET_DNSPARSER_Query *q)
{
  char *name;
  struct query_line ql;

  name = parse_name (udp_payload, 
		     udp_payload_length,
		     off, 0);
  if (NULL == name)
    return GNUNET_SYSERR;
  q->name = name;
  if (*off + sizeof (struct query_line) > udp_payload_length)
    return GNUNET_SYSERR;
  memcpy (&ql, &udp_payload[*off], sizeof (ql));
  *off += sizeof (ql);
  q->type = ntohs (ql.type);
  q->class = ntohs (ql.class);
  return GNUNET_OK;
}


/**
 * Parse a DNS record entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of udp_payload
 * @param off pointer to the offset of the record to parse in the udp_payload (to be
 *                    incremented by the size of the record)
 * @param r where to write the record information
 * @return GNUNET_OK on success, GNUNET_SYSERR if the record is malformed
 */
static int
parse_record (const char *udp_payload,
	      size_t udp_payload_length,
	      size_t *off,
	      struct GNUNET_DNSPARSER_Record *r)
{
  char *name;
  struct record_line rl;
  size_t old_off;
  struct soa_data soa;
  uint16_t mxpref;
  uint16_t data_len;

  name = parse_name (udp_payload, 
		     udp_payload_length,
		     off, 0);
  if (NULL == name)
    return GNUNET_SYSERR;
  r->name = name;
  if (*off + sizeof (struct record_line) > udp_payload_length)
    return GNUNET_SYSERR;
  memcpy (&rl, &udp_payload[*off], sizeof (rl));
  (*off) += sizeof (rl);
  r->type = ntohs (rl.type);
  r->class = ntohs (rl.class);
  r->expiration_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
											ntohl (rl.ttl)));
  data_len = ntohs (rl.data_len);
  if (*off + data_len > udp_payload_length)
    return GNUNET_SYSERR;
  switch (r->type)
  {
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    old_off = *off;
    r->data.hostname = parse_name (udp_payload,
				   udp_payload_length,
				   off, 0);    
    if ( (NULL == r->data.hostname) ||
	 (old_off + data_len != *off) )
      return GNUNET_SYSERR;
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_SOA:
    old_off = *off;
    r->data.soa = GNUNET_malloc (sizeof (struct GNUNET_DNSPARSER_SoaRecord));
    r->data.soa->mname = parse_name (udp_payload,
				     udp_payload_length,
				     off, 0);
    r->data.soa->rname = parse_name (udp_payload,
				     udp_payload_length,
				     off, 0);
    if ( (NULL == r->data.soa->mname) ||
	 (NULL == r->data.soa->rname) ||
	 (*off + sizeof (struct soa_data) > udp_payload_length) )
      return GNUNET_SYSERR;
    memcpy (&soa, &udp_payload[*off], sizeof (struct soa_data));
    r->data.soa->serial = ntohl (soa.serial);
    r->data.soa->refresh = ntohl (soa.refresh);
    r->data.soa->retry = ntohl (soa.retry);
    r->data.soa->expire = ntohl (soa.expire);
    r->data.soa->minimum_ttl = ntohl (soa.minimum);
    (*off) += sizeof (struct soa_data);
    if (old_off + data_len != *off) 
      return GNUNET_SYSERR;
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_MX:
    old_off = *off;
    if (*off + sizeof (uint16_t) > udp_payload_length)
      return GNUNET_SYSERR;
    memcpy (&mxpref, &udp_payload[*off], sizeof (uint16_t));    
    (*off) += sizeof (uint16_t);
    r->data.mx = GNUNET_malloc (sizeof (struct GNUNET_DNSPARSER_MxRecord));
    r->data.mx->preference = ntohs (mxpref);
    r->data.mx->mxhost = parse_name (udp_payload,
				     udp_payload_length,
				     off, 0);
    if (old_off + data_len != *off) 
      return GNUNET_SYSERR;
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
 * @param udp_payload_length number of bytes in udp_payload 
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
  p = GNUNET_malloc (sizeof (struct GNUNET_DNSPARSER_Packet));
  p->flags = dns->flags;
  p->id = dns->id;
  n = ntohs (dns->query_count);
  if (n > 0)
  {
    p->queries = GNUNET_malloc (n * sizeof (struct GNUNET_DNSPARSER_Query));
    p->num_queries = n;
    for (i=0;i<n;i++)
      if (GNUNET_OK !=
	  parse_query (udp_payload,
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
	  parse_record (udp_payload,
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
	  parse_record (udp_payload,
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
	  parse_record (udp_payload,
			udp_payload_length,
			&off,
			&p->additional_records[i]))
	goto error;   
  }
  return p;
 error:
  GNUNET_DNSPARSER_free_packet (p);
  return NULL;
}


/**
 * Free SOA information record.
 *
 * @param soa record to free
 */
static void
free_soa (struct GNUNET_DNSPARSER_SoaRecord *soa)
{
  if (NULL == soa)
    return;
  GNUNET_free_non_null (soa->mname);
  GNUNET_free_non_null (soa->rname);
  GNUNET_free (soa);      
}


/**
 * Free MX information record.
 *
 * @param mx record to free
 */
static void
free_mx (struct GNUNET_DNSPARSER_MxRecord *mx)
{
  if (NULL == mx)
    return;
  GNUNET_free_non_null (mx->mxhost);
  GNUNET_free (mx);      
}


static void
free_record (struct GNUNET_DNSPARSER_Record *r)
{
  GNUNET_free_non_null (r->name);
  switch (r->type)
  {
  case GNUNET_DNSPARSER_TYPE_MX:
    free_mx (r->data.mx);
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    free_soa (r->data.soa);
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
    free_record (&p->answers[i]);
  GNUNET_free_non_null (p->answers);
  for (i=0;i<p->num_authority_records;i++)
    free_record (&p->authority_records[i]);
  GNUNET_free_non_null (p->authority_records);
  for (i=0;i<p->num_additional_records;i++)
    free_record (&p->additional_records[i]);
  GNUNET_free_non_null (p->additional_records);
  GNUNET_free (p);
}


/* ********************** DNS packet assembly code **************** */


/**
 * Add a DNS name to the UDP packet at the given location.
 *
 * @param dst where to write the name
 * @param dst_len number of bytes in dst
 * @param off pointer to offset where to write the name (increment by bytes used)
 *            must not be changed if there is an error
 * @param name name to write
 * @return GNUNET_SYSERR if 'name' is invalid
 *         GNUNET_NO if 'name' did not fit
 *         GNUNET_OK if 'name' was added to 'dst'
 */
static int
add_name (char *dst,
	  size_t dst_len,
	  size_t *off,
	  const char *name)
{
  const char *dot;
  size_t start;
  size_t pos;
  size_t len;

  if (NULL == name)
    return GNUNET_SYSERR;
  start = *off;
  if (start + strlen (name) + 2 > dst_len)
    return GNUNET_NO;
  pos = start;
  do
  {
    dot = strchr (name, '.');
    if (NULL == dot)
      len = strlen (name);
    else
      len = dot - name;
    if ( (len >= 64) || (len == 0) )
      return GNUNET_NO; /* segment too long or empty */
    dst[pos++] = (char) (uint8_t) len;
    memcpy (&dst[pos], name, len);
    pos += len;
    name += len + 1; /* also skip dot */
  }
  while (NULL != dot);
  dst[pos++] = '\0'; /* terminator */
  *off = pos;
  return GNUNET_OK;
}


/**
 * Add a DNS query to the UDP packet at the given location.
 *
 * @param dst where to write the query
 * @param dst_len number of bytes in dst
 * @param off pointer to offset where to write the query (increment by bytes used)
 *            must not be changed if there is an error
 * @param query query to write
 * @return GNUNET_SYSERR if 'query' is invalid
 *         GNUNET_NO if 'query' did not fit
 *         GNUNET_OK if 'query' was added to 'dst'
 */
static int
add_query (char *dst,
	   size_t dst_len,
	   size_t *off,
	   const struct GNUNET_DNSPARSER_Query *query)
{
  int ret;
  struct query_line ql;

  ret = add_name (dst, dst_len - sizeof (struct query_line), off, query->name);
  if (ret != GNUNET_OK)
    return ret;
  ql.type = htons (query->type);
  ql.class = htons (query->class);
  memcpy (&dst[*off], &ql, sizeof (ql));
  (*off) += sizeof (ql);
  return GNUNET_OK;
}


/**
 * Add an MX record to the UDP packet at the given location.
 *
 * @param dst where to write the mx record
 * @param dst_len number of bytes in dst
 * @param off pointer to offset where to write the mx information (increment by bytes used);
 *            can also change if there was an error
 * @param mx mx information to write
 * @return GNUNET_SYSERR if 'mx' is invalid
 *         GNUNET_NO if 'mx' did not fit
 *         GNUNET_OK if 'mx' was added to 'dst'
 */
static int
add_mx (char *dst,
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
  return add_name (dst, dst_len, off, mx->mxhost);
}


/**
 * Add an SOA record to the UDP packet at the given location.
 *
 * @param dst where to write the SOA record
 * @param dst_len number of bytes in dst
 * @param off pointer to offset where to write the SOA information (increment by bytes used)
 *            can also change if there was an error
 * @param soa SOA information to write
 * @return GNUNET_SYSERR if 'soa' is invalid
 *         GNUNET_NO if 'soa' did not fit
 *         GNUNET_OK if 'soa' was added to 'dst'
 */
static int
add_soa (char *dst,
	 size_t dst_len,
	 size_t *off,
	 const struct GNUNET_DNSPARSER_SoaRecord *soa)
{
  struct soa_data sd;
  int ret;

  if ( (GNUNET_OK != (ret = add_name (dst,
				      dst_len,
				      off,
				      soa->mname))) ||
       (GNUNET_OK != (ret = add_name (dst,
				      dst_len,
				      off,
				      soa->rname)) ) )
    return ret;
  if (*off + sizeof (struct soa_data) > dst_len)
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
 * Add a DNS record to the UDP packet at the given location.
 *
 * @param dst where to write the query
 * @param dst_len number of bytes in dst
 * @param off pointer to offset where to write the query (increment by bytes used)
 *            must not be changed if there is an error
 * @param record record to write
 * @return GNUNET_SYSERR if 'record' is invalid
 *         GNUNET_NO if 'record' did not fit
 *         GNUNET_OK if 'record' was added to 'dst'
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
  struct record_line rl;

  start = *off;
  ret = add_name (dst, dst_len - sizeof (struct record_line), off, record->name);
  if (ret != GNUNET_OK)
    return ret;
  /* '*off' is now the position where we will need to write the record line */

  pos = *off + sizeof (struct record_line);
  switch (record->type)
  { 
  case GNUNET_DNSPARSER_TYPE_MX:
    ret = add_mx (dst, dst_len, &pos, record->data.mx);    
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    ret = add_soa (dst, dst_len, &pos, record->data.soa);
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    ret = add_name (dst, dst_len, &pos, record->data.hostname);
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
  if (ret != GNUNET_OK)
  {
    *off = start;
    return GNUNET_NO;
  }

  if (pos - (*off + sizeof (struct record_line)) > UINT16_MAX)
  {
    /* record data too long */
    *off = start;
    return GNUNET_NO;
  }
  rl.type = htons (record->type);
  rl.class = htons (record->class);
  rl.ttl = htonl (GNUNET_TIME_absolute_get_remaining (record->expiration_time).rel_value / 1000); /* in seconds */
  rl.data_len = htons ((uint16_t) (pos - (*off + sizeof (struct record_line))));
  memcpy (&dst[*off], &rl, sizeof (struct record_line));
  *off = pos;
  return GNUNET_OK;  
}


/**
 * Given a DNS packet, generate the corresponding UDP payload.
 * Note that we do not attempt to pack the strings with pointers
 * as this would complicate the code and this is about being 
 * simple and secure, not fast, fancy and broken like bind.
 *
 * @param p packet to pack
 * @param max maximum allowed size for the resulting UDP payload
 * @param buf set to a buffer with the packed message
 * @param buf_length set to the length of buf
 * @return GNUNET_SYSERR if 'p' is invalid
 *         GNUNET_NO if 'p' was truncated (but there is still a result in 'buf')
 *         GNUNET_OK if 'p' was packed completely into '*buf'
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
    ret = add_query (tmp, sizeof (tmp), &off, &p->queries[i]);  
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

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
struct dns_header
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
 * @return name as 0-terminated C string on success, NULL if the payload is malformed
 */
static char *
parse_name (const char *udp_payload,
	    size_t udp_payload_length,
	    size_t *off)
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
      /* pointer to string */
      if (*off + 1 > udp_payload_length)
	goto error;
      xoff = ((len - (64 | 128)) << 8) + input[*off+1];
      xstr = parse_name (udp_payload,
			 udp_payload_length,
			 &xoff);
      GNUNET_asprintf (&tmp,
		       "%s%s.",
		       ret,
		       xstr);
      GNUNET_free (ret);
      GNUNET_free (xstr);
      ret = tmp;
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
		     off);
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

  name = parse_name (udp_payload, 
		     udp_payload_length,
		     off);
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
  r->data_len = ntohs (rl.data_len);
  if (*off + r->data_len > udp_payload_length)
    return GNUNET_SYSERR;
  if (0 == r->data_len)
    return GNUNET_OK;
  switch (r->type)
  {
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    old_off = *off;
    r->data.hostname = parse_name (udp_payload,
				   udp_payload_length,
				   off);    
    if ( (NULL == r->data.hostname) ||
	 (old_off + r->data_len != *off) )
      return GNUNET_SYSERR;
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_SOA:
    old_off = *off;
    r->data.soa = GNUNET_malloc (sizeof (struct GNUNET_DNSPARSER_SoaRecord));
    r->data.soa->mname = parse_name (udp_payload,
				     udp_payload_length,
				     off);
    r->data.soa->rname = parse_name (udp_payload,
				     udp_payload_length,
				     off);
    if ( (NULL == r->data.soa->mname) ||
	 (NULL == r->data.soa->rname) ||
	 (*off + sizeof (soa) > udp_payload_length) )
      return GNUNET_SYSERR;
    memcpy (&soa, &udp_payload[*off], sizeof (soa));
    r->data.soa->serial = ntohl (soa.serial);
    r->data.soa->refresh = ntohl (soa.refresh);
    r->data.soa->retry = ntohl (soa.retry);
    r->data.soa->expire = ntohl (soa.expire);
    r->data.soa->minimum_ttl = ntohl (soa.minimum);
    (*off) += sizeof (soa);
    if (old_off + r->data_len != *off) 
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
				     off);
    if (old_off + r->data_len != *off) 
      return GNUNET_SYSERR;
    return GNUNET_OK;
  default:
    r->data.raw = GNUNET_malloc (r->data_len);
    memcpy (r->data.raw, &udp_payload[*off], r->data_len);
    break;
  }
  (*off) += r->data_len;
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
  const struct dns_header *dns;
  size_t off;
  unsigned int n;  
  unsigned int i;

  if (udp_payload_length < sizeof (struct dns_header))
    return NULL;
  dns = (const struct dns_header *) udp_payload;
  off = sizeof (struct dns_header);
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
    GNUNET_free_non_null (r->data.raw);
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


/**
 * Given a DNS packet, generate the corresponding UDP payload.
 *
 * @param p packet to pack
 * @param buf set to a buffer with the packed message
 * @param buf_length set to the length of buf
 * @return GNUNET_SYSERR if 'p' is invalid
 *         GNUNET_NO if 'p' was truncated (but there is still a result in 'buf')
 *         GNUNET_OK if 'p' was packed completely into '*buf'
 */
int
GNUNET_DNSPARSER_pack (struct GNUNET_DNSPARSER_Packet *p,
		       char **buf,
		       size_t *buf_length)
{
  // FIXME: not implemented
  GNUNET_break (0);
  return GNUNET_SYSERR;
}




/* legacy code follows */

/**
 * Parse a name from DNS to a normal .-delimited, 0-terminated string.
 *
 * @param d The destination of the name. Should have at least 255 bytes allocated.
 * @param src The DNS-Packet
 * @param idx The offset inside the Packet from which on the name should be read
 * @returns The offset of the first unparsed byte (the byte right behind the name)
 */
static unsigned int
parse_dns_name (char *d, const unsigned char *src, unsigned short idx)
{                               /*{{{ */
  char *dest = d;

  int len = src[idx++];

  while (len != 0)
  {
    if (len & 0xC0)
    {                           /* Compressed name, offset in this and the next octet */
      unsigned short offset = ((len & 0x3F) << 8) | src[idx++];

      parse_dns_name (dest, src, offset - 12);  /* 12 for the Header of the DNS-Packet, idx starts at 0 which is 12 bytes from the start of the packet */
      return idx;
    }
    memcpy (dest, src + idx, len);
    idx += len;
    dest += len;
    *dest = '.';
    dest++;
    len = src[idx++];
  };
  *dest = 0;

  return idx;
}

/*}}}*/

/**
 * Parse a complete DNS-Record from raw DNS-data to a struct dns_record
 *
 * @param data The DNS-data
 * @param dst Pointer to count pointers; individual pointers will be allocated
 * @param count Number of records to parse
 * @param idx The offset inside the Packet from which on the name should be read
 * @returns The offset of the first unparsed byte (the byte right behind the last record)
 */
static unsigned short
parse_dns_record (unsigned char *data,  /*{{{ */
                  struct dns_record **dst, unsigned short count,
                  unsigned short idx)
{
  int i;
  unsigned short _idx;

  for (i = 0; i < count; i++)
  {
    dst[i] = GNUNET_malloc (sizeof (struct dns_record));
    dst[i]->name = alloca (255);        // see RFC1035, no name can be longer than this.
    char *name = dst[i]->name;

    _idx = parse_dns_name (name, data, idx);
    dst[i]->namelen = _idx - idx;

    dst[i]->name = GNUNET_malloc (dst[i]->namelen);
    memcpy (dst[i]->name, name, dst[i]->namelen);

    idx = _idx;

    dst[i]->type = *((unsigned short *) (data + idx));
    idx += 2;
    dst[i]->class = *((unsigned short *) (data + idx));
    idx += 2;
    dst[i]->ttl = *((unsigned int *) (data + idx));
    idx += 4;
    dst[i]->data_len = *((unsigned short *) (data + idx));
    idx += 2;
    dst[i]->data = GNUNET_malloc (ntohs (dst[i]->data_len));
    memcpy (dst[i]->data, data + idx, ntohs (dst[i]->data_len));
    idx += ntohs (dst[i]->data_len);
  }
  return idx;
}                               /*}}} */

/**
 * Parse a raw DNS-Packet into an usable struct
 */
struct dns_pkt_parsed *
parse_dns_packet (struct dns_pkt *pkt)
{                               /*{{{ */
  struct dns_pkt_parsed *ppkt = GNUNET_malloc (sizeof (struct dns_pkt_parsed));

  memcpy (&ppkt->s, &pkt->s, sizeof pkt->s);

  unsigned short qdcount = ntohs (ppkt->s.qdcount);
  unsigned short ancount = ntohs (ppkt->s.ancount);
  unsigned short nscount = ntohs (ppkt->s.nscount);
  unsigned short arcount = ntohs (ppkt->s.arcount);

  ppkt->queries = GNUNET_malloc (qdcount * sizeof (struct dns_query *));
  ppkt->answers = GNUNET_malloc (ancount * sizeof (struct dns_record *));
  ppkt->nameservers = GNUNET_malloc (nscount * sizeof (struct dns_record *));
  ppkt->additional = GNUNET_malloc (arcount * sizeof (struct dns_record *));

  unsigned short idx = 0, _idx; /* This keeps track how far we have parsed the data */

  /* Parse the Query */
  int i;

  for (i = 0; i < qdcount; i++)
  {                             /*{{{ */
    ppkt->queries[i] = GNUNET_malloc (sizeof (struct dns_query));
    char *name = alloca (255);  /* see RFC1035, it can't be more than this. */

    _idx = parse_dns_name (name, pkt->data, idx);
    ppkt->queries[i]->namelen = _idx - idx;
    idx = _idx;

    ppkt->queries[i]->name = GNUNET_malloc (ppkt->queries[i]->namelen);
    memcpy (ppkt->queries[i]->name, name, ppkt->queries[i]->namelen);

    ppkt->queries[i]->qtype = *((unsigned short *) (pkt->data + idx));
    idx += 2;
    ppkt->queries[i]->qclass = *((unsigned short *) (pkt->data + idx));
    idx += 2;
  }
  /*}}} */
  idx = parse_dns_record (pkt->data, ppkt->answers, ancount, idx);
  idx = parse_dns_record (pkt->data, ppkt->nameservers, nscount, idx);
  idx = parse_dns_record (pkt->data, ppkt->additional, arcount, idx);
  return ppkt;
}                               /*}}} */

static void
unparse_dns_name (char *dest, char *src, size_t len)
{
  char *b = dest;
  char cnt = 0;

  dest++;
  while (*src != 0)
  {
    while (*src != '.' && *src != 0)
    {
      *dest = *src;
      src++;
      dest++;
      cnt++;
    }
    *b = cnt;
    cnt = 0;
    b = dest;
    dest++;
    src++;
  }
  *b = 0;
}

struct dns_pkt *
unparse_dns_packet (struct dns_pkt_parsed *ppkt)
{
  size_t size = sizeof (struct dns_pkt) - 1;
  int i;

  for (i = 0; i < ntohs (ppkt->s.qdcount); i++)
    size += ppkt->queries[i]->namelen + 1;

  for (i = 0; i < ntohs (ppkt->s.ancount); i++)
  {
    size += ppkt->answers[i]->namelen + 1;
    size += ppkt->answers[i]->data_len;
  }
  for (i = 0; i < ntohs (ppkt->s.nscount); i++)
  {
    size += ppkt->nameservers[i]->namelen + 1;
    size += ppkt->nameservers[i]->data_len;
  }
  for (i = 0; i < ntohs (ppkt->s.arcount); i++)
  {
    size += ppkt->additional[i]->namelen + 1;
    size += ppkt->additional[i]->data_len;
  }

  size +=
      4 * ntohs (ppkt->s.qdcount) + 10 * (ntohs (ppkt->s.ancount) +
                                          ntohs (ppkt->s.arcount) +
                                          ntohs (ppkt->s.nscount));

  struct dns_pkt *pkt = GNUNET_malloc (size);
  char *pkt_c = (char *) pkt;

  memcpy (&pkt->s, &ppkt->s, sizeof ppkt->s);
  size_t idx = sizeof ppkt->s;

  for (i = 0; i < ntohs (ppkt->s.qdcount); i++)
  {
    unparse_dns_name (&pkt_c[idx], ppkt->queries[i]->name,
                      ppkt->queries[i]->namelen);
    idx += ppkt->queries[i]->namelen;
    struct dns_query_line *d = (struct dns_query_line *) &pkt_c[idx];

    d->class = ppkt->queries[i]->qclass;
    d->type = ppkt->queries[i]->qtype;
    idx += sizeof (struct dns_query_line);
  }

  for (i = 0; i < ntohs (ppkt->s.ancount); i++)
  {
    unparse_dns_name (&pkt_c[idx], ppkt->answers[i]->name,
                      ppkt->answers[i]->namelen);
    idx += ppkt->answers[i]->namelen;
    struct dns_record_line *r = (struct dns_record_line *) &pkt_c[idx];

    r->type = ppkt->answers[i]->type;
    r->class = ppkt->answers[i]->class;
    r->ttl = ppkt->answers[i]->ttl;
    r->data_len = ppkt->answers[i]->data_len;
    idx += sizeof (struct dns_record_line);
    memcpy (&r->data, ppkt->answers[i]->data, ppkt->answers[i]->data_len);
    idx += ppkt->answers[i]->data_len;
  }

  for (i = 0; i < ntohs (ppkt->s.nscount); i++)
  {
    unparse_dns_name (&pkt_c[idx], ppkt->nameservers[i]->name,
                      ppkt->nameservers[i]->namelen);
    idx += ppkt->nameservers[i]->namelen;
    struct dns_record_line *r = (struct dns_record_line *) &pkt_c[idx];

    r->type = ppkt->nameservers[i]->type;
    r->class = ppkt->nameservers[i]->class;
    r->ttl = ppkt->nameservers[i]->ttl;
    r->data_len = ppkt->nameservers[i]->data_len;
    idx += sizeof (struct dns_record_line);
    memcpy (&r->data, ppkt->nameservers[i]->data,
            ppkt->nameservers[i]->data_len);
    idx += ppkt->nameservers[i]->data_len;
  }

  for (i = 0; i < ntohs (ppkt->s.arcount); i++)
  {
    unparse_dns_name (&pkt_c[idx], ppkt->additional[i]->name,
                      ppkt->additional[i]->namelen);
    idx += ppkt->additional[i]->namelen;
    struct dns_record_line *r = (struct dns_record_line *) &pkt_c[idx];

    r->type = ppkt->additional[i]->type;
    r->class = ppkt->additional[i]->class;
    r->ttl = ppkt->additional[i]->ttl;
    r->data_len = ppkt->additional[i]->data_len;
    idx += sizeof (struct dns_record_line);
    memcpy (&r->data, ppkt->additional[i]->data, ppkt->additional[i]->data_len);
    idx += ppkt->additional[i]->data_len;
  }

  return pkt;
}

void
free_parsed_dns_packet (struct dns_pkt_parsed *ppkt)
{
  unsigned short qdcount = ntohs (ppkt->s.qdcount);
  unsigned short ancount = ntohs (ppkt->s.ancount);
  unsigned short nscount = ntohs (ppkt->s.nscount);
  unsigned short arcount = ntohs (ppkt->s.arcount);

  int i;

  for (i = 0; i < qdcount; i++)
  {
    GNUNET_free (ppkt->queries[i]->name);
    GNUNET_free (ppkt->queries[i]);
  }
  GNUNET_free (ppkt->queries);
  for (i = 0; i < ancount; i++)
  {
    GNUNET_free (ppkt->answers[i]->name);
    GNUNET_free (ppkt->answers[i]->data);
    GNUNET_free (ppkt->answers[i]);
  }
  GNUNET_free (ppkt->answers);
  for (i = 0; i < nscount; i++)
  {
    GNUNET_free (ppkt->nameservers[i]->name);
    GNUNET_free (ppkt->nameservers[i]->data);
    GNUNET_free (ppkt->nameservers[i]);
  }
  GNUNET_free (ppkt->nameservers);
  for (i = 0; i < arcount; i++)
  {
    GNUNET_free (ppkt->additional[i]->name);
    GNUNET_free (ppkt->additional[i]->data);
    GNUNET_free (ppkt->additional[i]);
  }
  GNUNET_free (ppkt->additional);
  GNUNET_free (ppkt);
}

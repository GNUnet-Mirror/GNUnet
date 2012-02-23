#include "gns.h"

/**
 * Add a DNS name to the buffer at the given location.
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
 * Add an MX record to the buffer at the given location.
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
 * Add an SOA record to the buffer at the given location.
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
 * Add a DNS record to the buffer at the given location.
 *
 * @param dst where to write the record
 * @param dst_len number of bytes in dst
 * @param off pointer to offset where to write the query (increment by bytes used)
 *            must not be changed if there is an error
 * @param record record to write
 * @return GNUNET_SYSERR if 'record' is invalid
 *         GNUNET_NO if 'record' did not fit
 *         GNUNET_OK if 'record' was added to 'dst'
 */
static int
parse_record (char *dst,
	    size_t dst_len,
	    size_t *off,
	    const struct GNUNET_GNS_Record *record)
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

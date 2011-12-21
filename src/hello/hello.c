/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file hello/hello.c
 * @brief helper library for handling HELLOs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * A HELLO message is used to exchange information about
 * transports with other peers.  This struct is always
 * followed by the actual network addresses which have
 * the format:
 *
 * 1) transport-name (0-terminated)
 * 2) address-length (uint16_t, network byte order; possibly
 *    unaligned!)
 * 3) address expiration (GNUNET_TIME_AbsoluteNBO); possibly
 *    unaligned!)
 * 4) address (address-length bytes; possibly unaligned!)
 */
struct GNUNET_HELLO_Message
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_HELLO.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero (for alignment).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The public key of the peer.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

};
GNUNET_NETWORK_STRUCT_END

/**
 * Copy the given address information into
 * the given buffer using the format of HELLOs.
 *
 * @param address the address
 * @param expiration expiration for the address
 * @param target where to copy the address
 * @param max maximum number of bytes to copy to target
 * @return number of bytes copied, 0 if
 *         the target buffer was not big enough.
 */
size_t
GNUNET_HELLO_add_address (const struct GNUNET_HELLO_Address *address,
                          struct GNUNET_TIME_Absolute expiration, char *target,
                          size_t max)
{
  uint16_t alen;
  size_t slen;
  struct GNUNET_TIME_AbsoluteNBO exp;

  slen = strlen (address->transport_name) + 1;
  if (slen + sizeof (uint16_t) + sizeof (struct GNUNET_TIME_AbsoluteNBO) +
      address->address_length > max)
    return 0;
  exp = GNUNET_TIME_absolute_hton (expiration);
  alen = htons ((uint16_t) address->address_length);
  memcpy (target, address->transport_name, slen);
  memcpy (&target[slen], &alen, sizeof (uint16_t));
  slen += sizeof (uint16_t);
  memcpy (&target[slen], &exp, sizeof (struct GNUNET_TIME_AbsoluteNBO));
  slen += sizeof (struct GNUNET_TIME_AbsoluteNBO);
  memcpy (&target[slen], address->address, address->address_length);
  slen += address->address_length;
  return slen;
}


/**
 * Get the size of an address entry in a HELLO message.
 *
 * @param buf pointer to the start of the address entry
 * @param max maximum size of the entry (end of buf)
 * @param ralen set to the address length
 * @return size of the entry, or 0 if max is not large enough
 */
static size_t
get_hello_address_size (const char *buf, size_t max, uint16_t * ralen)
{
  const char *pos;
  uint16_t alen;
  size_t left;
  size_t slen;

  left = max;
  pos = buf;
  slen = 1;
  while ((left > 0) && ('\0' != *pos))
  {
    left--;
    pos++;
    slen++;
  }
  if (left == 0)
  {
    /* 0-termination not found */
    GNUNET_break_op (0);
    return 0;
  }
  pos++;
  if (left < sizeof (uint16_t) + sizeof (struct GNUNET_TIME_AbsoluteNBO))
  {
    /* not enough space for addrlen */
    GNUNET_break_op (0);
    return 0;
  }
  memcpy (&alen, pos, sizeof (uint16_t));
  alen = ntohs (alen);
  *ralen = alen;
  slen += alen + sizeof (uint16_t) + sizeof (struct GNUNET_TIME_AbsoluteNBO);
  if (max < slen)
  {
    /* not enough space for addr */
    GNUNET_break_op (0);
    return 0;
  }
  return slen;
}


/**
 * Construct a HELLO message given the public key,
 * expiration time and an iterator that spews the
 * transport addresses.
 *
 * @return the hello message
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_create (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                     *publicKey,
                     GNUNET_HELLO_GenerateAddressListCallback addrgen,
                     void *addrgen_cls)
{
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - 256 -
              sizeof (struct GNUNET_HELLO_Message)];
  size_t max;
  size_t used;
  size_t ret;
  struct GNUNET_HELLO_Message *hello;

  max = sizeof (buffer);
  used = 0;
  if (addrgen != NULL)
  {
    while (0 != (ret = addrgen (addrgen_cls, max, &buffer[used])))
    {
      max -= ret;
      used += ret;
    }
  }
  hello = GNUNET_malloc (sizeof (struct GNUNET_HELLO_Message) + used);
  hello->header.type = htons (GNUNET_MESSAGE_TYPE_HELLO);
  hello->header.size = htons (sizeof (struct GNUNET_HELLO_Message) + used);
  memcpy (&hello->publicKey, publicKey,
          sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  memcpy (&hello[1], buffer, used);
  return hello;
}


/**
 * Iterate over all of the addresses in the HELLO.
 *
 * @param msg HELLO to iterate over
 * @param return_modified if a modified copy should be returned,
 *         otherwise NULL will be returned
 * @param it iterator to call on each address
 * @param it_cls closure for it
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_iterate_addresses (const struct GNUNET_HELLO_Message *msg,
                                int return_modified,
                                GNUNET_HELLO_AddressIterator it, void *it_cls)
{
  struct GNUNET_HELLO_Address address;
  uint16_t msize;
  struct GNUNET_HELLO_Message *ret;
  const char *inptr;
  size_t insize;
  size_t esize;
  size_t wpos;
  char *woff;
  uint16_t alen;
  struct GNUNET_TIME_AbsoluteNBO expire;
  int iret;

  msize = GNUNET_HELLO_size (msg);
  if ((msize < sizeof (struct GNUNET_HELLO_Message)) ||
      (ntohs (msg->header.type) != GNUNET_MESSAGE_TYPE_HELLO))
    return NULL;
  ret = NULL;
  if (return_modified)
  {
    ret = GNUNET_malloc (msize);
    memcpy (ret, msg, msize);
  }
  inptr = (const char *) &msg[1];
  insize = msize - sizeof (struct GNUNET_HELLO_Message);
  wpos = 0;
  woff = (ret != NULL) ? (char *) &ret[1] : NULL;
  GNUNET_CRYPTO_hash (&msg->publicKey,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &address.peer.hashPubKey);
  while (insize > 0)
  {
    esize = get_hello_address_size (inptr, insize, &alen);
    if (esize == 0)
    {
      GNUNET_break (0);
      GNUNET_free_non_null (ret);
      return NULL;
    }
    memcpy (&expire,
            &inptr[esize - alen - sizeof (struct GNUNET_TIME_AbsoluteNBO)],
            sizeof (struct GNUNET_TIME_AbsoluteNBO));
    address.address = &inptr[esize - alen];
    address.address_length = alen;
    address.transport_name = inptr;
    iret = it (it_cls, &address, GNUNET_TIME_absolute_ntoh (expire));
    if (iret == GNUNET_SYSERR)
    {
      if (ret != NULL)
        ret->header.size = ntohs (sizeof (struct GNUNET_HELLO_Message) + wpos);
      return ret;
    }
    if ((iret == GNUNET_OK) && (ret != NULL))
    {
      memcpy (woff, inptr, esize);
      woff += esize;
      wpos += esize;
    }
    insize -= esize;
    inptr += esize;
  }
  if (ret != NULL)
    ret->header.size = ntohs (sizeof (struct GNUNET_HELLO_Message) + wpos);
  return ret;
}


struct ExpireContext
{
  const struct GNUNET_HELLO_Address *address;
  int found;
  struct GNUNET_TIME_Absolute expiration;
};


static int
get_match_exp (void *cls, const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct ExpireContext *ec = cls;

  if (0 == GNUNET_HELLO_address_cmp (address, ec->address))
  {
    ec->found = GNUNET_YES;
    ec->expiration = expiration;
    return GNUNET_SYSERR;       /* done here */
  }
  return GNUNET_OK;
}


struct MergeContext
{
  const struct GNUNET_HELLO_Message *h1;
  const struct GNUNET_HELLO_Message *h2;
  const struct GNUNET_HELLO_Message *other;
  char *buf;
  size_t max;
  size_t ret;
  int take_equal;

};


static int
copy_latest (void *cls, const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  struct MergeContext *mc = cls;
  struct ExpireContext ec;

  ec.address = address;
  ec.found = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (mc->other, GNUNET_NO, &get_match_exp, &ec);
  if ((ec.found == GNUNET_NO) ||
      (ec.expiration.abs_value < expiration.abs_value) ||
      ((ec.expiration.abs_value == expiration.abs_value) &&
       (mc->take_equal == GNUNET_YES)))
  {
    mc->ret +=
        GNUNET_HELLO_add_address (address, expiration, &mc->buf[mc->ret],
                                  mc->max - mc->ret);
  }
  return GNUNET_OK;
}


static size_t
merge_addr (void *cls, size_t max, void *buf)
{
  struct MergeContext *mc = cls;

  if (mc->h1 == NULL)
    return 0;
  mc->ret = 0;
  mc->max = max;
  mc->buf = buf;
  mc->take_equal = GNUNET_NO;
  mc->other = mc->h2;
  GNUNET_HELLO_iterate_addresses (mc->h1, GNUNET_NO, &copy_latest, mc);
  mc->take_equal = GNUNET_YES;
  mc->other = mc->h1;
  GNUNET_HELLO_iterate_addresses (mc->h2, GNUNET_NO, &copy_latest, mc);
  mc->h1 = NULL;
  return mc->ret;
}


/**
 * Construct a HELLO message by merging the
 * addresses in two existing HELLOs (which
 * must be for the same peer).
 *
 * @param h1 first HELLO message
 * @param h2 the second HELLO message
 * @return the combined hello message
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_merge (const struct GNUNET_HELLO_Message *h1,
                    const struct GNUNET_HELLO_Message *h2)
{
  struct MergeContext mc = { h1, h2, NULL, NULL, 0, 0, 0 };

  return GNUNET_HELLO_create (&h1->publicKey, &merge_addr, &mc);
}


struct DeltaContext
{
  struct GNUNET_TIME_Absolute expiration_limit;

  GNUNET_HELLO_AddressIterator it;

  void *it_cls;

  const struct GNUNET_HELLO_Message *old_hello;
};


static int
delta_match (void *cls, const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  struct DeltaContext *dc = cls;
  int ret;
  struct ExpireContext ec;

  ec.address = address;
  ec.found = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (dc->old_hello, GNUNET_NO, &get_match_exp,
                                  &ec);
  if ((ec.found == GNUNET_YES) &&
      ((ec.expiration.abs_value > expiration.abs_value) ||
       (ec.expiration.abs_value >= dc->expiration_limit.abs_value)))
    return GNUNET_YES;          /* skip */
  ret = dc->it (dc->it_cls, address, expiration);
  return ret;
}


/**
 * Iterate over addresses in "new_hello" that
 * are NOT already present in "old_hello".
 *
 * @param new_hello a HELLO message
 * @param old_hello a HELLO message
 * @param expiration_limit ignore addresses in old_hello
 *        that expired before the given time stamp
 * @param it iterator to call on each address
 * @param it_cls closure for it
 */
void
GNUNET_HELLO_iterate_new_addresses (const struct GNUNET_HELLO_Message
                                    *new_hello,
                                    const struct GNUNET_HELLO_Message
                                    *old_hello,
                                    struct GNUNET_TIME_Absolute
                                    expiration_limit,
                                    GNUNET_HELLO_AddressIterator it,
                                    void *it_cls)
{
  struct DeltaContext dc;

  dc.expiration_limit = expiration_limit;
  dc.it = it;
  dc.it_cls = it_cls;
  dc.old_hello = old_hello;
  GNUNET_HELLO_iterate_addresses (new_hello, GNUNET_NO, &delta_match, &dc);
}


/**
 * Return the size of the given HELLO message.
 * @param hello to inspect
 * @return the size, 0 if HELLO is invalid
 */
uint16_t
GNUNET_HELLO_size (const struct GNUNET_HELLO_Message *hello)
{
  uint16_t ret = ntohs (hello->header.size);

  if ((ret < sizeof (struct GNUNET_HELLO_Message)) ||
      (ntohs (hello->header.type) != GNUNET_MESSAGE_TYPE_HELLO))
    return 0;
  return ret;
}


/**
 * Get the public key from a HELLO message.
 *
 * @param hello the hello message
 * @param publicKey where to copy the public key information, can be NULL
 * @return GNUNET_SYSERR if the HELLO was malformed
 */
int
GNUNET_HELLO_get_key (const struct GNUNET_HELLO_Message *hello,
                      struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  uint16_t ret = ntohs (hello->header.size);

  if ((ret < sizeof (struct GNUNET_HELLO_Message)) ||
      (ntohs (hello->header.type) != GNUNET_MESSAGE_TYPE_HELLO))
    return GNUNET_SYSERR;
  *publicKey = hello->publicKey;
  return GNUNET_OK;
}


/**
 * Get the peer identity from a HELLO message.
 *
 * @param hello the hello message
 * @param peer where to store the peer's identity
 * @return GNUNET_SYSERR if the HELLO was malformed
 */
int
GNUNET_HELLO_get_id (const struct GNUNET_HELLO_Message *hello,
                     struct GNUNET_PeerIdentity *peer)
{
  uint16_t ret = ntohs (hello->header.size);

  if ((ret < sizeof (struct GNUNET_HELLO_Message)) ||
      (ntohs (hello->header.type) != GNUNET_MESSAGE_TYPE_HELLO))
    return GNUNET_SYSERR;
  GNUNET_CRYPTO_hash (&hello->publicKey,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &peer->hashPubKey);
  return GNUNET_OK;
}


/**
 * Get the header from a HELLO message, used so other code
 * can correctly send HELLO messages.
 *
 * @param hello the hello message
 *
 * @return header or NULL if the HELLO was malformed
 */
struct GNUNET_MessageHeader *
GNUNET_HELLO_get_header (struct GNUNET_HELLO_Message *hello)
{
  uint16_t ret = ntohs (hello->header.size);

  if ((ret < sizeof (struct GNUNET_HELLO_Message)) ||
      (ntohs (hello->header.type) != GNUNET_MESSAGE_TYPE_HELLO))
    return NULL;

  return &hello->header;
}


struct EqualsContext
{
  struct GNUNET_TIME_Absolute expiration_limit;

  struct GNUNET_TIME_Absolute result;

  const struct GNUNET_HELLO_Message *h2;

  const struct GNUNET_HELLO_Address *address;

  struct GNUNET_TIME_Absolute expiration;

  int found;

};


static int
find_other_matching (void *cls, const struct GNUNET_HELLO_Address *address,
                     struct GNUNET_TIME_Absolute expiration)
{
  struct EqualsContext *ec = cls;

  if (expiration.abs_value < ec->expiration_limit.abs_value)
    return GNUNET_YES;
  if (0 == GNUNET_HELLO_address_cmp (address, ec->address))
  {
    ec->found = GNUNET_YES;
    if (expiration.abs_value < ec->expiration.abs_value)
      ec->result = GNUNET_TIME_absolute_min (expiration, ec->result);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


static int
find_matching (void *cls, const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct EqualsContext *ec = cls;

  if (expiration.abs_value < ec->expiration_limit.abs_value)
    return GNUNET_YES;
  ec->address = address;
  ec->expiration = expiration;
  ec->found = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (ec->h2, GNUNET_NO, &find_other_matching, ec);
  if (ec->found == GNUNET_NO)
  {
    ec->result = GNUNET_TIME_UNIT_ZERO_ABS;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Test if two HELLO messages contain the same addresses.
 * If they only differ in expiration time, the lowest
 * expiration time larger than 'now' where they differ
 * is returned.
 *
 * @param h1 first HELLO message
 * @param h2 the second HELLO message
 * @param now time to use for deciding which addresses have
 *            expired and should not be considered at all
 * @return absolute time forever if the two HELLOs are
 *         totally identical; smallest timestamp >= now if
 *         they only differ in timestamps;
 *         zero if the some addresses with expirations >= now
 *         do not match at all
 */
struct GNUNET_TIME_Absolute
GNUNET_HELLO_equals (const struct GNUNET_HELLO_Message *h1,
                     const struct GNUNET_HELLO_Message *h2,
                     struct GNUNET_TIME_Absolute now)
{
  struct EqualsContext ec;

  if (0 !=
      memcmp (&h1->publicKey, &h2->publicKey,
              sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
    return GNUNET_TIME_UNIT_ZERO_ABS;
  ec.expiration_limit = now;
  ec.result = GNUNET_TIME_UNIT_FOREVER_ABS;
  ec.h2 = h2;
  GNUNET_HELLO_iterate_addresses (h1, GNUNET_NO, &find_matching, &ec);
  if (ec.result.abs_value == GNUNET_TIME_UNIT_ZERO.rel_value)
    return ec.result;
  ec.h2 = h1;
  GNUNET_HELLO_iterate_addresses (h2, GNUNET_NO, &find_matching, &ec);
  return ec.result;
}


static int
find_min_expire (void *cls, const struct GNUNET_HELLO_Address *address,
                 struct GNUNET_TIME_Absolute expiration)
{
  struct GNUNET_TIME_Absolute *min = cls;

  *min = GNUNET_TIME_absolute_min (*min, expiration);
  return GNUNET_OK;
}


/**
 * When does the last address in the given HELLO expire?
 *
 * @param msg HELLO to inspect
 * @return time the last address expires, 0 if there are no addresses in the HELLO
 */
struct GNUNET_TIME_Absolute
GNUNET_HELLO_get_last_expiration (const struct GNUNET_HELLO_Message *msg)
{
  struct GNUNET_TIME_Absolute ret;

  ret.abs_value = 0;
  GNUNET_HELLO_iterate_addresses (msg, GNUNET_NO, &find_min_expire, &ret);
  return ret;
}


/* end of hello.c */

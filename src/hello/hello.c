/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file hello/hello.c
 * @brief helper library for handling HELLOs
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_plugin.h"

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
 * 3) address expiration (`struct GNUNET_TIME_AbsoluteNBO`); possibly
 *    unaligned!)
 * 4) address (address-length bytes; possibly unaligned!)
 */
struct GNUNET_HELLO_Message
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_HELLO.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Use in F2F mode: Do not gossip this HELLO message
   */
  uint32_t friend_only GNUNET_PACKED;

  /**
   * The public key of the peer.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey publicKey;

};
GNUNET_NETWORK_STRUCT_END


/**
 * Context used for building our own URI.
 */
struct GNUNET_HELLO_ComposeUriContext
{
  /**
   * Final URI.
   */
  char *uri;

  /**
   * Function for finding transport plugins by name.
   */
  GNUNET_HELLO_TransportPluginsFind plugins_find;
};


/**
 * Context for #add_address_to_hello().
 */
struct GNUNET_HELLO_ParseUriContext
{
  /**
   * Position in the URI with the next address to parse.
   */
  const char *pos;

  /**
   * Set to #GNUNET_SYSERR to indicate parse errors.
   */
  int ret;

  /**
   * Counter
   */
  unsigned int counter_total;

  /**
   * Counter skipped addresses
   */
  unsigned int counter_added;

  /**
   * Function for finding transport plugins by name.
   */
  GNUNET_HELLO_TransportPluginsFind plugins_find;
};


/**
 * Return HELLO type
 *
 * @param h HELLO Message to test
 * @return #GNUNET_YES for friend-only or #GNUNET_NO otherwise
 */
int
GNUNET_HELLO_is_friend_only (const struct GNUNET_HELLO_Message *h)
{
  if (GNUNET_YES == ntohl(h->friend_only))
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Copy the given address information into
 * the given buffer using the format of HELLOs.
 *
 * @param address the address
 * @param expiration expiration for the @a address
 * @param target where to copy the @a address
 * @param max maximum number of bytes to copy to target
 * @return number of bytes copied, 0 if
 *         the target buffer was not big enough.
 */
size_t
GNUNET_HELLO_add_address (const struct GNUNET_HELLO_Address *address,
                          struct GNUNET_TIME_Absolute expiration,
                          char *target,
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
 * @param max maximum size of the entry (end of @a buf)
 * @param ralen set to the address length
 * @return size of the entry, or 0 if @a max is not large enough
 */
static size_t
get_hello_address_size (const char *buf,
			size_t max,
			uint16_t *ralen)
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
  if (0 == left)
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
 * If friend only is set to #GNUNET_YES we create a FRIEND_HELLO which
 * will not be gossiped to other peers.
 *
 * @param public_key public key to include in the HELLO
 * @param addrgen callback to invoke to get addresses
 * @param addrgen_cls closure for @a addrgen
 * @param friend_only should the returned HELLO be only visible to friends?
 * @return the hello message
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_create (const struct GNUNET_CRYPTO_EddsaPublicKey *public_key,
                     GNUNET_HELLO_GenerateAddressListCallback addrgen,
                     void *addrgen_cls,
                     int friend_only)
{
  char buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - 256 -
              sizeof (struct GNUNET_HELLO_Message)];
  size_t max;
  size_t used;
  size_t ret;
  struct GNUNET_HELLO_Message *hello;

  GNUNET_assert (NULL != public_key);
  GNUNET_assert ( (GNUNET_YES == friend_only) ||
                  (GNUNET_NO == friend_only) );
  max = sizeof (buffer);
  used = 0;
  if (NULL != addrgen)
  {
    while (GNUNET_SYSERR != (ret = addrgen (addrgen_cls,
                                            max,
                                            &buffer[used])))
    {
      max -= ret;
      used += ret;
    }
  }
  hello = GNUNET_malloc (sizeof (struct GNUNET_HELLO_Message) + used);
  hello->header.type = htons (GNUNET_MESSAGE_TYPE_HELLO);
  hello->header.size = htons (sizeof (struct GNUNET_HELLO_Message) + used);
  hello->friend_only = htonl (friend_only);
  hello->publicKey = *public_key;
  memcpy (&hello[1],
          buffer,
          used);
  return hello;
}


/**
 * Iterate over all of the addresses in the HELLO.
 *
 * @param msg HELLO to iterate over
 * @param return_modified if a modified copy should be returned,
 *         otherwise NULL will be returned
 * @param it iterator to call on each address
 * @param it_cls closure for @a it
 * @return modified HELLO message
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_iterate_addresses (const struct GNUNET_HELLO_Message *msg,
                                int return_modified,
                                GNUNET_HELLO_AddressIterator it,
                                void *it_cls)
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
    memcpy (ret,
            msg,
            msize);
  }
  inptr = (const char *) &msg[1];
  insize = msize - sizeof (struct GNUNET_HELLO_Message);
  wpos = 0;
  woff = (NULL != ret) ? (char *) &ret[1] : NULL;
  address.peer.public_key = msg->publicKey;
  while (insize > 0)
  {
    esize = get_hello_address_size (inptr,
                                    insize,
                                    &alen);
    if (0 == esize)
    {
      GNUNET_break (0);
      GNUNET_free_non_null (ret);
      return NULL;
    }
    /* need memcpy() due to possibility of misalignment */
    memcpy (&expire,
            &inptr[esize - alen - sizeof (struct GNUNET_TIME_AbsoluteNBO)],
            sizeof (struct GNUNET_TIME_AbsoluteNBO));
    address.address = &inptr[esize - alen];
    address.address_length = alen;
    address.transport_name = inptr;
    address.local_info = GNUNET_HELLO_ADDRESS_INFO_NONE;
    iret = it (it_cls,
               &address,
               GNUNET_TIME_absolute_ntoh (expire));
    if (GNUNET_SYSERR == iret)
      break;
    if ( (GNUNET_OK == iret) &&
         (NULL != ret) )
    {
      /* copy address over */
      memcpy (woff,
              inptr,
              esize);
      woff += esize;
      wpos += esize;
    }
    insize -= esize;
    inptr += esize;
  }
  if (NULL != ret)
    ret->header.size = ntohs (sizeof (struct GNUNET_HELLO_Message) + wpos);
  return ret;
}


/**
 * Closure for #get_match_exp().
 */
struct ExpireContext
{
  /**
   * Address we are looking for.
   */
  const struct GNUNET_HELLO_Address *address;

  /**
   * Set to #GNUNET_YES if we found the @e address.
   */
  int found;

  /**
   * Set to the expiration of the match if @e found is #GNUNET_YES.
   */
  struct GNUNET_TIME_Absolute expiration;
};


/**
 * Store the expiration time of an address that matches the template.
 *
 * @param cls the `struct ExpireContext`
 * @param address address to match against the template
 * @param expiration expiration time of @a address, to store in @a cls
 * @return #GNUNET_SYSERR if we found a matching address, #GNUNET_OK otherwise
 */
static int
get_match_exp (void *cls,
               const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct ExpireContext *ec = cls;

  if (0 != GNUNET_HELLO_address_cmp (address,
                                     ec->address))
    return GNUNET_OK;
  ec->found = GNUNET_YES;
  ec->expiration = expiration;
  return GNUNET_SYSERR;       /* done here */
}


/**
 * Context for a #GNUNET_HELLO_Merge operation.
 */
struct MergeContext
{
  /**
   * First HELLO we are merging.
   */
  const struct GNUNET_HELLO_Message *h1;

  /**
   * Second HELLO we are merging.
   */
  const struct GNUNET_HELLO_Message *h2;

  /**
   * Either @e h1 or @e h2, used when copying
   * to compare against (so we only copy the
   * most recent entry).
   */
  const struct GNUNET_HELLO_Message *other;

  /**
   * Buffer where we copy to.
   */
  char *buf;

  /**
   * Number of bytes allocated in @e buf
   */
  size_t max;

  /**
   * Current (write) offset in @e buf.
   */
  size_t ret;

  /**
   * Should we copy addresses with an identical value
   * and expiration time in @e other, or do we only
   * copy addresses with strictly later expiration times?
   */
  int take_equal;

};


/**
 * Append the address @a address to the buffer from
 * the merge context IF it is more recent than equivalent
 * addresses in `other`.
 *
 * @param cls the `struct MergeContext`
 * @param address the HELLO address we might copy
 * @param expiration expiration time for @a address
 * @return always #GNUNET_OK
 */
static int
copy_latest (void *cls,
             const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  struct MergeContext *mc = cls;
  struct ExpireContext ec;

  ec.address = address;
  ec.found = GNUNET_NO;
  /* check if address exists in other */
  GNUNET_HELLO_iterate_addresses (mc->other,
                                  GNUNET_NO,
                                  &get_match_exp,
                                  &ec);
  if ( (GNUNET_NO == ec.found) ||
       (ec.expiration.abs_value_us < expiration.abs_value_us) ||
       ( (ec.expiration.abs_value_us == expiration.abs_value_us) &&
         (GNUNET_YES == mc->take_equal) ) )
  {
    /* copy address to buffer */
    mc->ret +=
        GNUNET_HELLO_add_address (address,
                                  expiration,
                                  &mc->buf[mc->ret],
                                  mc->max - mc->ret);
  }
  return GNUNET_OK;
}


/**
 * Function called to build the HELLO during
 * #GNUNET_HELLO_merge() by merging addresses from
 * two original HELLOs.
 *
 * @param cls the `struct MergeContext`
 * @param max number of bytes we can write at most in @a buf
 * @param buf where to copy the addresses
 * @return #GNUNET_SYSERR to end iteration, otherwise number of bytes written to @a buf
 */
static ssize_t
merge_addr (void *cls,
            size_t max,
            void *buf)
{
  struct MergeContext *mc = cls;

  if (NULL == mc->h1)
    return GNUNET_SYSERR; /* Stop iteration */
  mc->ret = 0;
  mc->max = max;
  mc->buf = buf;
  mc->take_equal = GNUNET_NO;
  mc->other = mc->h2;
  /* copy addresses from h1, if strictly larger expiration than h2 */
  GNUNET_HELLO_iterate_addresses (mc->h1,
                                  GNUNET_NO,
                                  &copy_latest,
                                  mc);
  mc->take_equal = GNUNET_YES;
  mc->other = mc->h1;
  /* copy addresses from h2, if larger or equal expiration than h1 */
  GNUNET_HELLO_iterate_addresses (mc->h2,
                                  GNUNET_NO,
                                  &copy_latest,
                                  mc);
  /* set marker to stop iteration */
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
 * @return the combined HELLO message
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_merge (const struct GNUNET_HELLO_Message *h1,
                    const struct GNUNET_HELLO_Message *h2)
{
  struct MergeContext mc = { h1, h2, NULL, NULL, 0, 0, 0 };
  int friend_only;

  if (h1->friend_only != h2->friend_only)
    friend_only = GNUNET_YES; /* One of the HELLOs is friend only */
  else
    friend_only = ntohl (h1->friend_only); /* Both HELLO's have the same type */

  return GNUNET_HELLO_create (&h1->publicKey,
                              &merge_addr,
                              &mc,
                              friend_only);
}


/**
 * Context used in #GNUNET_HELLO_iterate_new_addresses() to
 * figure out which addresses are in fact 'new'.
 */
struct DeltaContext
{
  /**
   * We should ignore addresses that expire before this time.
   */
  struct GNUNET_TIME_Absolute expiration_limit;

  /**
   * Function to call on addresses that are indeed new.
   */
  GNUNET_HELLO_AddressIterator it;

  /**
   * Closure for @e it.
   */
  void *it_cls;

  /**
   * HELLO with known addresses, addresses in this HELLO
   * we must always ignore.
   */
  const struct GNUNET_HELLO_Message *old_hello;
};


/**
 * Check if the given address is 'new', and if so, call
 * the iterator.  Compares the existing address against
 * addresses in the context's `old_hello` and calls the
 * iterator on those that are new (and not expired).
 *
 * @param cls the `struct DeltaContext`
 * @param address an address to check whether it is new
 * @param expiration expiration time for @a address
 * @return #GNUNET_YES if the address is ignored, otherwise
 *         whatever the iterator returned.
 */
static int
delta_match (void *cls,
             const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  struct DeltaContext *dc = cls;
  int ret;
  struct ExpireContext ec;

  ec.address = address;
  ec.found = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (dc->old_hello,
                                  GNUNET_NO,
                                  &get_match_exp,
                                  &ec);
  if ( (GNUNET_YES == ec.found) &&
       ( (ec.expiration.abs_value_us > expiration.abs_value_us) ||
         (ec.expiration.abs_value_us >= dc->expiration_limit.abs_value_us)))
    return GNUNET_YES;          /* skip: found and boring */
  ret = dc->it (dc->it_cls,
                address,
                expiration);
  return ret;
}


/**
 * Iterate over addresses in @a new_hello that are NOT already present
 * in @a old_hello.  Note that if the address is present in @a old_hello
 * but the expiration time in @a new_hello is more recent, the iterator
 * is also called.
 *
 * @param new_hello a HELLO message
 * @param old_hello a HELLO message
 * @param expiration_limit ignore addresses in @a old_hello
 *        that expired before the given time stamp
 * @param it iterator to call on each address
 * @param it_cls closure for @a it
 */
void
GNUNET_HELLO_iterate_new_addresses (const struct GNUNET_HELLO_Message *new_hello,
                                    const struct GNUNET_HELLO_Message *old_hello,
                                    struct GNUNET_TIME_Absolute expiration_limit,
                                    GNUNET_HELLO_AddressIterator it,
                                    void *it_cls)
{
  struct DeltaContext dc;

  dc.expiration_limit = expiration_limit;
  dc.it = it;
  dc.it_cls = it_cls;
  dc.old_hello = old_hello;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (new_hello,
                                                 GNUNET_NO,
                                                 &delta_match,
                                                 &dc));
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
 * Get the peer identity from a HELLO message.
 *
 * @param hello the hello message
 * @param peer where to store the peer's identity
 * @return #GNUNET_SYSERR if the HELLO was malformed
 */
int
GNUNET_HELLO_get_id (const struct GNUNET_HELLO_Message *hello,
                     struct GNUNET_PeerIdentity *peer)
{
  uint16_t ret = ntohs (hello->header.size);

  if ((ret < sizeof (struct GNUNET_HELLO_Message)) ||
      (ntohs (hello->header.type) != GNUNET_MESSAGE_TYPE_HELLO))
    return GNUNET_SYSERR;
  peer->public_key = hello->publicKey;
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


/**
 * Context used for comparing HELLOs in #GNUNET_HELLO_equals().
 */
struct EqualsContext
{
  /**
   * Addresses that expired before this date are ignored for
   * the comparisson.
   */
  struct GNUNET_TIME_Absolute expiration_limit;

  /**
   * Earliest expiration time for which we found a match
   * with a difference in expiration times.
   * At this time, the two HELLOs may start to diverge.
   */
  struct GNUNET_TIME_Absolute result;

  /**
   * HELLO message to compare against. (First set to the second
   * HELLO, then set to the first HELLO.)
   */
  const struct GNUNET_HELLO_Message *ref;

  /**
   * Address we are currently looking for.
   */
  const struct GNUNET_HELLO_Address *address;

  /**
   * Expiration time of @e address.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Did we find the address we were looking for?
   */
  int found;

};


/**
 * Check if the given address matches the address we are currently
 * looking for. If so, sets `found` to #GNUNET_YES and, if the
 * expiration times for the two addresses differ, updates `result` to
 * the minimum of our @a expiration and the existing value
 *
 * @param cls the `struct EqualsContext`
 * @param address address from the reference HELLO
 * @param expiration expiration time for @a address
 * @return #GNUNET_YES if the address is expired or does not match
 *         #GNUNET_SYSERR if the address does match.
 */
static int
find_other_matching (void *cls,
                     const struct GNUNET_HELLO_Address *address,
                     struct GNUNET_TIME_Absolute expiration)
{
  struct EqualsContext *ec = cls;

  if (expiration.abs_value_us < ec->expiration_limit.abs_value_us)
    return GNUNET_YES;
  if (0 == GNUNET_HELLO_address_cmp (address, ec->address))
  {
    ec->found = GNUNET_YES;
    if (expiration.abs_value_us < ec->expiration.abs_value_us)
      ec->result = GNUNET_TIME_absolute_min (expiration,
                                             ec->result);
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Helper function for #GNUNET_HELLO_equals().  Checks
 * if the given @a address exists also in the other HELLO;
 * if not, the result time is set to zero and the iteration
 * is aborted.
 *
 * @param cls the `struct EqualsContext`
 * @param address address to locate
 * @param expiration expiration time of the current address
 * @return #GNUNET_OK if the address exists or is expired,
 *         #GNUNET_SYSERR if it was not found
 */
static int
find_matching (void *cls,
               const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct EqualsContext *ec = cls;

  if (expiration.abs_value_us < ec->expiration_limit.abs_value_us)
    return GNUNET_OK; /* expired, we don't care */
  ec->address = address;
  ec->expiration = expiration;
  ec->found = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (ec->ref,
                                  GNUNET_NO,
                                  &find_other_matching,
                                  ec);
  if (GNUNET_NO == ec->found)
  {
    /* not found, we differ *now* */
    ec->result = GNUNET_TIME_UNIT_ZERO_ABS;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Test if two HELLO messages contain the same addresses.
 * If they only differ in expiration time, the lowest
 * expiration time larger than @a now where they differ
 * is returned.
 *
 * @param h1 first HELLO message
 * @param h2 the second HELLO message
 * @param now time to use for deciding which addresses have
 *            expired and should not be considered at all
 * @return absolute time forever if the two HELLOs are
 *         totally identical; smallest timestamp >= @a now if
 *         they only differ in timestamps;
 *         zero if the some addresses with expirations >= @a now
 *         do not match at all
 */
struct GNUNET_TIME_Absolute
GNUNET_HELLO_equals (const struct GNUNET_HELLO_Message *h1,
                     const struct GNUNET_HELLO_Message *h2,
                     struct GNUNET_TIME_Absolute now)
{
  struct EqualsContext ec;

  if (h1->header.type != h2->header.type)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  if (0 !=
      memcmp (&h1->publicKey,
              &h2->publicKey,
              sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)))
    return GNUNET_TIME_UNIT_ZERO_ABS;
  ec.expiration_limit = now;
  ec.result = GNUNET_TIME_UNIT_FOREVER_ABS;
  ec.ref = h2;
  GNUNET_HELLO_iterate_addresses (h1,
                                  GNUNET_NO,
                                  &find_matching,
                                  &ec);
  if (ec.result.abs_value_us == GNUNET_TIME_UNIT_ZERO.rel_value_us)
    return ec.result;
  ec.ref = h1;
  GNUNET_HELLO_iterate_addresses (h2,
                                  GNUNET_NO,
                                  &find_matching,
                                  &ec);
  return ec.result;
}


/**
 * Iterator to find the time when the last address will expire.
 * Updates the maximum value stored in @a cls.
 *
 * @param cls where to store the max, a `struct GNUNET_TIME_Absolute`
 * @param address an address (ignored)
 * @param expiration expiration time for @a address
 * @return #GNUNET_OK (always)
 */
static int
find_max_expire (void *cls,
                 const struct GNUNET_HELLO_Address *address,
                 struct GNUNET_TIME_Absolute expiration)
{
  struct GNUNET_TIME_Absolute *max = cls;

  *max = GNUNET_TIME_absolute_max (*max, expiration);
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

  ret = GNUNET_TIME_UNIT_ZERO_ABS;
  GNUNET_HELLO_iterate_addresses (msg,
                                  GNUNET_NO,
                                  &find_max_expire,
                                  &ret);
  return ret;
}


/**
 * GNUnet URIs are of the general form "gnunet://MODULE/IDENTIFIER".
 * The specific structure of "IDENTIFIER" depends on the module and
 * maybe differenciated into additional subcategories if applicable.
 * This module only deals with hello identifiers (MODULE = "hello").
 * <p>
 *
 * The concrete URI format is:
 *
 * "gnunet://hello/PEER[+YYYYMMDDHHMMSS+<TYPE>+<ADDRESS>]...".
 * These URIs can be used to add a peer record to peerinfo service.
 * PEER is the string representation of peer's public key.
 * YYYYMMDDHHMMSS is the expiration date.
 * TYPE is a transport type.
 * ADDRESS is the address, its format depends upon the transport type.
 * The concrete transport types and corresponding address formats are:
 *
 * <ul><li>
 *
 * <TCP|UDP>!IPADDRESS
 * IPVDDRESS is either IPV4 .-delimited address in form of XXX.XXX.XXX.XXX:PPPPP
 * or IPV6 :-delimited address  with '[' and ']' (according to RFC2732):
 * [XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:PPPPP
 * PPPPP is the port number. May be 0.
 *
 * </li><li>
 *
 * [add SMTP, HTTP and other addresses here]
 *
 * </li></ul>
 *
 * The encoding for hexadecimal values is defined in the crypto_hash.c
 * module in the gnunetutil library and discussed there.
 *
 * Examples:
 *
 * gnunet://hello/V8XXK9GAN5ZJFRFQP8MQX3D83BZTSBQVHKWWD0JPE63Z821906EG+20120302010059+TCP+192.168.0.1:2086+TCP+64.23.8.174:0
 * gnunet://hello/V8XXK9GAN5ZJFRFQP8MQX3D83BZTSBQVHKWWD0JPE63Z821906EG+20120302010059+TCP+[2001:db8:85a3:8d3:1319:8a2e:370:7348]:2086
 *
 * <p>
 */



/**
 * Function that is called on each address of this peer.
 * Expands the corresponding URI string.
 *
 * @param cls the `struct GNUNET_HELLO_ComposeUriContext`
 * @param address address to add
 * @param expiration expiration time for the address
 * @return #GNUNET_OK (continue iteration).
 */
static int
add_address_to_uri (void *cls,
                    const struct GNUNET_HELLO_Address *address,
                    struct GNUNET_TIME_Absolute expiration)
{
  struct GNUNET_HELLO_ComposeUriContext *ctx = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  const char *addr;
  char *ret;
  char *addr_dup;
  char *pos;
  char tbuf[16] = "";
  char *client_str = "_client";
  struct tm *t;
  time_t seconds;

  papi = ctx->plugins_find (address->transport_name);
  if (papi == NULL)
  {
    /* Not an error - we might just not have the right plugin. */
    return GNUNET_OK;
  }
  if (NULL == papi->address_to_string)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"URI conversion not implemented for plugin `%s'\n",
		address->transport_name);
    return GNUNET_OK;
  }
  addr = papi->address_to_string (papi->cls, address->address, address->address_length);

  if ( (addr == NULL) || (strlen(addr) == 0) )
    return GNUNET_OK;

  addr_dup = GNUNET_strdup (addr);
  if (NULL != (pos = strstr (addr_dup, "_server")))
  	memcpy (pos, client_str, strlen(client_str)); /* Replace all server addresses with client addresses */

  seconds = expiration.abs_value_us / 1000LL / 1000LL;
  t = gmtime (&seconds);

  GNUNET_asprintf (&ret,
		   "%s%c%s%c%s%c%s",
		   ctx->uri,
		   GNUNET_HELLO_URI_SEP,
		   strftime (tbuf,
                             sizeof (tbuf),
                             "%Y%m%d%H%M%S",
                             t) ? tbuf : "0",
                   GNUNET_HELLO_URI_SEP,
		   address->transport_name,
		   GNUNET_HELLO_URI_SEP,
		   addr_dup);
  GNUNET_free (addr_dup);
  GNUNET_free (ctx->uri);
  ctx->uri = ret;
  return GNUNET_OK;
}


/**
 * Compose a hello URI string from a hello message.
 *
 * @param hello Hello message
 * @param plugins_find Function to find transport plugins by name
 * @return Hello URI string
 */
char *
GNUNET_HELLO_compose_uri (const struct GNUNET_HELLO_Message *hello,
                          GNUNET_HELLO_TransportPluginsFind plugins_find)
{
  struct GNUNET_HELLO_ComposeUriContext ctx;
  ctx.plugins_find = plugins_find;

  char *pkey = GNUNET_CRYPTO_eddsa_public_key_to_string (&(hello->publicKey));

  GNUNET_asprintf (&(ctx.uri),
                   "%s%s",
                   (GNUNET_YES == GNUNET_HELLO_is_friend_only (hello)) ? GNUNET_FRIEND_HELLO_URI_PREFIX : GNUNET_HELLO_URI_PREFIX,
                   pkey);
  GNUNET_free (pkey);

  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &add_address_to_uri, &ctx);
  return ctx.uri;
}


/* ************************* Parse HELLO URI ********************* */


/**
 * We're building a HELLO.  Parse the next address from the
 * parsing context and append it.
 *
 * @param cls the `struct GNUNET_HELLO_ParseUriContext`
 * @param max number of bytes available for HELLO construction
 * @param buffer where to copy the next address (in binary format)
 * @return number of bytes added to buffer, #GNUNET_SYSERR on error
 */
static ssize_t
add_address_to_hello (void *cls,
                      size_t max,
                      void *buffer)
{
  struct GNUNET_HELLO_ParseUriContext *ctx = cls;
  const char *tname;
  const char *address;
  char *uri_address;
  const char *end;
  char *plugin_name;
  struct tm expiration_time;
  time_t expiration_seconds;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  void *addr;
  size_t addr_len;
  struct GNUNET_HELLO_Address haddr;
  ssize_t ret;

  if (NULL == ctx->pos)
    return GNUNET_SYSERR;
  if (GNUNET_HELLO_URI_SEP != ctx->pos[0])
  {
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ctx->pos++;

  if ( ('0' == ctx->pos[0]) &&
       (GNUNET_HELLO_URI_SEP == ctx->pos[1]) )
  {
    expire = GNUNET_TIME_UNIT_FOREVER_ABS;
    tname = ctx->pos + 1;
  }
  else
  {
    memset (&expiration_time, 0, sizeof (expiration_time));
    tname = strptime (ctx->pos,
                      "%Y%m%d%H%M%S",
                      &expiration_time);
    if (NULL == tname)
    {
      ctx->ret = GNUNET_SYSERR;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to parse HELLO message: missing expiration time\n"));
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    expiration_seconds = mktime (&expiration_time);
    if (expiration_seconds == (time_t) -1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to parse HELLO message: invalid expiration time\n"));
      ctx->ret = GNUNET_SYSERR;
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    expire.abs_value_us = expiration_seconds * 1000LL * 1000LL;
  }
  if (GNUNET_HELLO_URI_SEP != tname[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse HELLO message: malformed\n"));
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  tname++;
  address = strchr (tname, (int) GNUNET_HELLO_URI_SEP);
  if (NULL == address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse HELLO message: missing transport plugin\n"));
    ctx->ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  address++;
  end = strchr (address, (int) GNUNET_HELLO_URI_SEP);
  ctx->pos = end;
  ctx->counter_total ++;
  plugin_name = GNUNET_strndup (tname, address - (tname+1));
  papi = ctx->plugins_find (plugin_name);
  if (NULL == papi)
  {
    /* Not an error - we might just not have the right plugin.
     * Skip this part, advance to the next one and recurse.
     * But only if this is not the end of string.
     */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Plugin `%s' not found, skipping address\n"),
                plugin_name);
    GNUNET_free (plugin_name);
    return 0;
  }
  if (NULL == papi->string_to_address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Plugin `%s' does not support URIs yet\n"),
		plugin_name);
    GNUNET_free (plugin_name);
    GNUNET_break (0);
    return 0;
  }
  uri_address = GNUNET_strndup (address, end - address);
  if (GNUNET_OK !=
      papi->string_to_address (papi->cls,
                               uri_address,
			       strlen (uri_address) + 1,
			       &addr,
			       &addr_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to parse `%s' as an address for plugin `%s'\n"),
                uri_address,
		plugin_name);
    GNUNET_free (plugin_name);
    GNUNET_free (uri_address);
    return 0;
  }
  GNUNET_free (uri_address);
  /* address.peer is unset - not used by add_address() */
  haddr.address_length = addr_len;
  haddr.address = addr;
  haddr.transport_name = plugin_name;
  ret = GNUNET_HELLO_add_address (&haddr, expire, buffer, max);
  ctx->counter_added ++;
  GNUNET_free (addr);
  GNUNET_free (plugin_name);
  return ret;
}


/**
 * Parse a hello URI string to a hello message.
 *
 * @param uri URI string to parse
 * @param pubkey Pointer to struct where public key is parsed
 * @param hello Pointer to struct where hello message is parsed
 * @param plugins_find Function to find transport plugins by name
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the URI was invalid, #GNUNET_NO on other errors
 */
int
GNUNET_HELLO_parse_uri (const char *uri,
                        struct GNUNET_CRYPTO_EddsaPublicKey *pubkey,
                        struct GNUNET_HELLO_Message **hello,
                        GNUNET_HELLO_TransportPluginsFind plugins_find)
{
  const char *pks;
  const char *exc;
  int friend_only;
  struct GNUNET_HELLO_ParseUriContext ctx;

  if (0 == strncmp (uri,
		    GNUNET_HELLO_URI_PREFIX,
		    strlen (GNUNET_HELLO_URI_PREFIX)))
  {
    pks = &uri[strlen (GNUNET_HELLO_URI_PREFIX)];
    friend_only = GNUNET_NO;
  }
  else if (0 == strncmp (uri,
	    GNUNET_FRIEND_HELLO_URI_PREFIX,
	    strlen (GNUNET_FRIEND_HELLO_URI_PREFIX)))
  {
    pks = &uri[strlen (GNUNET_FRIEND_HELLO_URI_PREFIX)];
    friend_only = GNUNET_YES;
  }
  else
    return GNUNET_SYSERR;
  exc = strchr (pks, GNUNET_HELLO_URI_SEP);

  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (pks,
                                     (NULL == exc) ? strlen (pks) : (exc - pks),
                                     (unsigned char *) pubkey,
                                     sizeof (*pubkey)))
    return GNUNET_SYSERR;

  ctx.pos = exc;
  ctx.ret = GNUNET_OK;
  ctx.counter_total = 0;
  ctx.counter_added = 0;
  ctx.plugins_find = plugins_find;
  *hello = GNUNET_HELLO_create (pubkey,
                                &add_address_to_hello,
                                &ctx,
                                friend_only);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "HELLO URI contained %u addresses, added %u addresses\n",
              ctx.counter_total,
              ctx.counter_added);

  return ctx.ret;
}


/* end of hello.c */

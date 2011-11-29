/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_hello_lib.h
 * @brief helper library for handling HELLOs
 * @author Christian Grothoff
 */

#ifndef GNUNET_HELLO_LIB_H
#define GNUNET_HELLO_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"


/**
 * An address for communicating with a peer.  We frequently
 * need this tuple and the components cannot really be
 * separated.  This is NOT the format that would be used
 * on the wire.
 */
struct GNUNET_HELLO_Address
{

  /**
   * For which peer is this an address?
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Name of the transport plugin enabling the communication using
   * this address.
   */
  const char *transport_name;

  /**
   * Binary representation of the address (plugin-specific).
   */
  const void *address;

  /**
   * Number of bytes in 'address'.
   */
  size_t address_length;

};


/**
 * Allocate an address struct.
 *
 * @param peer the peer
 * @param transport_name plugin name
 * @param address binary address
 * @param address_length number of bytes in 'address'
 * @return the address struct
 */
struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_allocate (const struct GNUNET_PeerIdentity *peer,
                               const char *transport_name, const void *address,
                               size_t address_length);


/**
 * Copy an address struct.
 *
 * @param address address to copy
 * @return a copy of the address struct
 */
struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_copy (const struct GNUNET_HELLO_Address *address);


/**
 * Compare two addresses.  Does NOT compare the peer identity,
 * that is assumed already to match!
 *
 * @param a1 first address
 * @param a2 second address
 * @return 0 if the addresses are equal, -1 if a1<a2, 1 if a1>a2.
 */
int
GNUNET_HELLO_address_cmp (const struct GNUNET_HELLO_Address *a1,
                          const struct GNUNET_HELLO_Address *a2);


/**
 * Get the size of an address struct.
 *
 * @param address address
 * @return the size
 */
size_t
GNUNET_HELLO_address_get_size (const struct GNUNET_HELLO_Address *address);

/**
 * Free an address.
 *
 * @param addr address to free
 */
#define GNUNET_HELLO_address_free(addr) GNUNET_free(addr)


/**
 * A HELLO message is used to exchange information about
 * transports with other peers.  This struct is guaranteed
 * to start with a "GNUNET_MessageHeader", everything else
 * should be internal to the HELLO library.
 */
struct GNUNET_HELLO_Message;


/**
 * Copy the given address information into
 * the given buffer using the format of HELLOs.
 *
 * @param address address to add
 * @param expiration expiration for the address
 * @param target where to copy the address
 * @param max maximum number of bytes to copy to target
 * @return number of bytes copied, 0 if
 *         the target buffer was not big enough.
 */
size_t
GNUNET_HELLO_add_address (const struct GNUNET_HELLO_Address *address,
                          struct GNUNET_TIME_Absolute expiration, char *target,
                          size_t max);


/**
 * Callback function used to fill a buffer of max bytes with a list of
 * addresses in the format used by HELLOs.  Should use
 * "GNUNET_HELLO_add_address" as a helper function.
 *
 * @param cls closure
 * @param max maximum number of bytes that can be written to buf
 * @param buf where to write the address information
 * @return number of bytes written, 0 to signal the
 *         end of the iteration.
 */
typedef size_t (*GNUNET_HELLO_GenerateAddressListCallback) (void *cls,
                                                            size_t max,
                                                            void *buf);


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
                     void *addrgen_cls);


/**
 * Return the size of the given HELLO message.
 * @param hello to inspect
 * @return the size, 0 if HELLO is invalid
 */
uint16_t
GNUNET_HELLO_size (const struct GNUNET_HELLO_Message *hello);


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
                    const struct GNUNET_HELLO_Message *h2);


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
                     struct GNUNET_TIME_Absolute now);


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param address the address
 * @param expiration expiration time
 * @return GNUNET_OK to keep the address,
 *         GNUNET_NO to delete it from the HELLO
 *         GNUNET_SYSERR to stop iterating (but keep current address)
 */
typedef int (*GNUNET_HELLO_AddressIterator) (void *cls,
                                             const struct GNUNET_HELLO_Address *
                                             address,
                                             struct GNUNET_TIME_Absolute
                                             expiration);


/**
 * When does the last address in the given HELLO expire?
 *
 * @param msg HELLO to inspect
 * @return time the last address expires, 0 if there are no addresses in the HELLO
 */
struct GNUNET_TIME_Absolute
GNUNET_HELLO_get_last_expiration (const struct GNUNET_HELLO_Message *msg);


/**
 * Iterate over all of the addresses in the HELLO.
 *
 * @param msg HELLO to iterate over; client does not need to
 *        have verified that msg is well-formed (beyond starting
 *        with a GNUNET_MessageHeader of the right type).
 * @param return_modified if a modified copy should be returned,
 *         otherwise NULL will be returned
 * @param it iterator to call on each address
 * @param it_cls closure for it
 * @return the modified HELLO or NULL
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_iterate_addresses (const struct GNUNET_HELLO_Message *msg,
                                int return_modified,
                                GNUNET_HELLO_AddressIterator it, void *it_cls);


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
                                    void *it_cls);


/**
 * Get the public key from a HELLO message.
 *
 * @param hello the hello message
 * @param publicKey where to copy the public key information, can be NULL
 * @return GNUNET_SYSERR if the HELLO was malformed
 */
int
GNUNET_HELLO_get_key (const struct GNUNET_HELLO_Message *hello,
                      struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                      *publicKey);


/**
 * Get the peer identity from a HELLO message.
 *
 * @param hello the hello message
 * @param peer where to store the peer's identity
 * @return GNUNET_SYSERR if the HELLO was malformed
 */
int
GNUNET_HELLO_get_id (const struct GNUNET_HELLO_Message *hello,
                     struct GNUNET_PeerIdentity *peer);


/**
 * Get the header from a HELLO message, used so other code
 * can correctly send HELLO messages.
 *
 * @param hello the hello message
 *
 * @return header or NULL if the HELLO was malformed
 */
struct GNUNET_MessageHeader *
GNUNET_HELLO_get_header (struct GNUNET_HELLO_Message *hello);

/* ifndef GNUNET_HELLO_LIB_H */
#endif
/* end of gnunet_hello_lib.h */

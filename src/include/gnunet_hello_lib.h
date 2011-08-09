/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2010 Christian Grothoff (and other contributing authors)

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
 * @param tname name of the transport plugin
 * @param expiration expiration for the address
 * @param addr the address
 * @param addr_len length of the address in bytes
 * @param target where to copy the address
 * @param max maximum number of bytes to copy to target
 * @return number of bytes copied, 0 if
 *         the target buffer was not big enough.
 */
size_t
GNUNET_HELLO_add_address (const char *tname,
                          struct GNUNET_TIME_Absolute expiration,
                          const void *addr,
                          uint16_t addr_len, char *target, size_t max);


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
typedef size_t
  (*GNUNET_HELLO_GenerateAddressListCallback) (void *cls,
                                               size_t max, void *buf);


/**
 * Construct a HELLO message given the public key,
 * expiration time and an iterator that spews the
 * transport addresses.
 *
 * @return the hello message
 */
struct GNUNET_HELLO_Message *GNUNET_HELLO_create (const struct
                                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                                                  *publicKey,
                                                  GNUNET_HELLO_GenerateAddressListCallback
                                                  addrgen, void *addrgen_cls);


/**
 * Return the size of the given HELLO message.
 * @param hello to inspect
 * @return the size, 0 if HELLO is invalid
 */
uint16_t GNUNET_HELLO_size (const struct GNUNET_HELLO_Message *hello);


/**
 * Construct a HELLO message by merging the
 * addresses in two existing HELLOs (which
 * must be for the same peer).
 *
 * @param h1 first HELLO message
 * @param h2 the second HELLO message
 * @return the combined hello message
 */
struct GNUNET_HELLO_Message *GNUNET_HELLO_merge (const struct
                                                 GNUNET_HELLO_Message *h1,
                                                 const struct
                                                 GNUNET_HELLO_Message *h2);


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
GNUNET_HELLO_equals (const struct
		     GNUNET_HELLO_Message *h1,
		     const struct
		     GNUNET_HELLO_Message *h2,
		     struct GNUNET_TIME_Absolute now);


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK to keep the address,
 *         GNUNET_NO to delete it from the HELLO
 *         GNUNET_SYSERR to stop iterating (but keep current address)
 */
typedef int
  (*GNUNET_HELLO_AddressIterator) (void *cls,
                                   const char *tname,
                                   struct GNUNET_TIME_Absolute expiration,
                                   const void *addr, 
				   uint16_t addrlen);


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
struct GNUNET_HELLO_Message *GNUNET_HELLO_iterate_addresses (const struct
                                                             GNUNET_HELLO_Message
                                                             *msg,
                                                             int
                                                             return_modified,
                                                             GNUNET_HELLO_AddressIterator
                                                             it,
                                                             void *it_cls);


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

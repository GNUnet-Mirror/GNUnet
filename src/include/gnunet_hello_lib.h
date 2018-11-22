/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2010, 2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @author Christian Grothoff
 * @file
 * Helper library for handling HELLOs
 *
 * @defgroup hello  Hello library
 * Helper library for handling HELLOs
 *
 * @see [Documentation](https://gnunet.org/gnunets-hostlist-subsystem)
 *
 * @{
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

#include "gnunet_util_lib.h"


/**
 * Prefix that every HELLO URI must start with.
 */
#define GNUNET_HELLO_URI_PREFIX "gnunet://hello/"

/**
 * Prefix that every FRIEND HELLO URI must start with.
 */
#define GNUNET_FRIEND_HELLO_URI_PREFIX "gnunet://friend-hello/"

/**
 * Separator used in HELLO URI
 */
#define GNUNET_HELLO_URI_SEP '+'


/**
 * Additional local information about an address
 *
 * These information are only valid for the local peer and are not serialized
 * when a #GNUNET_HELLO_Message is created
 */
enum GNUNET_HELLO_AddressInfo
{
  /**
   * No additional information
   */
  GNUNET_HELLO_ADDRESS_INFO_NONE = 0,

  /**
   * This is an inbound address and cannot be used to initiate an outbound
   * connection to another peer
   */
  GNUNET_HELLO_ADDRESS_INFO_INBOUND = 1
};


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
   * Number of bytes in @e address.
   */
  size_t address_length;

  /**
   * Extended information about address
   *
   * This field contains additional #GNUNET_HELLO_AddressInfo flags e.g.
   * to indicate an address is inbound and cannot be used to initiate an
   * outbound connection.
   *
   * These information are only valid for the local peer and are not serialized
   * when a #GNUNET_HELLO_Message is created
   */
  enum GNUNET_HELLO_AddressInfo local_info;

};


/**
 * Allocate an address struct.
 *
 * @param peer the peer
 * @param transport_name plugin name
 * @param address binary address
 * @param address_length number of bytes in @a address
 * @param local_info additional local information for the address
 * @return the address struct
 */
struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_allocate (const struct GNUNET_PeerIdentity *peer,
                               const char *transport_name,
                               const void *address,
                               size_t address_length,
                               enum GNUNET_HELLO_AddressInfo local_info);


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
 * @return 0 if the addresses are equal, -1 if @a a1< @a a2, 1 if @a a1> @a a2.
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
 * Check if an address has a local option set
 *
 * @param address the address to check
 * @param option the respective option to check for
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GNUNET_HELLO_address_check_option (const struct GNUNET_HELLO_Address *address,
                                   enum GNUNET_HELLO_AddressInfo option);


/**
 * Free an address.
 *
 * @param addr address to free
 */
#define GNUNET_HELLO_address_free(addr) GNUNET_free(addr)


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
 * Return HELLO type
 *
 * @param h HELLO Message to test
 * @return #GNUNET_YES for friend-only or #GNUNET_NO otherwise
 */
int
GNUNET_HELLO_is_friend_only (const struct GNUNET_HELLO_Message *h);


/**
 * Copy the given address information into
 * the given buffer using the format of HELLOs.
 *
 * @param address address to add
 * @param expiration expiration for the address
 * @param target where to copy the address
 * @param max maximum number of bytes to copy to @a target
 * @return number of bytes copied, 0 if
 *         the target buffer was not big enough.
 */
size_t
GNUNET_HELLO_add_address (const struct GNUNET_HELLO_Address *address,
                          struct GNUNET_TIME_Absolute expiration,
                          char *target,
                          size_t max);


/**
 * Callback function used to fill a buffer of max bytes with a list of
 * addresses in the format used by HELLOs.  Should use
 * #GNUNET_HELLO_add_address() as a helper function.
 *
 * @param cls closure
 * @param max maximum number of bytes that can be written to @a buf
 * @param buf where to write the address information
 * @return number of bytes written or 0, #GNUNET_SYSERR to signal the
 *         end of the iteration.
 */
typedef ssize_t
(*GNUNET_HELLO_GenerateAddressListCallback) (void *cls,
                                             size_t max,
                                             void *buf);


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
                     int friend_only);


/**
 * Return the size of the given HELLO message.
 *
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
 * @return #GNUNET_OK to keep the address,
 *         #GNUNET_NO to delete it from the HELLO
 *         #GNUNET_SYSERR to stop iterating (but keep current address)
 */
typedef int
(*GNUNET_HELLO_AddressIterator) (void *cls,
                                 const struct GNUNET_HELLO_Address *address,
                                 struct GNUNET_TIME_Absolute expiration);


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
 * @param it_cls closure for @a it
 * @return the modified HELLO or NULL
 */
struct GNUNET_HELLO_Message *
GNUNET_HELLO_iterate_addresses (const struct GNUNET_HELLO_Message *msg,
                                int return_modified,
                                GNUNET_HELLO_AddressIterator it, void *it_cls);


/**
 * Iterate over addresses in @a new_hello that are NOT already present
 * in @a old_hello. Note that if the address is present in @a old_hello
 * but the expiration time in @a new_hello is more recent, the
 * iterator is also called.
 *
 * @param new_hello a HELLO message
 * @param old_hello a HELLO message
 * @param expiration_limit ignore addresses in old_hello
 *        that expired before the given time stamp
 * @param it iterator to call on each address
 * @param it_cls closure for @a it
 */
void
GNUNET_HELLO_iterate_new_addresses (const struct GNUNET_HELLO_Message *new_hello,
                                    const struct GNUNET_HELLO_Message *old_hello,
                                    struct GNUNET_TIME_Absolute expiration_limit,
                                    GNUNET_HELLO_AddressIterator it,
                                    void *it_cls);


/**
 * Get the peer identity from a HELLO message.
 *
 * @param hello the hello message
 * @param peer where to store the peer's identity
 * @return #GNUNET_SYSERR if the HELLO was malformed
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


/**
 * Helper function to load/access transport plugins.
 * FIXME: pass closure!
 *
 * @param name name of the transport plugin to load
 * @return NULL if a plugin with name @a name is not known/loadable
 */
typedef struct GNUNET_TRANSPORT_PluginFunctions *
(*GNUNET_HELLO_TransportPluginsFind) (const char *name);


/**
 * Compose a hello URI string from a hello message.
 *
 * @param hello Hello message
 * @param plugins_find Function to find transport plugins by name
 * @return Hello URI string
 */
char *
GNUNET_HELLO_compose_uri (const struct GNUNET_HELLO_Message *hello,
                          GNUNET_HELLO_TransportPluginsFind plugins_find);


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
                        GNUNET_HELLO_TransportPluginsFind plugins_find);



/* NG API */

/**
 * Build address record by signing raw information with private key.
 *
 * @param address text address to sign
 * @param expiration how long is @a address valid
 * @param private_key signing key to use
 * @param result[out] where to write address record (allocated)
 * @param result_size[out] set to size of @a result
 */
void
GNUNET_HELLO_sign_address (const char *address,
			   struct GNUNET_TIME_Absolute expiration,
			   const struct GNUNET_CRYPTO_EddsaPrivateKey *private_key,
			   void **result,
			   size_t *result_size);


/**
 * Check signature and extract address record.
 *
 * @param raw raw signed address
 * @param raw_size size of @a raw
 * @param public_key public key to use for signature verification
 * @param expiration[out] how long is the address valid
 * @return NULL on error, otherwise the address
 */
char *
GNUNET_HELLO_extract_address (const void *raw,
			      size_t raw_size,
			      const struct GNUNET_CRYPTO_EddsaPublicKey *public_key,
			      struct GNUNET_TIME_Absolute *expiration);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_HELLO_LIB_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_hello_lib.h */

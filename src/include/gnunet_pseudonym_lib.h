/*
     This file is part of GNUnet.
     (C) 2001--2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_pseudonym_lib.h
 * @brief functions related to pseudonyms
 * @author Christian Grothoff
 */

#ifndef GNUNET_PSEUDONYM_LIB_H
#define GNUNET_PSEUDONYM_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_container_lib.h"


/**
 * Identifier for a GNUnet pseudonym (the public key).
 * Q-point, Q=dp.
 */
struct GNUNET_PseudonymIdentifier
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits),
   * given here in affine coordinates.
   */
  unsigned char q_x[256 / 8];

  /**
   * Q consists of an x- and a y-value, each mod p (256 bits),
   * given here in affine coordinates.
   */
  unsigned char q_y[256 / 8];

};


/**
 * Handle for a pseudonym (private key).
 */
struct GNUNET_PseudonymHandle;


/**
 * Signature made with a pseudonym (includes the full public key).
 * The ECDSA signature is a pair (r,s) with r = x1 mod n where
 * (x1,y1) = kG for "random" k and s = k^{-1}(z + rd) mod n,
 * where z is derived from the hash of the message that is being
 * signed.
 */
struct GNUNET_PseudonymSignature
{
  
  /**
   * Who created the signature? (public key of the signer), 'd' value in NIST P-256.
   */
  struct GNUNET_PseudonymIdentifier signer;

  /**
   * Binary ECDSA signature data, r-value.  Value is mod n, and n is 256 bits.
   */
  unsigned char sig_r[256 / 8];

  /**
   * Binary ECDSA signature data, s-value.  Value is mod n, and n is 256 bits.
   */
  unsigned char sig_s[256 / 8];
};


/**
 * Purpose for signature made with a pseudonym.
 */
struct GNUNET_PseudonymSignaturePurpose
{
  /**
   * How many bytes are being signed (including this header)?
   */
  uint32_t size;

  /**
   * What is the context/purpose of the signature?
   */
  uint32_t purpose;
};


/**
 * Create a pseudonym.
 *
 * @param filename name of the file to use for storage, NULL for in-memory only
 * @return handle to the private key of the pseudonym
 */
struct GNUNET_PseudonymHandle *
GNUNET_PSEUDONYM_create (const char *filename);


/**
 * Create a pseudonym, from a file that must already exist.
 *
 * @param filename name of the file to use for storage, NULL for in-memory only
 * @return handle to the private key of the pseudonym
 */
struct GNUNET_PseudonymHandle *
GNUNET_PSEUDONYM_create_from_existing_file (const char *filename);


/**
 * Get the handle for the 'anonymous' pseudonym shared by all users.
 * That pseudonym uses a fixed 'secret' for the private key; this
 * construction is useful to make anonymous and pseudonymous APIs
 * (and packets) indistinguishable on the network.  See #2564.
 *
 * @return handle to the (non-secret) private key of the 'anonymous' pseudonym
 */
struct GNUNET_PseudonymHandle *
GNUNET_PSEUDONYM_get_anonymous_pseudonym_handle (void);


/**
 * Destroy a pseudonym handle.  Does NOT remove the private key from
 * the disk.
 *
 * @param ph pseudonym handle to destroy
 */
void
GNUNET_PSEUDONYM_destroy (struct GNUNET_PseudonymHandle *ph);


/**
 * Cryptographically sign some data with the pseudonym.
 *
 * @param ph private key used for signing (corresponds to 'x' in #2564)
 * @param purpose data to sign
 * @param seed hash of the plaintext of the data that we are signing, 
 *             used for deterministic PRNG for anonymous signing;
 *             corresponds to 'k' in section 2.7 of #2564
 * @param signing_key modifier to apply to the private key for signing;
 *                    corresponds to 'h' in section 2.3 of #2564.
 * @param signature where to store the signature
 * @return GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_sign (struct GNUNET_PseudonymHandle *ph,
		       const struct GNUNET_PseudonymSignaturePurpose *purpose,
		       const struct GNUNET_HashCode *seed,
		       const struct GNUNET_HashCode *signing_key,
		       struct GNUNET_PseudonymSignature *signature);


/**
 * Given a pseudonym and a signing key, derive the corresponding public
 * key that would be used to verify the resulting signature.
 *
 * @param pseudonym the public key (g^x in DSA, dQ in ECDSA)
 * @param signing_key input to derive 'h' (see section 2.4 of #2564)
 * @param verification_key resulting public key to verify the signature
 *        created from the 'ph' of 'pseudonym' and the 'signing_key';
 *        the value stored here can then be given to GNUNET_PSEUDONYM_verify.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_PSEUDONYM_derive_verification_key (struct GNUNET_PseudonymIdentifier *pseudonym,
					  const struct GNUNET_HashCode *signing_key,
					  struct GNUNET_PseudonymIdentifier *verification_key);


/**
 * Verify a signature made with a pseudonym.
 *
 * @param purpose data that was signed
 * @param signature signature to verify
 * @param verification_key public key to use for checking the signature;
 *                    corresponds to 'g^(x+h)' in section 2.4 of #2564.
 * @return GNUNET_OK on success (signature valid, 'pseudonym' set),
 *         GNUNET_SYSERR if the signature is invalid
 */
int
GNUNET_PSEUDONYM_verify (const struct GNUNET_PseudonymSignaturePurpose *purpose,
			 const struct GNUNET_PseudonymSignature *signature,
			 const struct GNUNET_PseudonymIdentifier *verification_key);


/**
 * Get the identifier (public key) of a pseudonym.
 *
 * @param ph pseudonym handle with the private key
 * @param pseudonym pseudonym identifier (set based on 'ph')
 */
void
GNUNET_PSEUDONYM_get_identifier (struct GNUNET_PseudonymHandle *ph,
				 struct GNUNET_PseudonymIdentifier *pseudonym);



/**
 * Iterator over all known pseudonyms.
 *
 * @param cls closure
 * @param pseudonym hash code of public key of pseudonym
 * @param name name of the pseudonym (might be NULL)
 * @param unique_name unique name of the pseudonym (might be NULL)
 * @param md meta data known about the pseudonym
 * @param rating the local rating of the pseudonym
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_PSEUDONYM_Iterator) (void *cls,
                                          const struct GNUNET_PseudonymIdentifier *pseudonym,
                                          const char *name,
                                          const char *unique_name,
                                          const struct GNUNET_CONTAINER_MetaData *md, 
					  int32_t rating);


/**
 * Change the rank of a pseudonym.
 *
 * @param cfg overall configuration
 * @param pseudonym identity of the pseudonym
 * @param delta by how much should the rating be changed?
 * @return new rating of the pseudonym
 */
int
GNUNET_PSEUDONYM_rank (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const struct GNUNET_PseudonymIdentifier *pseudonym, 
		       int32_t delta);


/**
 * Add a pseudonym to the set of known pseudonyms.
 * For all pseudonym advertisements that we discover
 * FS should automatically call this function.
 *
 * @param cfg overall configuration
 * @param pseudonym the pseudonym identifier
 * @param meta metadata for the pseudonym
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_add (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      const struct GNUNET_PseudonymIdentifier *pseudonym,
                      const struct GNUNET_CONTAINER_MetaData *meta);


/**
 * List all known pseudonyms.
 *
 * @param cfg overall configuration
 * @param iterator function to call for each pseudonym
 * @param iterator_cls closure for iterator
 * @return number of pseudonyms found
 */
int
GNUNET_PSEUDONYM_list_all (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_PSEUDONYM_Iterator iterator, 
			   void *iterator_cls);


/**
 * Handle for a discovery callback registration.
 */
struct GNUNET_PSEUDONYM_DiscoveryHandle;


/**
 * Register callback to be invoked whenever we discover
 * a new pseudonym.
 *
 * @param cfg our configuration
 * @param iterator function to invoke on discovery
 * @param iterator_cls closure for iterator
 * @return registration handle
 */
struct GNUNET_PSEUDONYM_DiscoveryHandle *
GNUNET_PSEUDONYM_discovery_callback_register (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                              GNUNET_PSEUDONYM_Iterator iterator, 
					      void *iterator_cls);


/**
 * Unregister pseudonym discovery callback.
 *
 * @param dh registration to unregister
 */
void
GNUNET_PSEUDONYM_discovery_callback_unregister (struct GNUNET_PSEUDONYM_DiscoveryHandle *dh);


/**
 * Return unique variant of the pseudonym name.  Use after
 * GNUNET_PSEUDONYM_id_to_name() to make sure that name is unique.
 *
 * @param cfg configuration
 * @param pseudonym cryptographic ID of the pseudonym
 * @param name name to uniquify
 * @param suffix if not NULL, filled with the suffix value
 * @return NULL on failure (should never happen), name on success.
 *         Free the name with GNUNET_free().
 */
char *
GNUNET_PSEUDONYM_name_uniquify (const struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_PseudonymIdentifier *pseudonym, 
				const char *name, 
				unsigned int *suffix);


/**
 * Get pseudonym name, metadata and rank. This is a wrapper around
 * internal read_info() call, and ensures that returned data is not
 * invalid (not NULL).  Writing back information returned by this
 * function will give a name "no-name" to pseudonyms that have no
 * name. This side-effect is unavoidable, but hardly harmful.
 *
 * @param cfg configuration
 * @param pseudonym cryptographic ID of the pseudonym
 * @param ret_meta a location to store metadata pointer. NULL, if metadata
 *        is not needed. Destroy with GNUNET_CONTAINER_meta_data_destroy().
 * @param ret_rank a location to store rank. NULL, if rank not needed.
 * @param ret_name a location to store human-readable name. Name is not unique.
 *        NULL, if name is not needed. Free with GNUNET_free().
 * @param name_is_a_dup is set to GNUNET_YES, if ret_name was filled with
 *        a duplicate of a "no-name" placeholder
 * @return GNUNET_OK on success. GNUENT_SYSERR if the data was
 *         unobtainable (in that case ret_* are filled with placeholders - 
 *         empty metadata container, rank -1 and a "no-name" name).
 */
int
GNUNET_PSEUDONYM_get_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   const struct GNUNET_PseudonymIdentifier *pseudonym, 
			   struct GNUNET_CONTAINER_MetaData **ret_meta,
			   int32_t *ret_rank, 
			   char **ret_name, 
			   int *name_is_a_dup);


/**
 * Get the pseudonym ID belonging to the given pseudonym name.
 *
 * @param cfg configuration to use
 * @param ns_uname unique (!) human-readable name for the pseudonym
 * @param pseudonym set to pseudonym ID based on 'ns_uname'
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_name_to_id (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *ns_uname,
			     struct GNUNET_PseudonymIdentifier *pseudonym);


/**
 * Set the pseudonym metadata, rank and name.
 *
 * @param cfg overall configuration
 * @param pseudonym id of the pseudonym
 * @param name name to set. Must be the non-unique version of it.
 *        May be NULL, in which case it erases pseudonym's name!
 * @param md metadata to set
 *        May be NULL, in which case it erases pseudonym's metadata!
 * @param rank rank to assign
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_set_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   const struct GNUNET_PseudonymIdentifier *pseudonym, 
			   const char *name,
			   const struct GNUNET_CONTAINER_MetaData *md, 
			   int32_t rank);


/**
 * Remove pseudonym from the set of known pseudonyms.
 *
 * @param cfg overall configuration
 * @param id the pseudonym identifier
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_remove (const struct GNUNET_CONFIGURATION_Handle *cfg,
    const struct GNUNET_PseudonymIdentifier *id);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSEUDONYM_LIB_H */
#endif
/* end of gnunet_pseudonym_lib.h */

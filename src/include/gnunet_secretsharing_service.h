/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_secretsharing_service.h
 * @brief verifiable additive secret sharing and cooperative decryption
 * @author Florian Dold
 */

#ifndef GNUNET_SECRETSHARING_SERVICE_H
#define GNUNET_SECRETSHARING_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_configuration_lib.h"
#include <gcrypt.h>


/**
 * Number of bits for secretsharing keys.
 * Must be smaller than the Pallier key size used internally
 * by the secretsharing service.
 */
#define GNUNET_SECRETSHARING_KEY_BITS 1024


/**
 * Session that will eventually establish a shared secred between
 * the involved peers and allow encryption and cooperative decryption.
 */
struct GNUNET_SECRETSHARING_Session;

/**
 * Share of a secret shared with a group of peers.
 * Contains both the share and information about the peers that have
 * the other parts of the share.
 */
struct GNUNET_SECRETSHARING_Share;


/**
 * Handle to cancel a cooperative decryption operation.
 */
struct GNUNET_SECRETSHARING_DecryptionHandle;


/**
 * Public key of a group sharing a secret.
 */
struct GNUNET_SECRETSHARING_PublicKey
{
  uint32_t bits[GNUNET_SECRETSHARING_KEY_BITS / 8 / sizeof (uint32_t)];
};


/**
 * Encrypted field element.
 */
struct GNUNET_SECRETSHARING_Ciphertext
{
  uint32_t bits[2 * GNUNET_SECRETSHARING_KEY_BITS / 8 / sizeof (uint32_t)];
};


/**
 * Plain, unencrypted message that can be encrypted with
 * a group public key.
 */
struct GNUNET_SECRETSHARING_Message
{
  /**
   * Value of the message.
   */
  gcry_mpi_t value;
};


/**
 * Called once the secret has been established with all peers, or the deadline is due.
 *
 * Note that the number of peers can be smaller than 'k' (this threshold parameter), which
 * makes the threshold crypto system useless.  However, in this case one can still determine which peers
 * were able to participate in the secret sharing successfully.
 *
 * If the secret sharing failed, num_ready_peers is 0 and my_share and public_key is NULL.
 *
 * @param cls closure
 * @param my_share the share of this peer
 * @param public_key public key of the session
 * @param num_ready_peers number of peers in @a ready_peers
 * @param ready_peers peers that successfuly participated in establishing
 *                    the shared secret
 */
typedef void (*GNUNET_SECRETSHARING_SecretReadyCallback) (void *cls,
                                                          const struct GNUNET_SECRETSHARING_Share *my_share,
                                                          const struct GNUNET_SECRETSHARING_PublicKey *public_key,
                                                          unsigned int num_ready_peers,
                                                          const struct GNUNET_PeerIdentity *ready_peers);


/**
 * Called when a decryption has succeeded.
 *
 * @param cls closure
 * @param data decrypted value
 * @param data_size number of bytes in @a data
 */
typedef void (*GNUNET_SECRETSHARING_DecryptCallback) (void *cls,
                                                      const void *data,
                                                      size_t data_size);


/**
 * Create a session that will eventually establish a shared secret
 * with the other peers.
 *
 * @param cfg configuration to use
 * @param num_peers number of peers in 'peers'
 * @param peers array of peers that we will share secrets with, can optionally contain the local peer
 * @param session_id unique session id
 * @param deadline point in time where the session must be established; taken as hint
 *                 by underlying consensus sessions
 * @param threshold minimum number of peers that must cooperate to decrypt a value
 * @param cb called when the secret has been established
 * @param cls closure for cb
 */
struct GNUNET_SECRETSHARING_Session *
GNUNET_SECRETSHARING_create_session (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     unsigned int num_peers,
                                     const struct GNUNET_PeerIdentity *peers,
                                     const struct GNUNET_HashCode *session_id,
                                     struct GNUNET_TIME_Absolute deadline,
                                     unsigned int threshold,
                                     GNUNET_SECRETSHARING_SecretReadyCallback cb,
                                     void *cls);


/**
 * Destroy a secret share.
 *
 * @param share secret share to destroy
 */
void
GNUNET_SECRETSHARING_share_destroy (const struct GNUNET_SECRETSHARING_Share *share);


/**
 * Destroy a secret sharing session.
 *
 * @param session session to destroy
 */
void
GNUNET_SECRETSHARING_destroy_session (struct GNUNET_SECRETSHARING_Session *session);


/**
 * Encrypt a value.  This operation is executed locally, no communication is
 * necessary.
 *
 * This is a helper function, encryption can be done soley with a session's public key
 * and the crypto system parameters.
 *
 * @param public_key public key to use for decryption
 * @param message message to encrypt
 * @param message_size number of bytes in @a message
 * @param result_ciphertext pointer to store the resulting ciphertext
 * @return #GNUNET_YES on succes, #GNUNET_SYSERR if the message is invalid (invalid range)
 */
int
GNUNET_SECRETSHARING_encrypt (struct GNUNET_SECRETSHARING_PublicKey *public_key,
                              const void *message,
                              size_t message_size,
                              struct GNUNET_SECRETSHARING_Ciphertext *result_ciphertext);


/**
 * Publish the given ciphertext for decryption.  Once a sufficient (>=k) number of peers has
 * published the same value, it will be decrypted.
 *
 * When the operation is canceled, the decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param share our secret share to use for decryption
 * @param ciphertext ciphertext to publish in order to decrypt it (if enough peers agree)
 * @param decrypt_cb callback called once the decryption succeeded
 * @param decrypt_cb_cls closure for @a decrypt_cb
 * @return handle to cancel the operation
 */
struct GNUNET_SECRETSHARING_DecryptionHandle *
GNUNET_SECRETSHARING_decrypt (struct GNUNET_SECRETSHARING_Share *share,
                              struct GNUNET_SECRETSHARING_Ciphertext *ciphertext,
                              GNUNET_SECRETSHARING_DecryptCallback decrypt_cb,
                              void *decrypt_cb_cls);


/**
 * Cancel a decryption.
 *
 * The decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param decryption_handle decryption to cancel
 */
void
GNUNET_SECRETSHARING_decrypt_cancel (struct GNUNET_SECRETSHARING_DecryptionHandle *decryption_handle);


/**
 * Read a share from its binary representation.
 *
 * @param data binary representation of the share
 * @param len length of @a data
 * @return the share, or NULL on error
 */
struct GNUNET_SECRETSHARING_Share *
GNUNET_SECRETSHARING_share_read (void *data, size_t len);


/**
 * Convert a share to its binary representation.  Use
 * #GNUNET_SECRETSHARING_share_size to get the necessary size for the binary
 * representation.
 *
 * @param share share to write
 * @param buf buffer to write to
 * @param buflen number of writable bytes in @a buffer
 * @param[out] writelen pointer to store number of bytes written,
 *             ignored if NULL
 * @return GNUNET_YES on success, GNUNET_NO on failure
 */
int
GNUNET_SECRETSHARING_share_write (struct GNUNET_SECRETSHARING_Share *share,
                                  void *buf, size_t buflen, size_t *writelen);


/**
 * Get the number of bytes necessary to represent the given share.
 *
 * @param share share
 * @return number of bytes necessary to represent @a share
 */
size_t
GNUNET_SECRETSHARING_share_size (struct GNUNET_SECRETSHARING_Share *share);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

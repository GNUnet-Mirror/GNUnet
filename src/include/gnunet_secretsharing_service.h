/*
      This file is part of GNUnet
      Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * Number of bits for secretsharing elements.
 * Must be smaller than the Pallier key size used internally
 * by the secretsharing service.
 * When changing this value, other internal parameters must also
 * be adjusted.
 */
#define GNUNET_SECRETSHARING_ELGAMAL_BITS 1024


/**
 * The q-parameter for ElGamal encryption, a 1024-bit safe prime.
 */
#define GNUNET_SECRETSHARING_ELGAMAL_P_HEX  \
      "0x08a347d3d69e8b2dd7d1b12a08dfbccbebf4ca" \
      "6f4269a0814e158a34312964d946b3ef22882317" \
      "2bcf30fc08f772774cb404f9bc002a6f66b09a79" \
      "d810d67c4f8cb3bedc6060e3c8ef874b1b64df71" \
      "6c7d2b002da880e269438d5a776e6b5f253c8df5" \
      "6a16b1c7ce58def07c03db48238aadfc52a354a2" \
      "7ed285b0c1675cad3f3"

/**
 * The q-parameter for ElGamal encryption,
 * a 1023-bit Sophie Germain prime, q = (p-1)/2
 */
#define GNUNET_SECRETSHARING_ELGAMAL_Q_HEX  \
      "0x0451a3e9eb4f4596ebe8d895046fde65f5fa65" \
      "37a134d040a70ac51a1894b26ca359f79144118b" \
      "95e7987e047bb93ba65a027cde001537b3584d3c" \
      "ec086b3e27c659df6e303071e477c3a58db26fb8" \
      "b63e958016d4407134a1c6ad3bb735af929e46fa" \
      "b50b58e3e72c6f783e01eda411c556fe2951aa51" \
      "3f6942d860b3ae569f9"

/**
 * The g-parameter for ElGamal encryption,
 * a generator of the unique size q subgroup of Z_p^*
 */
#define GNUNET_SECRETSHARING_ELGAMAL_G_HEX  \
      "0x05c00c36d2e822950087ef09d8252994adc4e4" \
      "8fe3ec70269f035b46063aff0c99b633fd64df43" \
      "02442e1914c829a41505a275438871f365e91c12" \
      "3d5303ef9e90f4b8cb89bf86cc9b513e74a72634" \
      "9cfd9f953674fab5d511e1c078fc72d72b34086f" \
      "c82b4b951989eb85325cb203ff98df76bc366bba" \
      "1d7024c3650f60d0da"



/**
 * Session that will eventually establish a shared secred between
 * the involved peers and allow encryption and cooperative decryption.
 */
struct GNUNET_SECRETSHARING_Session;

/**
 * Share of a secret shared with a group of peers.
 * Contains the secret share itself, the public key, the list of peers, and the
 * exponential commitments to the secret shares of the other peers.
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
  uint32_t bits[GNUNET_SECRETSHARING_ELGAMAL_BITS / 8 / sizeof (uint32_t)];
};


/**
 * Encrypted field element.
 */
struct GNUNET_SECRETSHARING_Ciphertext
{
  uint32_t c1_bits[GNUNET_SECRETSHARING_ELGAMAL_BITS / 8 / sizeof (uint32_t)];
  uint32_t c2_bits[GNUNET_SECRETSHARING_ELGAMAL_BITS / 8 / sizeof (uint32_t)];
};


/**
 * Plain, unencrypted message that can be encrypted with
 * a group public key.
 * Note that we are not operating in GF(2^n), thus not every
 * bit pattern is a valid plain text.
 */
struct GNUNET_SECRETSHARING_Plaintext
{
  /**
   * Value of the message.
   */
  uint32_t bits[GNUNET_SECRETSHARING_ELGAMAL_BITS / 8 / sizeof (uint32_t)];
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
 * After this callback has been called, the secretsharing session will be invalid.
 *
 * @param cls closure
 * @param my_share the share of this peer
 * @param public_key public key of the session
 * @param num_ready_peers number of peers in @a ready_peers
 * @param ready_peers peers that successfuly participated in establishing
 *                    the shared secret
 */
typedef void (*GNUNET_SECRETSHARING_SecretReadyCallback) (void *cls,
                                                          struct GNUNET_SECRETSHARING_Share *my_share,
                                                          struct GNUNET_SECRETSHARING_PublicKey *public_key,
                                                          unsigned int num_ready_peers,
                                                          struct GNUNET_PeerIdentity *ready_peers);


/**
 * Called when a decryption has succeeded.
 *
 * @param cls closure
 * @param data decrypted value
 * @param data_size number of bytes in @a data
 */
typedef void (*GNUNET_SECRETSHARING_DecryptCallback) (void *cls,
                                                      const struct GNUNET_SECRETSHARING_Plaintext *plaintext);


/**
 * Create a session that will eventually establish a shared secret
 * with the other peers.
 *
 * @param cfg configuration to use
 * @param num_peers number of peers in @a peers
 * @param peers array of peers that we will share secrets with, can optionally contain the local peer
 * @param session_id unique session id
 * @param start When should all peers be available for sharing the secret?
 *              Random number generation can take place before the start time.
 * @param deadline point in time where the session must be established; taken as hint
 *                 by underlying consensus sessions
 * @param threshold minimum number of peers that must cooperate to decrypt a value
 * @param cb called when the secret has been established
 * @param cls closure for @a cb
 */
struct GNUNET_SECRETSHARING_Session *
GNUNET_SECRETSHARING_create_session (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     unsigned int num_peers,
                                     const struct GNUNET_PeerIdentity *peers,
                                     const struct GNUNET_HashCode *session_id,
                                     struct GNUNET_TIME_Absolute start,
                                     struct GNUNET_TIME_Absolute deadline,
                                     unsigned int threshold,
                                     GNUNET_SECRETSHARING_SecretReadyCallback cb,
                                     void *cls);


/**
 * Destroy a secret sharing session.
 * The secret ready callback will not be called.
 *
 * @param s session to destroy
 */
void
GNUNET_SECRETSHARING_session_destroy (struct GNUNET_SECRETSHARING_Session *s);


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
GNUNET_SECRETSHARING_encrypt (const struct GNUNET_SECRETSHARING_PublicKey *public_key,
                              const struct GNUNET_SECRETSHARING_Plaintext *plaintext,
                              struct GNUNET_SECRETSHARING_Ciphertext *result_ciphertext);


/**
 * Publish the given ciphertext for decryption.  Once a sufficient (>=k) number of peers has
 * published the same value, it will be decrypted.
 *
 * When the operation is canceled, the decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param cfg configuration to use
 * @param share our secret share to use for decryption
 * @param ciphertext ciphertext to publish in order to decrypt it (if enough peers agree)
 * @param decrypt_cb callback called once the decryption succeeded
 * @param start By when should the cooperation for decryption start?
 * @param deadline By when should the decryption be finished?
 * @param decrypt_cb_cls closure for @a decrypt_cb
 * @return handle to cancel the operation
 */
struct GNUNET_SECRETSHARING_DecryptionHandle *
GNUNET_SECRETSHARING_decrypt (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              struct GNUNET_SECRETSHARING_Share *share,
                              const struct GNUNET_SECRETSHARING_Ciphertext *ciphertext,
                              struct GNUNET_TIME_Absolute start,
                              struct GNUNET_TIME_Absolute deadline,
                              GNUNET_SECRETSHARING_DecryptCallback decrypt_cb,
                              void *decrypt_cb_cls);


/**
 * Cancel a decryption.
 *
 * The decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param dh to cancel
 */
void
GNUNET_SECRETSHARING_decrypt_cancel (struct GNUNET_SECRETSHARING_DecryptionHandle *dh);


/**
 * Read a share from its binary representation.
 *
 * @param data Binary representation of the share.
 * @param len Length of @a data.
 * @param[out] readlen Number of bytes read,
 *             ignored if NULL.
 * @return The share, or NULL on error.
 */
struct GNUNET_SECRETSHARING_Share *
GNUNET_SECRETSHARING_share_read (const void *data, size_t len, size_t *readlen);


/**
 * Convert a share to its binary representation.
 * Can be called with a NULL @a buf to get the size of the share.
 *
 * @param share Share to write.
 * @param buf Buffer to write to.
 * @param buflen Number of writable bytes in @a buf.
 * @param[out] writelen Pointer to store number of bytes written,
 *             ignored if NULL.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure.
 */
int
GNUNET_SECRETSHARING_share_write (const struct GNUNET_SECRETSHARING_Share *share,
                                  void *buf, size_t buflen, size_t *writelen);


void
GNUNET_SECRETSHARING_share_destroy (struct GNUNET_SECRETSHARING_Share *share);


int
GNUNET_SECRETSHARING_plaintext_generate (struct GNUNET_SECRETSHARING_Plaintext *plaintext,
                                         gcry_mpi_t exponent);

int
GNUNET_SECRETSHARING_plaintext_generate_i (struct GNUNET_SECRETSHARING_Plaintext *plaintext,
                                           int64_t exponent);




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

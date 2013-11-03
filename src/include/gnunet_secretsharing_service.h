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
 * @brief verified additive secret sharing and cooperative decryption
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
 * Session that will eventually establish a shared secred between
 * the involved peers and allow encryption and cooperative decryption.
 */
struct GNUNET_SECRETSHARING_Session;


/**
 * Handle to cancel a cooperative decryption operation.
 */
struct GNUNET_SECRETSHARING_DecryptionHandle;


/**
 * Parameters of the crypto system.
 */
struct GNUNET_SECRETSHARING_Parameters
{
  /**
   * Threshold, that is, minimum number of peers that
   * must cooperate to decrypt a value.
   */
  unsigned int k;
  /**
   * Prime with p = 2q+1.
   */
  gcry_mpi_t p;
  /**
   * Prime.
   */
  gcry_mpi_t q;
  /**
   * Generator of G_q.
   */
  gcry_mpi_t g;
};


/**
 * Encrypted field element.
 */
struct GNUNET_SECRETSHARING_Ciphertext 
{
  /**
   * First component.
   */
  gcry_mpi_t c1;
  /**
   * Second component.
   */
  gcry_mpi_t c2;
};


/**
 * Called once the secret has been established with all peers, or the deadline is due.
 *
 * Note that the number of peers can be smaller that 'k' (this threshold parameter), which
 * makes the threshold crypto system useledd.  However, in this case one can still determine which peers
 * were able to participate in the secret sharing successfully.
 *
 * @param cls closure
 * @param public_key public key of the session
 * @param num_ready_peers number of peers in @ready_peers
 * @parem ready_peers peers that successfuly participated in establishing
 *                    the shared secret
 */
typedef void (*GNUNET_SECRETSHARING_SecretReadyCallback) (void *cls,
                                                          gcry_mpi_t public_key,
                                                          unsigned int num_ready_peers,
                                                          const struct GNUNET_PeerIdentity *ready_peers);


/**
 * Called when a decryption has succeeded.
 *
 * @param cls closure
 * @param result decrypted value
 */
typedef void (*GNUNET_SECRETSHARING_DecryptCallback) (void *cls,
                                                      gcry_mpi_t result);


/**
 * Create a session that will eventually establish a shared secret
 * with the other peers.
 *
 * @param cfg configuration to use
 * @param num_peers number of peers in @peers
 * @param session_id unique session id
 * @param deadline point in time where the session must be established; taken as hint
 *                 by underlying consensus sessions
 * @param cb called when the secret has been established
 * @param cls closure for cb
 */
struct GNUNET_SECRETSHARING_Session *
GNUNET_SECRETSHARING_create_session (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     unsigned int num_peers,
                                     const struct GNUNET_PeerIdentity *peers,
                                     const struct GNUNET_HashCode *session_id,
                                     struct GNUNET_TIME_Absolute deadline,
                                     struct GNUNET_SECRETSHARING_Parameters *parameters,
                                     GNUNET_SECRETSHARING_SecretReadyCallback *cb,
                                     void *cls);


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
 * @param session session to take the key for encryption from,
 *                the session's ready callback must have been already called
 * @param message message to encrypt
 * @param result_cyphertext pointer to store the resulting ciphertext
 * @return GNUNET_YES on succes, GNUNET_SYSERR if the message is invalid (invalid range)
 */
int 
GNUNET_SECRETSHARING_encrypt (const struct GNUNET_SECRETSHARING_Session *session,
                              gcry_mpi_t message,
                              struct GNUNET_SECRETSHARING_Ciphertext *result_ciphertext);


/**
 * Publish the given ciphertext for decryption.  Once a sufficient (>=k) number of peers has
 * published the same value, it will be decrypted.
 *
 * When the operation is canceled, the decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param session session to use for the decryption
 * @param ciphertext ciphertext to publish in order to decrypt it (if enough peers agree)
 * @param decrypt_cb callback called once the decryption succeeded
 * @param cls closure for decrypt_cb
 * @return handle to cancel the operation
 */
struct GNUNET_SECRETSHARING_DecryptionHandle *
GNUNET_SECRETSHARING_publish_decrypt (struct GNUNET_SECRETSHARING_Session *session,
                                      struct GNUNET_SECRETSHARING_Ciphertext *ciphertext,
                                      GNUNET_SECRETSHARING_DecryptCallback decrypt_cb,
                                      void *cls);


/**
 * Cancel a decryption.
 *
 * The decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param decryption_handle decryption to cancel
 */
void
GNUNET_SECRETSHARING_cancel_decrypt (struct GNUNET_SECRETSHARING_DecryptionHandle *decryption_handle);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

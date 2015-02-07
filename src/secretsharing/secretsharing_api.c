/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/secretsharing_api.c
 * @brief
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_secretsharing_service.h"
#include "secretsharing.h"
#include <gcrypt.h>


#define LOG(kind,...) GNUNET_log_from (kind, "secretsharing-api",__VA_ARGS__)

/**
 * Session that will eventually establish a shared secred between
 * the involved peers and allow encryption and cooperative decryption.
 */
struct GNUNET_SECRETSHARING_Session
{
  /**
   * Client connected to the secretsharing service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue for @e client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Called when the secret sharing is done.
   */
  GNUNET_SECRETSHARING_SecretReadyCallback secret_ready_cb;

  /**
   * Closure for @e secret_ready_cb.
   */
  void *secret_ready_cls;
};


/**
 * Handle to cancel a cooperative decryption operation.
 */
struct GNUNET_SECRETSHARING_DecryptionHandle
{
  /**
   * Client connected to the secretsharing service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue for @e client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Called when the secret sharing is done.
   */
  GNUNET_SECRETSHARING_DecryptCallback decrypt_cb;

  /**
   * Closure for @e decrypt_cb.
   */
  void *decrypt_cls;
};


/**
 * The ElGamal prime field order as libgcrypt mpi.
 * Initialized in #init_crypto_constants.
 */
static gcry_mpi_t elgamal_q;

/**
 * Modulus of the prime field used for ElGamal.
 * Initialized in #init_crypto_constants.
 */
static gcry_mpi_t elgamal_p;

/**
 * Generator for prime field of order 'elgamal_q'.
 * Initialized in #init_crypto_constants.
 */
static gcry_mpi_t elgamal_g;


/**
 * Function to initialize #elgamal_q, #elgamal_p and #elgamal_g.
 */
static void
ensure_elgamal_initialized (void)
{
  if (NULL != elgamal_q)
    return; /* looks like crypto is already initialized */

  GNUNET_assert (0 == gcry_mpi_scan (&elgamal_q, GCRYMPI_FMT_HEX,
                                     GNUNET_SECRETSHARING_ELGAMAL_Q_HEX, 0, NULL));
  GNUNET_assert (0 == gcry_mpi_scan (&elgamal_p, GCRYMPI_FMT_HEX,
                                     GNUNET_SECRETSHARING_ELGAMAL_P_HEX, 0, NULL));
  GNUNET_assert (0 == gcry_mpi_scan (&elgamal_g, GCRYMPI_FMT_HEX,
                                     GNUNET_SECRETSHARING_ELGAMAL_G_HEX, 0, NULL));
}


/**
 * Callback invoked when there is an error communicating with
 * the service.  Notifies the application about the error.
 *
 * @param cls the `struct GNUNET_SECRETSHARING_Session`
 * @param error error code
 */
static void
handle_session_client_error (void *cls,
                             enum GNUNET_MQ_Error error)
{
  struct GNUNET_SECRETSHARING_Session *s = cls;

  s->secret_ready_cb (s->secret_ready_cls, NULL, NULL, 0, NULL);
  GNUNET_SECRETSHARING_session_destroy (s);
}


/**
 * Callback invoked when there is an error communicating with
 * the service.  Notifies the application about the error.
 *
 * @param cls the `struct GNUNET_SECRETSHARING_DecryptionHandle`
 * @param error error code
 */
static void
handle_decrypt_client_error (void *cls,
                             enum GNUNET_MQ_Error error)
{
  struct GNUNET_SECRETSHARING_DecryptionHandle *dh = cls;

  dh->decrypt_cb (dh->decrypt_cls, NULL);
  GNUNET_SECRETSHARING_decrypt_cancel (dh);
}


/**
 * Handler invoked with the final result message from
 * secret sharing.  Decodes the message and passes the
 * result to the application.
 *
 * @param cls the `struct GNUNET_SECRETSHARING_Session`
 * @param msg message with the result
 */
static void
handle_secret_ready (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SECRETSHARING_Session *s = cls;
  const struct GNUNET_SECRETSHARING_SecretReadyMessage *m;
  struct GNUNET_SECRETSHARING_Share *share;
  size_t share_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got secret ready message of size %u\n",
       ntohs (msg->size));
  if (ntohs (msg->size) < sizeof (struct GNUNET_SECRETSHARING_SecretReadyMessage))
  {
    GNUNET_break (0);
    s->secret_ready_cb (s->secret_ready_cls, NULL, NULL, 0, NULL);
    GNUNET_SECRETSHARING_session_destroy (s);
    return;
  }
  m = (const struct GNUNET_SECRETSHARING_SecretReadyMessage *) msg;
  share_size = ntohs (m->header.size) - sizeof (struct GNUNET_SECRETSHARING_SecretReadyMessage);

  share = GNUNET_SECRETSHARING_share_read (&m[1],
                                           share_size,
                                           NULL);
  s->secret_ready_cb (s->secret_ready_cls,
                      share, /* FIXME */
                      &share->public_key,
                      share->num_peers,
                      (struct GNUNET_PeerIdentity *) &m[1]);
  GNUNET_SECRETSHARING_session_destroy (s);
}


/**
 * Destroy a secret sharing session.
 * The secret ready callback will not be called.
 *
 * @param s session to destroy
 */
void
GNUNET_SECRETSHARING_session_destroy (struct GNUNET_SECRETSHARING_Session *s)
{
  GNUNET_MQ_destroy (s->mq);
  s->mq = NULL;
  GNUNET_CLIENT_disconnect (s->client);
  s->client = NULL;
  GNUNET_free (s);
}


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
                                     void *cls)
{
  struct GNUNET_SECRETSHARING_Session *s;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SECRETSHARING_CreateMessage *msg;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    { &handle_secret_ready,
      GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY, 0},
    GNUNET_MQ_HANDLERS_END
  };

  s = GNUNET_new (struct GNUNET_SECRETSHARING_Session);
  s->client = GNUNET_CLIENT_connect ("secretsharing", cfg);
  if (NULL == s->client)
  {
    /* secretsharing not configured correctly */
    GNUNET_break (0);
    GNUNET_free (s);
    return NULL;
  }
  s->secret_ready_cb = cb;
  s->secret_ready_cls = cls;
  s->mq = GNUNET_MQ_queue_for_connection_client (s->client, mq_handlers,
                                                 &handle_session_client_error,
                                                 s);
  GNUNET_assert (NULL != s->mq);

  ev = GNUNET_MQ_msg_extra (msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_GENERATE);

  msg->threshold = htons (threshold);
  msg->num_peers = htons (num_peers);
  msg->session_id = *session_id;
  msg->start = GNUNET_TIME_absolute_hton (start);
  msg->deadline = GNUNET_TIME_absolute_hton (deadline);
  memcpy (&msg[1], peers, num_peers * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (s->mq, ev);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Secretsharing session created with %u peers\n",
       num_peers);
  return s;
}


static void
handle_decrypt_done (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SECRETSHARING_DecryptionHandle *dh = cls;
  const struct GNUNET_SECRETSHARING_DecryptResponseMessage *m =
    (const void *) msg; // FIXME: size check!?
  const struct GNUNET_SECRETSHARING_Plaintext *plaintext;

  if (m->success == 0)
    plaintext = NULL;
  else
    plaintext = (void *) &m->plaintext;

  dh->decrypt_cb (dh->decrypt_cls, plaintext);

  GNUNET_SECRETSHARING_decrypt_cancel (dh);
}


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
GNUNET_SECRETSHARING_decrypt (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              struct GNUNET_SECRETSHARING_Share *share,
                              const struct GNUNET_SECRETSHARING_Ciphertext *ciphertext,
                              struct GNUNET_TIME_Absolute start,
                              struct GNUNET_TIME_Absolute deadline,
                              GNUNET_SECRETSHARING_DecryptCallback decrypt_cb,
                              void *decrypt_cb_cls)
{
  struct GNUNET_SECRETSHARING_DecryptionHandle *s;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SECRETSHARING_DecryptRequestMessage *msg;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {handle_decrypt_done, GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_DONE, 0},
    GNUNET_MQ_HANDLERS_END
  };
  size_t share_size;


  s = GNUNET_new (struct GNUNET_SECRETSHARING_DecryptionHandle);
  s->client = GNUNET_CLIENT_connect ("secretsharing", cfg);
  s->decrypt_cb = decrypt_cb;
  s->decrypt_cls = decrypt_cb_cls;
  GNUNET_assert (NULL != s->client);

  s->mq = GNUNET_MQ_queue_for_connection_client (s->client, mq_handlers,
                                                 &handle_decrypt_client_error,
                                                 s);
  GNUNET_assert (NULL != s->mq);

  GNUNET_assert (GNUNET_OK == GNUNET_SECRETSHARING_share_write (share, NULL, 0, &share_size));

  ev = GNUNET_MQ_msg_extra (msg,
                            share_size,
                            GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT);

  GNUNET_assert (GNUNET_OK == GNUNET_SECRETSHARING_share_write (share, &msg[1], share_size, NULL));

  msg->start = GNUNET_TIME_absolute_hton (start);
  msg->deadline = GNUNET_TIME_absolute_hton (deadline);
  msg->ciphertext = *ciphertext;

  GNUNET_MQ_send (s->mq, ev);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "decrypt session created\n");
  return s;
}


int
GNUNET_SECRETSHARING_plaintext_generate_i (struct GNUNET_SECRETSHARING_Plaintext *plaintext,
                                           int64_t exponent)
{
  int negative;
  gcry_mpi_t x;

  ensure_elgamal_initialized ();

  GNUNET_assert (NULL != (x = gcry_mpi_new (0)));

  negative = GNUNET_NO;
  if (exponent < 0)
  {
    negative = GNUNET_YES;
    exponent = -exponent;
  }

  gcry_mpi_set_ui (x, exponent);

  gcry_mpi_powm (x, elgamal_g, x, elgamal_p);

  if (GNUNET_YES == negative)
  {
    int res;
    res = gcry_mpi_invm (x, x, elgamal_p);
    if (0 == res)
      return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_mpi_print_unsigned (plaintext, sizeof (struct GNUNET_SECRETSHARING_Plaintext), x);

  return GNUNET_OK;
}


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
                              struct GNUNET_SECRETSHARING_Ciphertext *result_ciphertext)
{
  /* pubkey */
  gcry_mpi_t h;
  /* nonce */
  gcry_mpi_t y;
  /* plaintext message */
  gcry_mpi_t m;
  /* temp value */
  gcry_mpi_t tmp;

  ensure_elgamal_initialized ();

  GNUNET_assert (NULL != (h = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (y = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (tmp = gcry_mpi_new (0)));

  GNUNET_CRYPTO_mpi_scan_unsigned (&h, public_key, sizeof *public_key);
  GNUNET_CRYPTO_mpi_scan_unsigned (&m, plaintext, sizeof *plaintext);

  // Randomize y such that 0 < y < elgamal_q.
  // The '- 1' is necessary as bitlength(q) = bitlength(p) - 1.
  do
  {
    gcry_mpi_randomize (y, GNUNET_SECRETSHARING_ELGAMAL_BITS - 1, GCRY_WEAK_RANDOM);
  } while ((gcry_mpi_cmp_ui (y, 0) == 0) || (gcry_mpi_cmp (y, elgamal_q) >= 0));

  // tmp <- g^y
  gcry_mpi_powm (tmp, elgamal_g, y, elgamal_p);
  // write tmp to c1
  GNUNET_CRYPTO_mpi_print_unsigned (&result_ciphertext->c1_bits,
                                    GNUNET_SECRETSHARING_ELGAMAL_BITS / 8, tmp);

  // tmp <- h^y
  gcry_mpi_powm (tmp, h, y, elgamal_p);
  // tmp <- tmp * m
  gcry_mpi_mulm (tmp, tmp, m, elgamal_p);
  // write tmp to c2
  GNUNET_CRYPTO_mpi_print_unsigned (&result_ciphertext->c2_bits,
                                    GNUNET_SECRETSHARING_ELGAMAL_BITS / 8, tmp);

  return GNUNET_OK;
}


/**
 * Cancel a decryption.
 *
 * The decrypt_cb is not called anymore, but the calling
 * peer may already have irrevocably contributed his share for the decryption of the value.
 *
 * @param dh to cancel
 */
void
GNUNET_SECRETSHARING_decrypt_cancel (struct GNUNET_SECRETSHARING_DecryptionHandle *dh)
{
  GNUNET_MQ_destroy (dh->mq);
  dh->mq = NULL;
  GNUNET_CLIENT_disconnect (dh->client);
  dh->client = NULL;
  GNUNET_free (dh);
}

/* end of secretsharing_api.c */

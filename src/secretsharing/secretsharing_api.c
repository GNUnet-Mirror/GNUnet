/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
   * Message queue for 'client'.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Called when the secret sharing is done.
   */
  GNUNET_SECRETSHARING_SecretReadyCallback secret_ready_cb;

  /**
   * Closure for 'secret_ready_cb'.
   */
  void *secret_ready_cls;
};


struct GNUNET_SECRETSHARING_DecryptionHandle
{
  /**
   * Client connected to the secretsharing service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue for 'client'.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Called when the secret sharing is done.
   */
  GNUNET_SECRETSHARING_DecryptCallback decrypt_cb;

  /**
   * Closure for 'decrypt_cb'.
   */
  void *decrypt_cls;
};


static void
handle_session_client_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_SECRETSHARING_Session *s = cls;

  s->secret_ready_cb (s->secret_ready_cls, NULL, NULL, 0, NULL);
}


static void
handle_decrypt_client_error (void *cls, enum GNUNET_MQ_Error error)
{
  GNUNET_assert (0);
}

static void
handle_secret_ready (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SECRETSHARING_Session *session = cls;
  struct GNUNET_SECRETSHARING_Share *share;
  const struct GNUNET_SECRETSHARING_SecretReadyMessage *m = (const void *) msg;
  size_t share_size;

  share_size = ntohs (m->header.size) - sizeof *m;

  share = GNUNET_SECRETSHARING_share_read (&m[1], share_size, NULL);

  session->secret_ready_cb (session->secret_ready_cls,
                      share, /* FIXME */
                      &share->public_key,
                      share->num_peers,
                      (struct GNUNET_PeerIdentity *) &m[1]);

}


struct GNUNET_SECRETSHARING_Session *
GNUNET_SECRETSHARING_create_session (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     unsigned int num_peers,
                                     const struct GNUNET_PeerIdentity *peers,
                                     const struct GNUNET_HashCode *session_id,
                                     struct GNUNET_TIME_Absolute deadline,
                                     unsigned int threshold,
                                     GNUNET_SECRETSHARING_SecretReadyCallback cb,
                                     void *cls)
{
  struct GNUNET_SECRETSHARING_Session *s;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SECRETSHARING_CreateMessage *msg;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {handle_secret_ready, GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY, 0},
    GNUNET_MQ_HANDLERS_END
  };


  s = GNUNET_new (struct GNUNET_SECRETSHARING_Session);
  s->client = GNUNET_CLIENT_connect ("secretsharing", cfg);
  s->secret_ready_cb = cb;
  s->secret_ready_cls = cls;
  GNUNET_assert (NULL != s->client);

  s->mq = GNUNET_MQ_queue_for_connection_client (s->client, mq_handlers,
                                                   handle_session_client_error, s);
  GNUNET_assert (NULL != s->mq);

  ev = GNUNET_MQ_msg_extra (msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_GENERATE);

  msg->threshold = htons (threshold);
  msg->num_peers = htons (num_peers);
  msg->session_id = *session_id;
  msg->deadline = GNUNET_TIME_absolute_hton (deadline);
  memcpy (&msg[1], peers, num_peers * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (s->mq, ev);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "secretsharing session created with %u peers\n",
       num_peers);
  return s;
}


static void
handle_decrypt_done (void *cls, const struct GNUNET_MessageHeader *msg)
{
  GNUNET_assert (0);
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
GNUNET_SECRETSHARING_decrypt (struct GNUNET_CONFIGURATION_Handle *cfg,
                              struct GNUNET_SECRETSHARING_Share *share,
                              struct GNUNET_SECRETSHARING_Ciphertext *ciphertext,
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
                                                 handle_decrypt_client_error, s);
  GNUNET_assert (NULL != s->mq);

  GNUNET_assert (GNUNET_OK == GNUNET_SECRETSHARING_share_write (share, NULL, 0, &share_size));

  ev = GNUNET_MQ_msg_extra (msg,
                            share_size,
                            GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT);

  GNUNET_assert (GNUNET_OK == GNUNET_SECRETSHARING_share_write (share, &msg[1], share_size, NULL));

  msg->deadline = GNUNET_TIME_absolute_hton (deadline);

  GNUNET_MQ_send (s->mq, ev);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "decrypt session created\n");
  return s;
}



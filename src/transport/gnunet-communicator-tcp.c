/*
     This file is part of GNUnet
     Copyright (C) 2010-2014, 2018, 2019 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file transport/gnunet-communicator-tcp.c
 * @brief Transport plugin using TCP.
 * @author Christian Grothoff
 *
 * TODO:
 * - support DNS names in BINDTO option (#5528)
 * - support NAT connection reversal method (#5529)
 * - support other TCP-specific NAT traversal methods (#5531)
 * - add replay protection support to the protocol by
 *   adding a nonce in the KX and requiring (!) a
 *   nounce ACK to be send within the first X bytes of
 *   data (#5530)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_nt_lib.h"
#include "gnunet_nat_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_communication_service.h"

/**
 * How long do we believe our addresses to remain up (before
 * the other peer should revalidate).
 */
#define ADDRESS_VALIDITY_PERIOD \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * How many messages do we keep at most in the queue to the
 * transport service before we start to drop (default,
 * can be changed via the configuration file).
 * Should be _below_ the level of the communicator API, as
 * otherwise we may read messages just to have them dropped
 * by the communicator API.
 */
#define DEFAULT_MAX_QUEUE_LENGTH 8

/**
 * Size of our IO buffers for ciphertext data. Must be at
 * least UINT_MAX + sizeof (struct TCPBox).
 */
#define BUF_SIZE (2 * 64 * 1024 + sizeof (struct TCPBox))

/**
 * How often do we rekey based on time (at least)
 */
#define REKEY_TIME_INTERVAL GNUNET_TIME_UNIT_DAYS

/**
 * How long do we wait until we must have received the initial KX?
 */
#define PROTO_QUEUE_TIMEOUT GNUNET_TIME_UNIT_MINUTES

/**
 * How often do we rekey based on number of bytes transmitted?
 * (additionally randomized).
 */
#define REKEY_MAX_BYTES (1024LLU * 1024 * 1024 * 4LLU)

/**
 * Size of the initial key exchange message sent first in both
 * directions.
 */
#define INITIAL_KX_SIZE                           \
  (sizeof (struct GNUNET_CRYPTO_EcdhePublicKey) + \
   sizeof (struct TCPConfirmation))


/**
 * Address prefix used by the communicator.
 */
#define COMMUNICATOR_ADDRESS_PREFIX "tcp"

/**
 * Configuration section used by the communicator.
 */
#define COMMUNICATOR_CONFIG_SECTION "communicator-tcp"

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Signature we use to verify that the ephemeral key was really chosen by
 * the specified sender.
 */
struct TcpHandshakeSignature
{
  /**
   * Purpose must be #GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Identity of the inititor of the TCP connection (TCP client).
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Presumed identity of the target of the TCP connection (TCP server)
   */
  struct GNUNET_PeerIdentity receiver;

  /**
   * Ephemeral key used by the @e sender.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;
};


/**
 * Encrypted continuation of TCP initial handshake.
 */
struct TCPConfirmation
{
  /**
   * Sender's identity
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Sender's signature of type #GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;
};


/**
 * TCP message box.  Always sent encrypted!
 */
struct TCPBox
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX.  Warning: the
   * header size EXCLUDES the size of the `struct TCPBox`. We usually
   * never do this, but here the payload may truly be 64k *after* the
   * TCPBox (as we have no MTU)!!
   */
  struct GNUNET_MessageHeader header;

  /**
   * HMAC for the following encrypted message.  Yes, we MUST use
   * mac-then-encrypt here, as we want to hide the message sizes on
   * the wire (zero plaintext design!).  Using CTR mode, padding oracle
   * attacks do not apply.  Besides, due to the use of ephemeral keys
   * (hopefully with effective replay protection from monotonic time!)
   * the attacker is limited in using the oracle.
   */
  struct GNUNET_ShortHashCode hmac;

  /* followed by as may bytes of payload as indicated in @e header,
     excluding the TCPBox itself! */
};


/**
 * TCP rekey message box.  Always sent encrypted!  Data after
 * this message will use the new key.
 */
struct TCPRekey
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * HMAC for the following encrypted message.  Yes, we MUST use
   * mac-then-encrypt here, as we want to hide the message sizes on
   * the wire (zero plaintext design!).  Using CTR mode padding oracle
   * attacks do not apply.  Besides, due to the use of ephemeral keys
   * (hopefully with effective replay protection from monotonic time!)
   * the attacker is limited in using the oracle.
   */
  struct GNUNET_ShortHashCode hmac;

  /**
   * New ephemeral key.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral;

  /**
   * Sender's signature of type #GNUNET_SIGNATURE_COMMUNICATOR_TCP_REKEY
   */
  struct GNUNET_CRYPTO_EddsaSignature sender_sig;

  /**
   * Monotonic time of @e sender, to possibly help detect replay attacks
   * (if receiver persists times by sender).
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;
};


/**
 * TCP finish. Sender asks for the connection to be closed.
 * Needed/useful in case we drop RST/FIN packets on the GNUnet
 * port due to the possibility of malicious RST/FIN injection.
 */
struct TCPFinish
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH.
   */
  struct GNUNET_MessageHeader header;

  /**
   * HMAC for the following encrypted message.  Yes, we MUST use
   * mac-then-encrypt here, as we want to hide the message sizes on
   * the wire (zero plaintext design!).  Using CTR mode padding oracle
   * attacks do not apply.  Besides, due to the use of ephemeral keys
   * (hopefully with effective replay protection from monotonic time!)
   * the attacker is limited in using the oracle.
   */
  struct GNUNET_ShortHashCode hmac;
};


GNUNET_NETWORK_STRUCT_END


/**
 * Handle for a queue.
 */
struct Queue
{

  /**
   * To whom are we talking to.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * socket that we transmit all data with on this queue
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * cipher for decryption of incoming data.
   */
  gcry_cipher_hd_t in_cipher;

  /**
   * cipher for encryption of outgoing data.
   */
  gcry_cipher_hd_t out_cipher;

  /**
   * Shared secret for HMAC verification on incoming data.
   */
  struct GNUNET_HashCode in_hmac;

  /**
   * Shared secret for HMAC generation on outgoing data, ratcheted after
   * each operation.
   */
  struct GNUNET_HashCode out_hmac;

  /**
   * Our ephemeral key. Stored here temporarily during rekeying / key
   * generation.
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey ephemeral;

  /**
   * ID of read task for this connection.
   */
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * ID of write task for this connection.
   */
  struct GNUNET_SCHEDULER_Task *write_task;

  /**
   * Address of the other peer.
   */
  struct sockaddr *address;

  /**
   * How many more bytes may we sent with the current @e out_cipher
   * before we should rekey?
   */
  uint64_t rekey_left_bytes;

  /**
   * Until what time may we sent with the current @e out_cipher
   * before we should rekey?
   */
  struct GNUNET_TIME_Absolute rekey_time;

  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * Message queue we are providing for the #ch.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * handle for this queue with the #ch.
   */
  struct GNUNET_TRANSPORT_QueueHandle *qh;

  /**
   * Number of bytes we currently have in our write queue.
   */
  unsigned long long bytes_in_queue;

  /**
   * Buffer for reading ciphertext from network into.
   */
  char cread_buf[BUF_SIZE];

  /**
   * buffer for writing ciphertext to network.
   */
  char cwrite_buf[BUF_SIZE];

  /**
   * Plaintext buffer for decrypted plaintext.
   */
  char pread_buf[UINT16_MAX + 1 + sizeof (struct TCPBox)];

  /**
   * Plaintext buffer for messages to be encrypted.
   */
  char pwrite_buf[UINT16_MAX + 1 + sizeof (struct TCPBox)];

  /**
   * At which offset in the ciphertext read buffer should we
   * append more ciphertext for transmission next?
   */
  size_t cread_off;

  /**
   * At which offset in the ciphertext write buffer should we
   * append more ciphertext from reading next?
   */
  size_t cwrite_off;

  /**
   * At which offset in the plaintext input buffer should we
   * append more plaintext from decryption next?
   */
  size_t pread_off;

  /**
   * At which offset in the plaintext output buffer should we
   * append more plaintext for encryption next?
   */
  size_t pwrite_off;

  /**
   * Timeout for this queue.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How may messages did we pass from this queue to CORE for which we
   * have yet to receive an acknoweldgement that CORE is done with
   * them? If "large" (or even just non-zero), we should throttle
   * reading to provide flow control.  See also #DEFAULT_MAX_QUEUE_LENGTH
   * and #max_queue_length.
   */
  unsigned int backpressure;

  /**
   * Which network type does this queue use?
   */
  enum GNUNET_NetworkType nt;

  /**
   * Is MQ awaiting a #GNUNET_MQ_impl_send_continue() call?
   */
  int mq_awaits_continue;

  /**
   * Did we enqueue a finish message and are closing down the queue?
   */
  int finishing;

  /**
   * Did we technically destroy this queue, but kept the allocation
   * around because of @e backpressure not being zero yet? Used
   * simply to delay the final #GNUNET_free() operation until
   * #core_read_finished_cb() has been called.
   */
  int destroyed;

  /**
   * #GNUNET_YES after #inject_key() placed the rekey message into the
   * plaintext buffer. Once the plaintext buffer is drained, this
   * means we must switch to the new key material.
   */
  int rekey_state;

  /**
   * #GNUNET_YES if we just rekeyed and must thus possibly
   * re-decrypt ciphertext.
   */
  int rekeyed;
};


/**
 * Handle for an incoming connection where we do not yet have enough
 * information to setup a full queue.
 */
struct ProtoQueue
{

  /**
   * Kept in a DLL.
   */
  struct ProtoQueue *next;

  /**
   * Kept in a DLL.
   */
  struct ProtoQueue *prev;

  /**
   * socket that we transmit all data with on this queue
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * ID of read task for this connection.
   */
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * Address of the other peer.
   */
  struct sockaddr *address;

  /**
   * Length of the address.
   */
  socklen_t address_len;

  /**
   * Timeout for this protoqueue.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Buffer for reading all the information we need to upgrade from
   * protoqueue to queue.
   */
  char ibuf[INITIAL_KX_SIZE];

  /**
   * Current offset for reading into @e ibuf.
   */
  size_t ibuf_off;
};


/**
 * ID of listen task
 */
static struct GNUNET_SCHEDULER_Task *listen_task;

/**
 * Maximum queue length before we stop reading towards the transport service.
 */
static unsigned long long max_queue_length;

/**
 * For logging statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our environment.
 */
static struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

/**
 * Queues (map from peer identity to `struct Queue`)
 */
static struct GNUNET_CONTAINER_MultiPeerMap *queue_map;

/**
 * Listen socket.
 */
static struct GNUNET_NETWORK_Handle *listen_sock;

/**
 * Our public key.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Network scanner to determine network types.
 */
static struct GNUNET_NT_InterfaceScanner *is;

/**
 * Connection to NAT service.
 */
static struct GNUNET_NAT_Handle *nat;

/**
 * Protoqueues DLL head.
 */
static struct ProtoQueue *proto_head;

/**
 * Protoqueues DLL tail.
 */
static struct ProtoQueue *proto_tail;


/**
 * We have been notified that our listen socket has something to
 * read. Do the read and reschedule this function to be called again
 * once more is available.
 *
 * @param cls NULL
 */
static void
listen_cb (void *cls);


/**
 * Functions with this signature are called whenever we need
 * to close a queue due to a disconnect or failure to
 * establish a connection.
 *
 * @param queue queue to close down
 */
static void
queue_destroy (struct Queue *queue)
{
  struct GNUNET_MQ_Handle *mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting queue for peer `%s'\n",
              GNUNET_i2s (&queue->target));
  if (NULL != (mq = queue->mq))
  {
    queue->mq = NULL;
    GNUNET_MQ_destroy (mq);
  }
  if (NULL != queue->qh)
  {
    GNUNET_TRANSPORT_communicator_mq_del (queue->qh);
    queue->qh = NULL;
  }
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (queue_map, &queue->target, queue));
  GNUNET_STATISTICS_set (stats,
                         "# queues active",
                         GNUNET_CONTAINER_multipeermap_size (queue_map),
                         GNUNET_NO);
  if (NULL != queue->read_task)
  {
    GNUNET_SCHEDULER_cancel (queue->read_task);
    queue->read_task = NULL;
  }
  if (NULL != queue->write_task)
  {
    GNUNET_SCHEDULER_cancel (queue->write_task);
    queue->write_task = NULL;
  }
  GNUNET_NETWORK_socket_close (queue->sock);
  gcry_cipher_close (queue->in_cipher);
  gcry_cipher_close (queue->out_cipher);
  GNUNET_free (queue->address);
  if (0 != queue->backpressure)
    queue->destroyed = GNUNET_YES;
  else
    GNUNET_free (queue);
  if (NULL == listen_task)
    listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                 listen_sock,
                                                 &listen_cb,
                                                 NULL);
}


/**
 * Compute @a mac over @a buf, and ratched the @a hmac_secret.
 *
 * @param[in,out] hmac_secret secret for HMAC calculation
 * @param buf buffer to MAC
 * @param buf_size number of bytes in @a buf
 * @param smac[out] where to write the HMAC
 */
static void
calculate_hmac (struct GNUNET_HashCode *hmac_secret,
                const void *buf,
                size_t buf_size,
                struct GNUNET_ShortHashCode *smac)
{
  struct GNUNET_HashCode mac;

  GNUNET_CRYPTO_hmac_raw (hmac_secret,
                          sizeof (struct GNUNET_HashCode),
                          buf,
                          buf_size,
                          &mac);
  /* truncate to `struct GNUNET_ShortHashCode` */
  memcpy (smac, &mac, sizeof (struct GNUNET_ShortHashCode));
  /* ratchet hmac key */
  GNUNET_CRYPTO_hash (hmac_secret,
                      sizeof (struct GNUNET_HashCode),
                      hmac_secret);
}


/**
 * Append a 'finish' message to the outgoing transmission. Once the
 * finish has been transmitted, destroy the queue.
 *
 * @param queue queue to shut down nicely
 */
static void
queue_finish (struct Queue *queue)
{
  struct TCPFinish fin;

  memset (&fin, 0, sizeof (fin));
  fin.header.size = htons (sizeof (fin));
  fin.header.type = htons (GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH);
  calculate_hmac (&queue->out_hmac, &fin, sizeof (fin), &fin.hmac);
  /* if there is any message left in pwrite_buf, we
     overwrite it (possibly dropping the last message
     from CORE hard here) */
  memcpy (queue->pwrite_buf, &fin, sizeof (fin));
  queue->pwrite_off = sizeof (fin);
  /* This flag will ensure that #queue_write() no longer
     notifies CORE about the possibility of sending
     more data, and that #queue_write() will call
     #queue_destroy() once the @c fin was fully written. */
  queue->finishing = GNUNET_YES;
}


/**
 * Increment queue timeout due to activity.  We do not immediately
 * notify the monitor here as that might generate excessive
 * signalling.
 *
 * @param queue queue for which the timeout should be rescheduled
 */
static void
reschedule_queue_timeout (struct Queue *queue)
{
  queue->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Queue read task. If we hit the timeout, disconnect it
 *
 * @param cls the `struct Queue *` to disconnect
 */
static void
queue_read (void *cls);


/**
 * Core tells us it is done processing a message that transport
 * received on a queue with status @a success.
 *
 * @param cls a `struct Queue *` where the message originally came from
 * @param success #GNUNET_OK on success
 */
static void
core_read_finished_cb (void *cls, int success)
{
  struct Queue *queue = cls;

  if (GNUNET_OK != success)
    GNUNET_STATISTICS_update (stats,
                              "# messages lost in communicator API towards CORE",
                              1,
                              GNUNET_NO);
  queue->backpressure--;
  /* handle deferred queue destruction */
  if ((queue->destroyed) && (0 == queue->backpressure))
  {
    GNUNET_free (queue);
    return;
  }
  reschedule_queue_timeout (queue);
  /* possibly unchoke reading, now that CORE made progress */
  if (NULL == queue->read_task)
    queue->read_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_absolute_get_remaining (
                                       queue->timeout),
                                     queue->sock,
                                     &queue_read,
                                     queue);
}


/**
 * We received @a plaintext_len bytes of @a plaintext on @a queue.
 * Pass it on to CORE.  If transmission is actually happening,
 * increase backpressure counter.
 *
 * @param queue the queue that received the plaintext
 * @param plaintext the plaintext that was received
 * @param plaintext_len number of bytes of plaintext received
 */
static void
pass_plaintext_to_core (struct Queue *queue,
                        const void *plaintext,
                        size_t plaintext_len)
{
  const struct GNUNET_MessageHeader *hdr = plaintext;
  int ret;

  if (ntohs (hdr->size) != plaintext_len)
  {
    /* NOTE: If we ever allow multiple CORE messages in one
       BOX, this will have to change! */
    GNUNET_break (0);
    return;
  }
  ret = GNUNET_TRANSPORT_communicator_receive (ch,
                                               &queue->target,
                                               hdr,
                                               ADDRESS_VALIDITY_PERIOD,
                                               &core_read_finished_cb,
                                               queue);
  if (GNUNET_OK == ret)
    queue->backpressure++;
  GNUNET_break (GNUNET_NO != ret); /* backpressure not working!? */
  if (GNUNET_SYSERR == ret)
    GNUNET_STATISTICS_update (stats,
                              "# bytes lost due to CORE not running",
                              plaintext_len,
                              GNUNET_NO);
}


/**
 * Setup @a cipher based on shared secret @a dh and decrypting
 * peer @a pid.
 *
 * @param dh shared secret
 * @param pid decrypting peer's identity
 * @param cipher[out] cipher to initialize
 * @param hmac_key[out] HMAC key to initialize
 */
static void
setup_cipher (const struct GNUNET_HashCode *dh,
              const struct GNUNET_PeerIdentity *pid,
              gcry_cipher_hd_t *cipher,
              struct GNUNET_HashCode *hmac_key)
{
  char key[256 / 8];
  char ctr[128 / 8];

  gcry_cipher_open (cipher,
                    GCRY_CIPHER_AES256 /* low level: go for speed */,
                    GCRY_CIPHER_MODE_CTR,
                    0 /* flags */);
  GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_kdf (key,
                                                  sizeof (key),
                                                  "TCP-key",
                                                  strlen ("TCP-key"),
                                                  dh,
                                                  sizeof (*dh),
                                                  pid,
                                                  sizeof (*pid),
                                                  NULL,
                                                  0));
  gcry_cipher_setkey (*cipher, key, sizeof (key));
  GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_kdf (ctr,
                                                  sizeof (ctr),
                                                  "TCP-ctr",
                                                  strlen ("TCP-ctr"),
                                                  dh,
                                                  sizeof (*dh),
                                                  pid,
                                                  sizeof (*pid),
                                                  NULL,
                                                  0));
  gcry_cipher_setctr (*cipher, ctr, sizeof (ctr));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (hmac_key,
                                    sizeof (struct GNUNET_HashCode),
                                    "TCP-hmac",
                                    strlen ("TCP-hmac"),
                                    dh,
                                    sizeof (*dh),
                                    pid,
                                    sizeof (*pid),
                                    NULL,
                                    0));
}


/**
 * Setup cipher of @a queue for decryption.
 *
 * @param ephemeral ephemeral key we received from the other peer
 * @param queue[in,out] queue to initialize decryption cipher for
 */
static void
setup_in_cipher (const struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral,
                 struct Queue *queue)
{
  struct GNUNET_HashCode dh;

  GNUNET_CRYPTO_eddsa_ecdh (my_private_key, ephemeral, &dh);
  setup_cipher (&dh, &my_identity, &queue->in_cipher, &queue->in_hmac);
}


/**
 * Handle @a rekey message on @a queue. The message was already
 * HMAC'ed, but we should additionally still check the signature.
 * Then we need to stop the old cipher and start afresh.
 *
 * @param queue the queue @a rekey was received on
 * @param rekey the rekey message
 */
static void
do_rekey (struct Queue *queue, const struct TCPRekey *rekey)
{
  struct TcpHandshakeSignature thp;

  thp.purpose.purpose = htonl (GNUNET_SIGNATURE_COMMUNICATOR_TCP_REKEY);
  thp.purpose.size = htonl (sizeof (thp));
  thp.sender = queue->target;
  thp.receiver = my_identity;
  thp.ephemeral = rekey->ephemeral;
  thp.monotonic_time = rekey->monotonic_time;
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_COMMUNICATOR_TCP_REKEY,
                                  &thp.purpose,
                                  &rekey->sender_sig,
                                  &queue->target.public_key))
  {
    GNUNET_break (0);
    queue_finish (queue);
    return;
  }
  gcry_cipher_close (queue->in_cipher);
  queue->rekeyed = GNUNET_YES;
  setup_in_cipher (&rekey->ephemeral, queue);
}


/**
 * Test if we have received a full message in plaintext.
 * If so, handle it.
 *
 * @param queue queue to process inbound plaintext for
 * @return number of bytes of plaintext handled, 0 for none
 */
static size_t
try_handle_plaintext (struct Queue *queue)
{
  const struct GNUNET_MessageHeader *hdr =
    (const struct GNUNET_MessageHeader *) queue->pread_buf;
  const struct TCPBox *box = (const struct TCPBox *) queue->pread_buf;
  const struct TCPRekey *rekey = (const struct TCPRekey *) queue->pread_buf;
  const struct TCPFinish *fin = (const struct TCPFinish *) queue->pread_buf;
  struct TCPRekey rekeyz;
  struct TCPFinish finz;
  struct GNUNET_ShortHashCode tmac;
  uint16_t type;
  size_t size = 0; /* make compiler happy */

  if (sizeof (*hdr) > queue->pread_off)
    return 0; /* not even a header */
  type = ntohs (hdr->type);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX:
    /* Special case: header size excludes box itself! */
    if (ntohs (hdr->size) + sizeof (struct TCPBox) > queue->pread_off)
      return 0;
    calculate_hmac (&queue->in_hmac, &box[1], ntohs (hdr->size), &tmac);
    if (0 != memcmp (&tmac, &box->hmac, sizeof (tmac)))
    {
      GNUNET_break_op (0);
      queue_finish (queue);
      return 0;
    }
    pass_plaintext_to_core (queue, (const void *) &box[1], ntohs (hdr->size));
    size = ntohs (hdr->size) + sizeof (*box);
    break;
  case GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY:
    if (sizeof (*rekey) > queue->pread_off)
      return 0;
    if (ntohs (hdr->size) != sizeof (*rekey))
    {
      GNUNET_break_op (0);
      queue_finish (queue);
      return 0;
    }
    rekeyz = *rekey;
    memset (&rekeyz.hmac, 0, sizeof (rekeyz.hmac));
    calculate_hmac (&queue->in_hmac, &rekeyz, sizeof (rekeyz), &tmac);
    if (0 != memcmp (&tmac, &box->hmac, sizeof (tmac)))
    {
      GNUNET_break_op (0);
      queue_finish (queue);
      return 0;
    }
    do_rekey (queue, rekey);
    size = ntohs (hdr->size);
    break;
  case GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH:
    if (sizeof (*fin) > queue->pread_off)
      return 0;
    if (ntohs (hdr->size) != sizeof (*fin))
    {
      GNUNET_break_op (0);
      queue_finish (queue);
      return 0;
    }
    finz = *fin;
    memset (&finz.hmac, 0, sizeof (finz.hmac));
    calculate_hmac (&queue->in_hmac, &rekeyz, sizeof (rekeyz), &tmac);
    if (0 != memcmp (&tmac, &fin->hmac, sizeof (tmac)))
    {
      GNUNET_break_op (0);
      queue_finish (queue);
      return 0;
    }
    /* handle FINISH by destroying queue */
    queue_destroy (queue);
    break;
  default:
    GNUNET_break_op (0);
    queue_finish (queue);
    return 0;
  }
  GNUNET_assert (0 != size);
  return size;
}


/**
 * Queue read task. If we hit the timeout, disconnect it
 *
 * @param cls the `struct Queue *` to disconnect
 */
static void
queue_read (void *cls)
{
  struct Queue *queue = cls;
  struct GNUNET_TIME_Relative left;
  ssize_t rcvd;

  queue->read_task = NULL;
  rcvd = GNUNET_NETWORK_socket_recv (queue->sock,
                                     &queue->cread_buf[queue->cread_off],
                                     BUF_SIZE - queue->cread_off);
  if (-1 == rcvd)
  {
    if ((EAGAIN != errno) && (EINTR != errno))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "recv");
      queue_finish (queue);
      return;
    }
    /* try again */
    queue->read_task =
      GNUNET_SCHEDULER_add_read_net (left, queue->sock, &queue_read, queue);
    return;
  }
  if (0 != rcvd)
    reschedule_queue_timeout (queue);
  queue->cread_off += rcvd;
  while ((queue->pread_off < sizeof (queue->pread_buf)) &&
         (queue->cread_off > 0))
  {
    size_t max = GNUNET_MIN (sizeof (queue->pread_buf) - queue->pread_off,
                             queue->cread_off);
    size_t done;
    size_t total;

    GNUNET_assert (0 ==
                   gcry_cipher_decrypt (queue->in_cipher,
                                        &queue->pread_buf[queue->pread_off],
                                        max,
                                        queue->cread_buf,
                                        max));
    queue->pread_off += max;
    total = 0;
    while ((GNUNET_NO == queue->rekeyed) &&
           (0 != (done = try_handle_plaintext (queue))))
    {
      /* 'done' bytes of plaintext were used, shift buffer */
      GNUNET_assert (done <= queue->pread_off);
      /* NOTE: this memmove() could possibly sometimes be
   avoided if we pass 'total' into try_handle_plaintext()
   and use it at an offset into the buffer there! */
      memmove (queue->pread_buf,
               &queue->pread_buf[done],
               queue->pread_off - done);
      queue->pread_off -= done;
      total += done;
    }
    /* when we encounter a rekey message, the decryption above uses the
       wrong key for everything after the rekey; in that case, we have
       to re-do the decryption at 'total' instead of at 'max'. If there
       is no rekey and the last message is incomplete (max > total),
       it is safe to keep the decryption so we shift by 'max' */
    if (GNUNET_YES == queue->rekeyed)
    {
      max = total;
      queue->rekeyed = GNUNET_NO;
    }
    memmove (queue->cread_buf, &queue->cread_buf[max], queue->cread_off - max);
    queue->cread_off -= max;
  }

  if (BUF_SIZE == queue->cread_off)
    return; /* buffer full, suspend reading */
  left = GNUNET_TIME_absolute_get_remaining (queue->timeout);
  if (0 != left.rel_value_us)
  {
    if (max_queue_length < queue->backpressure)
    {
      /* continue reading */
      queue->read_task =
        GNUNET_SCHEDULER_add_read_net (left, queue->sock, &queue_read, queue);
    }
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queue %p was idle for %s, disconnecting\n",
              queue,
              GNUNET_STRINGS_relative_time_to_string (
                GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                GNUNET_YES));
  queue_finish (queue);
}


/**
 * Convert TCP bind specification to a `struct sockaddr *`
 *
 * @param bindto bind specification to convert
 * @param[out] sock_len set to the length of the address
 * @return converted bindto specification
 */
static struct sockaddr *
tcp_address_to_sockaddr (const char *bindto, socklen_t *sock_len)
{
  struct sockaddr *in;
  unsigned int port;
  char dummy[2];
  char *colon;
  char *cp;

  if (1 == SSCANF (bindto, "%u%1s", &port, dummy))
  {
    /* interpreting value as just a PORT number */
    if (port > UINT16_MAX)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "BINDTO specification `%s' invalid: value too large for port\n",
                  bindto);
      return NULL;
    }
    if ((GNUNET_NO == GNUNET_NETWORK_test_pf (PF_INET6)) ||
        (GNUNET_YES ==
         GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                               COMMUNICATOR_CONFIG_SECTION,
                                               "DISABLE_V6")))
    {
      struct sockaddr_in *i4;

      i4 = GNUNET_malloc (sizeof (struct sockaddr_in));
      i4->sin_family = AF_INET;
      i4->sin_port = htons ((uint16_t) port);
      *sock_len = sizeof (struct sockaddr_in);
      in = (struct sockaddr *) i4;
    }
    else
    {
      struct sockaddr_in6 *i6;

      i6 = GNUNET_malloc (sizeof (struct sockaddr_in6));
      i6->sin6_family = AF_INET6;
      i6->sin6_port = htons ((uint16_t) port);
      *sock_len = sizeof (struct sockaddr_in6);
      in = (struct sockaddr *) i6;
    }
    return in;
  }
  cp = GNUNET_strdup (bindto);
  colon = strrchr (cp, ':');
  if (NULL != colon)
  {
    /* interpet value after colon as port */
    *colon = '\0';
    colon++;
    if (1 == SSCANF (colon, "%u%1s", &port, dummy))
    {
      /* interpreting value as just a PORT number */
      if (port > UINT16_MAX)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "BINDTO specification `%s' invalid: value too large for port\n",
                    bindto);
        GNUNET_free (cp);
        return NULL;
      }
    }
    else
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_ERROR,
        "BINDTO specification `%s' invalid: last ':' not followed by number\n",
        bindto);
      GNUNET_free (cp);
      return NULL;
    }
  }
  else
  {
    /* interpret missing port as 0, aka pick any free one */
    port = 0;
  }
  {
    /* try IPv4 */
    struct sockaddr_in v4;

    if (1 == inet_pton (AF_INET, cp, &v4))
    {
      v4.sin_port = htons ((uint16_t) port);
      in = GNUNET_memdup (&v4, sizeof (v4));
      *sock_len = sizeof (v4);
      GNUNET_free (cp);
      return in;
    }
  }
  {
    /* try IPv6 */
    struct sockaddr_in6 v6;
    const char *start;

    start = cp;
    if (('[' == *cp) && (']' == cp[strlen (cp) - 1]))
    {
      start++; /* skip over '[' */
      cp[strlen (cp) - 1] = '\0'; /* eat ']' */
    }
    if (1 == inet_pton (AF_INET6, start, &v6))
    {
      v6.sin6_port = htons ((uint16_t) port);
      in = GNUNET_memdup (&v6, sizeof (v6));
      *sock_len = sizeof (v6);
      GNUNET_free (cp);
      return in;
    }
  }
  /* #5528 FIXME (feature!): maybe also try getnameinfo()? */
  GNUNET_free (cp);
  return NULL;
}


/**
 * Setup cipher for outgoing data stream based on target and
 * our ephemeral private key.
 *
 * @param queue queue to setup outgoing (encryption) cipher for
 */
static void
setup_out_cipher (struct Queue *queue)
{
  struct GNUNET_HashCode dh;

  GNUNET_CRYPTO_ecdh_eddsa (&queue->ephemeral, &queue->target.public_key, &dh);
  /* we don't need the private key anymore, drop it! */
  memset (&queue->ephemeral, 0, sizeof (queue->ephemeral));
  setup_cipher (&dh, &queue->target, &queue->out_cipher, &queue->out_hmac);
  queue->rekey_time = GNUNET_TIME_relative_to_absolute (REKEY_TIME_INTERVAL);
  queue->rekey_left_bytes =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, REKEY_MAX_BYTES);
}


/**
 * Inject a `struct TCPRekey` message into the queue's plaintext
 * buffer.
 *
 * @param queue queue to perform rekeying on
 */
static void
inject_rekey (struct Queue *queue)
{
  struct TCPRekey rekey;
  struct TcpHandshakeSignature thp;

  GNUNET_assert (0 == queue->pwrite_off);
  memset (&rekey, 0, sizeof (rekey));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdhe_key_create2 (&queue->ephemeral));
  rekey.header.type = ntohs (GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY);
  rekey.header.size = ntohs (sizeof (rekey));
  GNUNET_CRYPTO_ecdhe_key_get_public (&queue->ephemeral, &rekey.ephemeral);
  rekey.monotonic_time =
    GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get_monotonic (cfg));
  thp.purpose.purpose = htonl (GNUNET_SIGNATURE_COMMUNICATOR_TCP_REKEY);
  thp.purpose.size = htonl (sizeof (thp));
  thp.sender = my_identity;
  thp.receiver = queue->target;
  thp.ephemeral = rekey.ephemeral;
  thp.monotonic_time = rekey.monotonic_time;
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (my_private_key,
                                                        &thp.purpose,
                                                        &rekey.sender_sig));
  calculate_hmac (&queue->out_hmac, &rekey, sizeof (rekey), &rekey.hmac);
  memcpy (queue->pwrite_buf, &rekey, sizeof (rekey));
  queue->rekey_state = GNUNET_YES;
}


/**
 * We encrypted the rekey message, now update actually swap the key
 * material and update the key freshness parameters of @a queue.
 */
static void
switch_key (struct Queue *queue)
{
  queue->rekey_state = GNUNET_NO;
  gcry_cipher_close (queue->out_cipher);
  setup_out_cipher (queue);
}


/**
 * We have been notified that our socket is ready to write.
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls a `struct Queue`
 */
static void
queue_write (void *cls)
{
  struct Queue *queue = cls;
  ssize_t sent;

  queue->write_task = NULL;
  sent = GNUNET_NETWORK_socket_send (queue->sock,
                                     queue->cwrite_buf,
                                     queue->cwrite_off);
  if ((-1 == sent) && (EAGAIN != errno) && (EINTR != errno))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "send");
    queue_destroy (queue);
    return;
  }
  if (sent > 0)
  {
    size_t usent = (size_t) sent;

    memmove (queue->cwrite_buf,
             &queue->cwrite_buf[usent],
             queue->cwrite_off - usent);
    reschedule_queue_timeout (queue);
  }
  /* can we encrypt more? (always encrypt full messages, needed
     such that #mq_cancel() can work!) */
  if (queue->cwrite_off + queue->pwrite_off <= BUF_SIZE)
  {
    GNUNET_assert (0 ==
                   gcry_cipher_encrypt (queue->out_cipher,
                                        &queue->cwrite_buf[queue->cwrite_off],
                                        queue->pwrite_off,
                                        queue->pwrite_buf,
                                        queue->pwrite_off));
    if (queue->rekey_left_bytes > queue->pwrite_off)
      queue->rekey_left_bytes -= queue->pwrite_off;
    else
      queue->rekey_left_bytes = 0;
    queue->cwrite_off += queue->pwrite_off;
    queue->pwrite_off = 0;
  }
  if ((GNUNET_YES == queue->rekey_state) && (0 == queue->pwrite_off))
    switch_key (queue);
  if ((0 == queue->pwrite_off) &&
      ((0 == queue->rekey_left_bytes) ||
       (0 ==
        GNUNET_TIME_absolute_get_remaining (queue->rekey_time).rel_value_us)))
    inject_rekey (queue);
  if ((0 == queue->pwrite_off) && (! queue->finishing) &&
      (queue->mq_awaits_continue))
  {
    queue->mq_awaits_continue = GNUNET_NO;
    GNUNET_MQ_impl_send_continue (queue->mq);
  }
  /* did we just finish writing 'finish'? */
  if ((0 == queue->cwrite_off) && (GNUNET_YES == queue->finishing))
  {
    queue_destroy (queue);
    return;
  }
  /* do we care to write more? */
  if (0 < queue->cwrite_off)
    queue->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      queue->sock,
                                      &queue_write,
                                      queue);
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct Queue`
 */
static void
mq_send (struct GNUNET_MQ_Handle *mq,
         const struct GNUNET_MessageHeader *msg,
         void *impl_state)
{
  struct Queue *queue = impl_state;
  uint16_t msize = ntohs (msg->size);
  struct TCPBox box;

  GNUNET_assert (mq == queue->mq);
  if (GNUNET_YES == queue->finishing)
    return; /* this queue is dying, drop msg */
  GNUNET_assert (0 == queue->pread_off);
  box.header.type = htons (GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX);
  box.header.size = htons (msize);
  calculate_hmac (&queue->out_hmac, msg, msize, &box.hmac);
  memcpy (&queue->pread_buf[queue->pread_off], &box, sizeof (box));
  queue->pread_off += sizeof (box);
  memcpy (&queue->pread_buf[queue->pread_off], msg, msize);
  queue->pread_off += msize;
  GNUNET_assert (NULL != queue->sock);
  if (NULL == queue->write_task)
    queue->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      queue->sock,
                                      &queue_write,
                                      queue);
}


/**
 * Signature of functions implementing the destruction of a message
 * queue.  Implementations must not free @a mq, but should take care
 * of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state our `struct Queue`
 */
static void
mq_destroy (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Queue *queue = impl_state;

  if (mq == queue->mq)
  {
    queue->mq = NULL;
    queue_finish (queue);
  }
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state our `struct Queue`
 */
static void
mq_cancel (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Queue *queue = impl_state;

  GNUNET_assert (0 != queue->pwrite_off);
  queue->pwrite_off = 0;
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls our `struct Queue`
 * @param error error code
 */
static void
mq_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct Queue *queue = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "MQ error in queue to %s: %d\n",
              GNUNET_i2s (&queue->target),
              (int) error);
  queue_finish (queue);
}


/**
 * Add the given @a queue to our internal data structure.  Setup the
 * MQ processing and inform transport that the queue is ready.  Must
 * be called after the KX for outgoing messages has been bootstrapped.
 *
 * @param queue queue to boot
 */
static void
boot_queue (struct Queue *queue, enum GNUNET_TRANSPORT_ConnectionStatus cs)
{
  queue->nt =
    GNUNET_NT_scanner_get_type (is, queue->address, queue->address_len);
  (void) GNUNET_CONTAINER_multipeermap_put (
    queue_map,
    &queue->target,
    queue,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (stats,
                         "# queues active",
                         GNUNET_CONTAINER_multipeermap_size (queue_map),
                         GNUNET_NO);
  queue->timeout =
    GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  queue->mq = GNUNET_MQ_queue_for_callbacks (&mq_send,
                                             &mq_destroy,
                                             &mq_cancel,
                                             queue,
                                             NULL,
                                             &mq_error,
                                             queue);
  {
    char *foreign_addr;

    switch (queue->address->sa_family)
    {
    case AF_INET:
      GNUNET_asprintf (&foreign_addr,
                       "%s-%s",
                       COMMUNICATOR_ADDRESS_PREFIX,
                       GNUNET_a2s (queue->address, queue->address_len));
      break;
    case AF_INET6:
      GNUNET_asprintf (&foreign_addr,
                       "%s-%s",
                       COMMUNICATOR_ADDRESS_PREFIX,
                       GNUNET_a2s (queue->address, queue->address_len));
      break;
    default:
      GNUNET_assert (0);
    }
    queue->qh = GNUNET_TRANSPORT_communicator_mq_add (ch,
                                                      &queue->target,
                                                      foreign_addr,
                                                      0 /* no MTU */,
                                                      queue->nt,
                                                      cs,
                                                      queue->mq);
    GNUNET_free (foreign_addr);
  }
}


/**
 * Generate and transmit our ephemeral key and the signature for
 * the initial KX with the other peer.  Must be called first, before
 * any other bytes are ever written to the output buffer.  Note that
 * our cipher must already be initialized when calling this function.
 * Helper function for #start_initial_kx_out().
 *
 * @param queue queue to do KX for
 * @param epub our public key for the KX
 */
static void
transmit_kx (struct Queue *queue,
             const struct GNUNET_CRYPTO_EcdhePublicKey *epub)
{
  struct TcpHandshakeSignature ths;
  struct TCPConfirmation tc;

  memcpy (queue->cwrite_buf, epub, sizeof (*epub));
  queue->cwrite_off = sizeof (epub);
  /* compute 'tc' and append in encrypted format to cwrite_buf */
  tc.sender = my_identity;
  tc.monotonic_time =
    GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get_monotonic (cfg));
  ths.purpose.purpose = htonl (GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE);
  ths.purpose.size = htonl (sizeof (ths));
  ths.sender = my_identity;
  ths.receiver = queue->target;
  ths.ephemeral = *epub;
  ths.monotonic_time = tc.monotonic_time;
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (my_private_key,
                                                        &ths.purpose,
                                                        &tc.sender_sig));
  GNUNET_assert (0 ==
                 gcry_cipher_encrypt (queue->out_cipher,
                                      &queue->cwrite_buf[queue->cwrite_off],
                                      sizeof (tc),
                                      &tc,
                                      sizeof (tc)));
  queue->cwrite_off += sizeof (tc);
}


/**
 * Initialize our key material for outgoing transmissions and
 * inform the other peer about it. Must be called first before
 * any data is sent.
 *
 * @param queue the queue to setup
 */
static void
start_initial_kx_out (struct Queue *queue)
{
  struct GNUNET_CRYPTO_EcdhePublicKey epub;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdhe_key_create2 (&queue->ephemeral));
  GNUNET_CRYPTO_ecdhe_key_get_public (&queue->ephemeral, &epub);
  setup_out_cipher (queue);
  transmit_kx (queue, &epub);
}


/**
 * We have received the first bytes from the other side on a @a queue.
 * Decrypt the @a tc contained in @a ibuf and check the signature.
 * Note that #setup_in_cipher() must have already been called.
 *
 * @param queue queue to decrypt initial bytes from other peer for
 * @param tc[out] where to store the result
 * @param ibuf incoming data, of size
 *        `INITIAL_KX_SIZE`
 * @return #GNUNET_OK if the signature was OK, #GNUNET_SYSERR if not
 */
static int
decrypt_and_check_tc (struct Queue *queue,
                      struct TCPConfirmation *tc,
                      char *ibuf)
{
  struct TcpHandshakeSignature ths;

  GNUNET_assert (
    0 ==
    gcry_cipher_decrypt (queue->in_cipher,
                         tc,
                         sizeof (*tc),
                         &ibuf[sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)],
                         sizeof (tc)));
  ths.purpose.purpose = htonl (GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE);
  ths.purpose.size = htonl (sizeof (ths));
  ths.sender = tc->sender;
  ths.receiver = my_identity;
  memcpy (&ths.ephemeral, ibuf, sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
  ths.monotonic_time = tc->monotonic_time;
  return GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE,
                                     &ths.purpose,
                                     &tc->sender_sig,
                                     &tc->sender.public_key);
}


/**
 * Closes socket and frees memory associated with @a pq.
 *
 * @param pq proto queue to free
 */
static void
free_proto_queue (struct ProtoQueue *pq)
{
  GNUNET_NETWORK_socket_close (pq->sock);
  GNUNET_free (pq->address);
  GNUNET_CONTAINER_DLL_remove (proto_head, proto_tail, pq);
  GNUNET_free (pq);
}


/**
 * Read from the socket of the proto queue until we have enough data
 * to upgrade to full queue.
 *
 * @param cls a `struct ProtoQueue`
 */
static void
proto_read_kx (void *cls)
{
  struct ProtoQueue *pq = cls;
  ssize_t rcvd;
  struct GNUNET_TIME_Relative left;
  struct Queue *queue;
  struct TCPConfirmation tc;

  pq->read_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (pq->timeout);
  if (0 == left.rel_value_us)
  {
    free_proto_queue (pq);
    return;
  }
  rcvd = GNUNET_NETWORK_socket_recv (pq->sock,
                                     &pq->ibuf[pq->ibuf_off],
                                     sizeof (pq->ibuf) - pq->ibuf_off);
  if (-1 == rcvd)
  {
    if ((EAGAIN != errno) && (EINTR != errno))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "recv");
      free_proto_queue (pq);
      return;
    }
    /* try again */
    pq->read_task =
      GNUNET_SCHEDULER_add_read_net (left, pq->sock, &proto_read_kx, pq);
    return;
  }
  pq->ibuf_off += rcvd;
  if (pq->ibuf_off > sizeof (pq->ibuf))
  {
    /* read more */
    pq->read_task =
      GNUNET_SCHEDULER_add_read_net (left, pq->sock, &proto_read_kx, pq);
    return;
  }
  /* we got all the data, let's find out who we are talking to! */
  queue = GNUNET_new (struct Queue);
  setup_in_cipher ((const struct GNUNET_CRYPTO_EcdhePublicKey *) pq->ibuf,
                   queue);
  if (GNUNET_OK != decrypt_and_check_tc (queue, &tc, pq->ibuf))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Invalid TCP KX received from %s\n",
                GNUNET_a2s (queue->address, queue->address_len));
    gcry_cipher_close (queue->in_cipher);
    GNUNET_free (queue);
    free_proto_queue (pq);
    return;
  }
  queue->address = pq->address; /* steals reference */
  queue->address_len = pq->address_len;
  queue->target = tc.sender;
  start_initial_kx_out (queue);
  boot_queue (queue, GNUNET_TRANSPORT_CS_INBOUND);
  queue->read_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                   queue->sock,
                                   &queue_read,
                                   queue);
  GNUNET_CONTAINER_DLL_remove (proto_head, proto_tail, pq);
  GNUNET_free (pq);
}


/**
 * We have been notified that our listen socket has something to
 * read. Do the read and reschedule this function to be called again
 * once more is available.
 *
 * @param cls NULL
 */
static void
listen_cb (void *cls)
{
  struct sockaddr_storage in;
  socklen_t addrlen;
  struct GNUNET_NETWORK_Handle *sock;
  struct ProtoQueue *pq;

  listen_task = NULL;
  GNUNET_assert (NULL != listen_sock);
  addrlen = sizeof (in);
  memset (&in, 0, sizeof (in));
  sock = GNUNET_NETWORK_socket_accept (listen_sock,
                                       (struct sockaddr *) &in,
                                       &addrlen);
  if ((NULL == sock) && ((EMFILE == errno) || (ENFILE == errno)))
    return; /* system limit reached, wait until connection goes down */
  listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                               listen_sock,
                                               &listen_cb,
                                               NULL);
  if ((NULL == sock) && ((EAGAIN == errno) || (ENOBUFS == errno)))
    return;
  if (NULL == sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "accept");
    return;
  }
  pq = GNUNET_new (struct ProtoQueue);
  pq->address_len = addrlen;
  pq->address = GNUNET_memdup (&in, addrlen);
  pq->timeout = GNUNET_TIME_relative_to_absolute (PROTO_QUEUE_TIMEOUT);
  pq->sock = sock;
  pq->read_task = GNUNET_SCHEDULER_add_read_net (PROTO_QUEUE_TIMEOUT,
                                                 pq->sock,
                                                 &proto_read_kx,
                                                 pq);
  GNUNET_CONTAINER_DLL_insert (proto_head, proto_tail, pq);
}


/**
 * Read from the socket of the queue until we have enough data
 * to initialize the decryption logic and can switch to regular
 * reading.
 *
 * @param cls a `struct Queue`
 */
static void
queue_read_kx (void *cls)
{
  struct Queue *queue = cls;
  ssize_t rcvd;
  struct GNUNET_TIME_Relative left;
  struct TCPConfirmation tc;

  queue->read_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (queue->timeout);
  if (0 == left.rel_value_us)
  {
    queue_destroy (queue);
    return;
  }
  rcvd = GNUNET_NETWORK_socket_recv (queue->sock,
                                     &queue->cread_buf[queue->cread_off],
                                     BUF_SIZE - queue->cread_off);
  if (-1 == rcvd)
  {
    if ((EAGAIN != errno) && (EINTR != errno))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "recv");
      queue_destroy (queue);
      return;
    }
    queue->read_task =
      GNUNET_SCHEDULER_add_read_net (left, queue->sock, &queue_read_kx, queue);
    return;
  }
  queue->cread_off += rcvd;
  if (queue->cread_off < INITIAL_KX_SIZE)
  {
    /* read more */
    queue->read_task =
      GNUNET_SCHEDULER_add_read_net (left, queue->sock, &queue_read_kx, queue);
    return;
  }
  /* we got all the data, let's find out who we are talking to! */
  setup_in_cipher ((const struct GNUNET_CRYPTO_EcdhePublicKey *)
                     queue->cread_buf,
                   queue);
  if (GNUNET_OK != decrypt_and_check_tc (queue, &tc, queue->cread_buf))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Invalid TCP KX received from %s\n",
                GNUNET_a2s (queue->address, queue->address_len));
    queue_destroy (queue);
    return;
  }
  if (0 !=
      memcmp (&tc.sender, &queue->target, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid sender in TCP KX received from %s\n",
                GNUNET_a2s (queue->address, queue->address_len));
    queue_destroy (queue);
    return;
  }

  /* update queue timeout */
  reschedule_queue_timeout (queue);
  /* prepare to continue with regular read task immediately */
  memmove (queue->cread_buf,
           &queue->cread_buf[INITIAL_KX_SIZE],
           queue->cread_off - (INITIAL_KX_SIZE));
  queue->cread_off -= INITIAL_KX_SIZE;
  queue->read_task = GNUNET_SCHEDULER_add_now (&queue_read, queue);
}


/**
 * Function called by the transport service to initialize a
 * message queue given address information about another peer.
 * If and when the communication channel is established, the
 * communicator must call #GNUNET_TRANSPORT_communicator_mq_add()
 * to notify the service that the channel is now up.  It is
 * the responsibility of the communicator to manage sane
 * retries and timeouts for any @a peer/@a address combination
 * provided by the transport service.  Timeouts and retries
 * do not need to be signalled to the transport service.
 *
 * @param cls closure
 * @param peer identity of the other peer
 * @param address where to send the message, human-readable
 *        communicator-specific format, 0-terminated, UTF-8
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the provided address is
 * invalid
 */
static int
mq_init (void *cls, const struct GNUNET_PeerIdentity *peer, const char *address)
{
  struct Queue *queue;
  const char *path;
  struct sockaddr *in;
  socklen_t in_len;
  struct GNUNET_NETWORK_Handle *sock;

  if (0 != strncmp (address,
                    COMMUNICATOR_ADDRESS_PREFIX "-",
                    strlen (COMMUNICATOR_ADDRESS_PREFIX "-")))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  path = &address[strlen (COMMUNICATOR_ADDRESS_PREFIX "-")];
  in = tcp_address_to_sockaddr (path, &in_len);

  sock = GNUNET_NETWORK_socket_create (in->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (NULL == sock)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "socket(%d) failed: %s",
                in->sa_family,
                STRERROR (errno));
    GNUNET_free (in);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_connect (sock, in, in_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "connect to `%s' failed: %s",
                address,
                STRERROR (errno));
    GNUNET_NETWORK_socket_close (sock);
    GNUNET_free (in);
    return GNUNET_SYSERR;
  }

  queue = GNUNET_new (struct Queue);
  queue->target = *peer;
  queue->address = in;
  queue->address_len = in_len;
  queue->sock = sock;
  boot_queue (queue, GNUNET_TRANSPORT_CS_OUTBOUND);
  queue->read_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                   queue->sock,
                                   &queue_read_kx,
                                   queue);
  if (NULL == queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Failed to setup queue to %s at `%s'\n",
                GNUNET_i2s (peer),
                path);
    GNUNET_NETWORK_socket_close (sock);
    return GNUNET_NO;
  }
  start_initial_kx_out (queue);
  return GNUNET_OK;
}


/**
 * Iterator over all message queues to clean up.
 *
 * @param cls NULL
 * @param target unused
 * @param value the queue to destroy
 * @return #GNUNET_OK to continue to iterate
 */
static int
get_queue_delete_it (void *cls,
                     const struct GNUNET_PeerIdentity *target,
                     void *value)
{
  struct Queue *queue = value;

  (void) cls;
  (void) target;
  queue_destroy (queue);
  return GNUNET_OK;
}


/**
 * Shutdown the UNIX communicator.
 *
 * @param cls NULL (always)
 */
static void
do_shutdown (void *cls)
{
  if (NULL != nat)
  {
    GNUNET_NAT_unregister (nat);
    nat = NULL;
  }
  if (NULL != listen_task)
  {
    GNUNET_SCHEDULER_cancel (listen_task);
    listen_task = NULL;
  }
  if (NULL != listen_sock)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (listen_sock));
    listen_sock = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (queue_map, &get_queue_delete_it, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (queue_map);
  if (NULL != ch)
  {
    GNUNET_TRANSPORT_communicator_disconnect (ch);
    ch = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  if (NULL != my_private_key)
  {
    GNUNET_free (my_private_key);
    my_private_key = NULL;
  }
  if (NULL != is)
  {
    GNUNET_NT_scanner_done (is);
    is = NULL;
  }
}


/**
 * Function called when the transport service has received an
 * acknowledgement for this communicator (!) via a different return
 * path.
 *
 * Not applicable for TCP.
 *
 * @param cls closure
 * @param sender which peer sent the notification
 * @param msg payload
 */
static void
enc_notify_cb (void *cls,
               const struct GNUNET_PeerIdentity *sender,
               const struct GNUNET_MessageHeader *msg)
{
  (void) cls;
  (void) sender;
  (void) msg;
  GNUNET_break_op (0);
}


/**
 * Signature of the callback passed to #GNUNET_NAT_register() for
 * a function to call whenever our set of 'valid' addresses changes.
 *
 * @param cls closure
 * @param app_ctx[in,out] location where the app can store stuff
 *                  on add and retrieve it on remove
 * @param add_remove #GNUNET_YES to add a new public IP address,
 *                   #GNUNET_NO to remove a previous (now invalid) one
 * @param ac address class the address belongs to
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
static void
nat_address_cb (void *cls,
                void **app_ctx,
                int add_remove,
                enum GNUNET_NAT_AddressClass ac,
                const struct sockaddr *addr,
                socklen_t addrlen)
{
  char *my_addr;
  struct GNUNET_TRANSPORT_AddressIdentifier *ai;

  if (GNUNET_YES == add_remove)
  {
    enum GNUNET_NetworkType nt;

    GNUNET_asprintf (&my_addr,
                     "%s-%s",
                     COMMUNICATOR_ADDRESS_PREFIX,
                     GNUNET_a2s (addr, addrlen));
    nt = GNUNET_NT_scanner_get_type (is, addr, addrlen);
    ai =
      GNUNET_TRANSPORT_communicator_address_add (ch,
                                                 my_addr,
                                                 nt,
                                                 GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (my_addr);
    *app_ctx = ai;
  }
  else
  {
    ai = *app_ctx;
    GNUNET_TRANSPORT_communicator_address_remove (ai);
    *app_ctx = NULL;
  }
}


/**
 * Setup communicator and launch network interactions.
 *
 * @param cls NULL (always)
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *bindto;
  struct sockaddr *in;
  socklen_t in_len;
  struct sockaddr_storage in_sto;
  socklen_t sto_len;

  (void) cls;
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               COMMUNICATOR_CONFIG_SECTION,
                                               "BINDTO",
                                               &bindto))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               COMMUNICATOR_CONFIG_SECTION,
                               "BINDTO");
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             COMMUNICATOR_CONFIG_SECTION,
                                             "MAX_QUEUE_LENGTH",
                                             &max_queue_length))
    max_queue_length = DEFAULT_MAX_QUEUE_LENGTH;

  in = tcp_address_to_sockaddr (bindto, &in_len);
  if (NULL == in)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to setup TCP socket address with path `%s'\n",
                bindto);
    GNUNET_free (bindto);
    return;
  }
  listen_sock =
    GNUNET_NETWORK_socket_create (in->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (NULL == listen_sock)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    GNUNET_free (in);
    GNUNET_free (bindto);
    return;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (listen_sock, in, in_len))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "bind", bindto);
    GNUNET_NETWORK_socket_close (listen_sock);
    listen_sock = NULL;
    GNUNET_free (in);
    GNUNET_free (bindto);
    return;
  }
  /* We might have bound to port 0, allowing the OS to figure it out;
     thus, get the real IN-address from the socket */
  sto_len = sizeof (in_sto);
  if (0 != getsockname (GNUNET_NETWORK_get_fd (listen_sock),
                        (struct sockaddr *) &in_sto,
                        &sto_len))
  {
    memcpy (&in_sto, in, in_len);
    sto_len = in_len;
  }
  GNUNET_free (in);
  GNUNET_free (bindto);
  in = (struct sockaddr *) &in_sto;
  in_len = sto_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Bound to `%s'\n",
              GNUNET_a2s ((const struct sockaddr *) &in_sto, sto_len));
  stats = GNUNET_STATISTICS_create ("C-TCP", cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  is = GNUNET_NT_scanner_init ();
  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL == my_private_key)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ (
        "Transport service is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key, &my_identity.public_key);
  /* start listening */
  listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                               listen_sock,
                                               &listen_cb,
                                               NULL);
  queue_map = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  ch = GNUNET_TRANSPORT_communicator_connect (cfg,
                                              COMMUNICATOR_CONFIG_SECTION,
                                              COMMUNICATOR_ADDRESS_PREFIX,
                                              GNUNET_TRANSPORT_CC_RELIABLE,
                                              &mq_init,
                                              NULL,
                                              &enc_notify_cb,
                                              NULL);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  nat = GNUNET_NAT_register (cfg,
                             COMMUNICATOR_CONFIG_SECTION,
                             IPPROTO_TCP,
                             1 /* one address */,
                             (const struct sockaddr **) &in,
                             &in_len,
                             &nat_address_cb,
                             NULL /* FIXME: support reversal: #5529 */,
                             NULL /* closure */);
}


/**
 * The main function for the UNIX communicator.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END};
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                          argv,
                                          "gnunet-communicator-tcp",
                                          _ ("GNUnet TCP communicator"),
                                          options,
                                          &run,
                                          NULL))
          ? 0
          : 1;
  GNUNET_free ((void *) argv);
  return ret;
}


/* end of gnunet-communicator-tcp.c */

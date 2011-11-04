/*
     This file is part of GNUnet.
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file chat/gnunet-service-chat.c
 * @brief service providing chat functionality
 * @author Christian Grothoff
 * @author Vitaly Minko
 */

#include "platform.h"
#include "gnunet_core_service.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "chat.h"

#define DEBUG_CHAT_SERVICE GNUNET_EXTRA_LOGGING
#define MAX_TRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)
#define EXPECTED_NEIGHBOUR_COUNT 16
#define QUEUE_SIZE 16
#define MAX_ANONYMOUS_MSG_LIST_LENGTH 16


/**
 * Linked list of our current clients.
 */
struct ChatClient
{
  struct ChatClient *next;

  /**
   * Handle for a chat client (NULL for external clients).
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Public key of the client.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

  /**
   * Name of the room which the client is in.
   */
  char *room;

  /**
   * Serialized metadata of the client.
   */
  char *member_info;

  /**
   * Hash of the public key (for convenience).
   */
  GNUNET_HashCode id;

  /**
   * Options which the client is willing to receive.
   */
  uint32_t msg_options;

  /**
   * Length of serialized metadata in member_info.
   */
  uint16_t meta_len;

  /**
   * Sequence number of the last message sent by the client.
   */
  uint32_t msg_sequence_number;

  /**
   * Sequence number of the last receipt sent by the client.
   * Used to discard already processed receipts.
   */
  uint32_t rcpt_sequence_number;

};

/**
 * Information about a peer that we are connected to.
 * We track data that is useful for determining which
 * peers should receive our requests.
 */
struct ConnectedPeer
{
  /**
   * The peer's identity.
   */
  GNUNET_PEER_Id pid;
};

/**
 * Linked list of recent anonymous messages.
 */
struct AnonymousMessage
{
  struct AnonymousMessage *next;

  /**
   * Hash of the message.
   */
  GNUNET_HashCode hash;

};


/**
 * Handle to the core service (NULL until we've connected to it).
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The identity of this host.
 */
static const struct GNUNET_PeerIdentity *me;

/**
 * Head of the list of current clients.
 */
static struct ChatClient *client_list_head = NULL;

/**
 * Notification context containing all connected clients.
 */
struct GNUNET_SERVER_NotificationContext *nc = NULL;

/**
 * Head of the list of recent anonymous messages.
 */
static struct AnonymousMessage *anonymous_list_head = NULL;

/**
 * Map of peer identifiers to "struct ConnectedPeer" (for that peer).
 */
static struct GNUNET_CONTAINER_MultiHashMap *connected_peers;


static void
remember_anonymous_message (const struct P2PReceiveNotificationMessage
                            *p2p_rnmsg)
{
  static GNUNET_HashCode hash;
  struct AnonymousMessage *anon_msg;
  struct AnonymousMessage *prev;
  int anon_list_len;

  GNUNET_CRYPTO_hash (p2p_rnmsg, ntohs (p2p_rnmsg->header.size), &hash);
  anon_msg = GNUNET_malloc (sizeof (struct AnonymousMessage));
  anon_msg->hash = hash;
  anon_msg->next = anonymous_list_head;
  anonymous_list_head = anon_msg;
  anon_list_len = 1;
  prev = NULL;
  while ((NULL != anon_msg->next))
  {
    prev = anon_msg;
    anon_msg = anon_msg->next;
    anon_list_len++;
  }
  if (anon_list_len == MAX_ANONYMOUS_MSG_LIST_LENGTH)
  {
    GNUNET_free (anon_msg);
    if (NULL != prev)
      prev->next = NULL;
  }
}


static int
lookup_anonymous_message (const struct P2PReceiveNotificationMessage *p2p_rnmsg)
{
  static GNUNET_HashCode hash;
  struct AnonymousMessage *anon_msg;

  GNUNET_CRYPTO_hash (p2p_rnmsg, ntohs (p2p_rnmsg->header.size), &hash);
  anon_msg = anonymous_list_head;
  while ((NULL != anon_msg) &&
         (0 != memcmp (&anon_msg->hash, &hash, sizeof (GNUNET_HashCode))))
    anon_msg = anon_msg->next;
  return (NULL != anon_msg);
}


/**
 * Transmit a message notification to the peer.
 *
 * @param cls closure, pointer to the 'struct P2PReceiveNotificationMessage'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_message_notification_to_peer (void *cls, size_t size, void *buf)
{
  struct P2PReceiveNotificationMessage *my_msg = cls;
  struct P2PReceiveNotificationMessage *m = buf;
  size_t msg_size;

#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting P2P message notification\n");
#endif
  if (buf == NULL)
  {
    /* client disconnected */
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Buffer is NULL, dropping the message\n");
#endif
    return 0;
  }
  msg_size = ntohs (my_msg->header.size);
  GNUNET_assert (size >= msg_size);
  memcpy (m, my_msg, msg_size);
  GNUNET_free (my_msg);
  return msg_size;
}


/**
 * Ask to send a message notification to the peer.
 */
static int
send_message_noficiation (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct P2PReceiveNotificationMessage *msg = cls;
  struct ConnectedPeer *cp = value;
  struct GNUNET_PeerIdentity pid;
  struct P2PReceiveNotificationMessage *my_msg;

  GNUNET_PEER_resolve (cp->pid, &pid);
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending message notification to `%s'\n",
              GNUNET_i2s (&pid));
#endif
  my_msg = GNUNET_memdup (msg, ntohs (msg->header.size));
  if (NULL ==
      GNUNET_CORE_notify_transmit_ready (core, GNUNET_NO, 1, MAX_TRANSMIT_DELAY,
                                         &pid, ntohs (msg->header.size),
                                         &transmit_message_notification_to_peer,
                                         my_msg))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to queue a message notification\n"));
  return GNUNET_YES;
}


/**
 * A client sent a chat message.  Encrypt the message text if the message is
 * private.  Send the message to local room members and to all connected peers.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_transmit_request (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  static GNUNET_HashCode all_zeros;
  const struct TransmitRequestMessage *trmsg;
  struct ReceiveNotificationMessage *rnmsg;
  struct P2PReceiveNotificationMessage *p2p_rnmsg;
  struct ChatClient *pos;
  struct ChatClient *target;
  struct GNUNET_CRYPTO_AesSessionKey key;
  char encrypted_msg[MAX_MESSAGE_LENGTH];
  const char *room;
  size_t room_len;
  int msg_len;
  int is_priv;
  int is_anon;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Client sent a chat message\n");
  if (ntohs (message->size) <= sizeof (struct TransmitRequestMessage))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed message: wrong size\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  trmsg = (const struct TransmitRequestMessage *) message;
  msg_len = ntohs (trmsg->header.size) - sizeof (struct TransmitRequestMessage);
  is_priv = (0 != (ntohl (trmsg->msg_options) & GNUNET_CHAT_MSG_PRIVATE));
  if (is_priv)
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypting the message text\n");
#endif
    GNUNET_CRYPTO_aes_create_session_key (&key);
    msg_len =
        GNUNET_CRYPTO_aes_encrypt (&trmsg[1], msg_len, &key,
                                   (const struct
                                    GNUNET_CRYPTO_AesInitializationVector *)
                                   INITVALUE, encrypted_msg);
    if (-1 == msg_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not encrypt the message text\n");
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  }
  rnmsg = GNUNET_malloc (sizeof (struct ReceiveNotificationMessage) + msg_len);
  rnmsg->header.size =
      htons (sizeof (struct ReceiveNotificationMessage) + msg_len);
  rnmsg->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_MESSAGE_NOTIFICATION);
  rnmsg->msg_options = trmsg->msg_options;
  rnmsg->timestamp = trmsg->timestamp;
  pos = client_list_head;
  while ((NULL != pos) && (pos->client != client))
    pos = pos->next;
  if (NULL == pos)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "The client is not a member of a chat room. Client has to "
                "join a chat room first\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free (rnmsg);
    return;
  }
  room = pos->room;
  pos->msg_sequence_number = ntohl (trmsg->sequence_number);
  is_anon = (0 != (ntohl (trmsg->msg_options) & GNUNET_CHAT_MSG_ANONYMOUS));
  if (is_anon)
  {
    memset (&rnmsg->sender, 0, sizeof (GNUNET_HashCode));
    rnmsg->sequence_number = 0;
  }
  else
  {
    rnmsg->sender = pos->id;
    rnmsg->sequence_number = trmsg->sequence_number;
  }
  if (is_priv)
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypting the session key using the public key of '%s'\n",
                GNUNET_h2s (&trmsg->target));
#endif
    if (0 == memcmp (&all_zeros, &trmsg->target, sizeof (GNUNET_HashCode)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Malformed message: private, but no target\n");
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      GNUNET_free (rnmsg);
      return;
    }
    memcpy (&rnmsg[1], encrypted_msg, msg_len);
    target = client_list_head;
    while ((NULL != target) &&
           (0 !=
            memcmp (&target->id, &trmsg->target, sizeof (GNUNET_HashCode))))
      target = target->next;
    if (NULL == target)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unknown target of the private message\n");
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      GNUNET_free (rnmsg);
      return;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_rsa_encrypt (&key,
                                   sizeof (struct GNUNET_CRYPTO_AesSessionKey),
                                   &target->public_key, &rnmsg->encrypted_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not encrypt the session key\n");
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      GNUNET_free (rnmsg);
      return;
    }
  }
  else
  {
    memcpy (&rnmsg[1], &trmsg[1], msg_len);
  }
  pos = client_list_head;
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message to local room members\n");
#endif
  while (NULL != pos)
  {
    if ((0 == strcmp (room, pos->room)) && (NULL != pos->client) &&
        (pos->client != client))
    {
      if (((!is_priv) ||
           (0 == memcmp (&trmsg->target, &pos->id, sizeof (GNUNET_HashCode))))
          && (0 == (ntohl (trmsg->msg_options) & (~pos->msg_options))))
      {
        GNUNET_SERVER_notification_context_unicast (nc, pos->client,
                                                    &rnmsg->header, GNUNET_NO);
      }
    }
    pos = pos->next;
  }
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting message to neighbour peers\n");
#endif
  if (is_anon)
  {
    room_len = strlen (room);
    p2p_rnmsg =
        GNUNET_malloc (sizeof (struct P2PReceiveNotificationMessage) + msg_len +
                       room_len);
    p2p_rnmsg->header.size =
        htons (sizeof (struct P2PReceiveNotificationMessage) + msg_len +
               room_len);
    p2p_rnmsg->room_name_len = htons (room_len);
    memcpy ((char *) &p2p_rnmsg[1], room, room_len);
    memcpy ((char *) &p2p_rnmsg[1] + room_len, &trmsg[1], msg_len);
  }
  else
  {
    p2p_rnmsg =
        GNUNET_malloc (sizeof (struct P2PReceiveNotificationMessage) + msg_len);
    p2p_rnmsg->header.size =
        htons (sizeof (struct P2PReceiveNotificationMessage) + msg_len);
    if (is_priv)
    {
      memcpy (&p2p_rnmsg[1], encrypted_msg, msg_len);
      memcpy (&p2p_rnmsg->encrypted_key, &rnmsg->encrypted_key,
              sizeof (struct GNUNET_CRYPTO_RsaEncryptedData));
    }
    else
      memcpy (&p2p_rnmsg[1], &trmsg[1], msg_len);
  }
  p2p_rnmsg->header.type =
      htons (GNUNET_MESSAGE_TYPE_CHAT_P2P_MESSAGE_NOTIFICATION);
  p2p_rnmsg->msg_options = trmsg->msg_options;
  p2p_rnmsg->sequence_number = trmsg->sequence_number;
  p2p_rnmsg->timestamp = trmsg->timestamp;
  p2p_rnmsg->reserved = htons (0);
  p2p_rnmsg->sender = rnmsg->sender;
  p2p_rnmsg->target = trmsg->target;
  if (is_anon)
    remember_anonymous_message (p2p_rnmsg);
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                         &send_message_noficiation, p2p_rnmsg);
  GNUNET_free (p2p_rnmsg);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_free (rnmsg);
}


/**
 * Transmit a join notification to the peer.
 *
 * @param cls closure, pointer to the 'struct ChatClient'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_join_notification_to_peer (void *cls, size_t size, void *buf)
{
  struct ChatClient *entry = cls;
  struct P2PJoinNotificationMessage *m = buf;
  size_t room_len;
  size_t meta_len;
  size_t msg_size;
  char *roomptr;

#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting P2P join notification\n");
#endif
  room_len = strlen (entry->room);
  meta_len = entry->meta_len;
  msg_size = sizeof (struct P2PJoinNotificationMessage) + meta_len + room_len;
  GNUNET_assert (size >= msg_size);
  GNUNET_assert (NULL != buf);
  m = buf;
  m->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_P2P_JOIN_NOTIFICATION);
  m->header.size = htons (msg_size);
  m->msg_options = htonl (entry->msg_options);
  m->room_name_len = htons (room_len);
  m->reserved = htons (0);
  m->reserved2 = htonl (0);
  m->public_key = entry->public_key;
  roomptr = (char *) &m[1];
  memcpy (roomptr, entry->room, room_len);
  if (meta_len > 0)
    memcpy (&roomptr[room_len], entry->member_info, meta_len);
  return msg_size;
}


/**
 * Ask to send a join notification to the peer.
 */
static int
send_join_noficiation (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ChatClient *entry = cls;
  struct ConnectedPeer *cp = value;
  struct GNUNET_PeerIdentity pid;
  size_t msg_size;

  GNUNET_PEER_resolve (cp->pid, &pid);
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending join notification to `%s'\n",
              GNUNET_i2s (&pid));
#endif
  msg_size =
      sizeof (struct P2PJoinNotificationMessage) + strlen (entry->room) +
      entry->meta_len;
  if (NULL ==
      GNUNET_CORE_notify_transmit_ready (core, GNUNET_NO, 1, MAX_TRANSMIT_DELAY,
                                         &pid, msg_size,
                                         &transmit_join_notification_to_peer,
                                         entry))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to queue a join notification\n"));
  return GNUNET_YES;
}


/**
 * A client asked for entering a chat room.  Add the new member to the list of
 * clients and notify remaining room members.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_join_request (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  const struct JoinRequestMessage *jrmsg;
  char *room_name;
  const char *roomptr;
  uint16_t header_size;
  uint16_t meta_len;
  uint16_t room_name_len;
  struct ChatClient *new_entry;
  struct ChatClient *entry;
  struct JoinNotificationMessage *jnmsg;
  struct JoinNotificationMessage *entry_jnmsg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Client sent a join request\n");
  if (ntohs (message->size) <= sizeof (struct JoinRequestMessage))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed message: wrong size\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  jrmsg = (const struct JoinRequestMessage *) message;
  header_size = ntohs (jrmsg->header.size);
  room_name_len = ntohs (jrmsg->room_name_len);
  if (header_size - sizeof (struct JoinRequestMessage) <= room_name_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed message: wrong length of the room name\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  meta_len = header_size - sizeof (struct JoinRequestMessage) - room_name_len;
  roomptr = (const char *) &jrmsg[1];
  room_name = GNUNET_malloc (room_name_len + 1);
  memcpy (room_name, roomptr, room_name_len);
  room_name[room_name_len] = '\0';
  new_entry = GNUNET_malloc (sizeof (struct ChatClient));
  memset (new_entry, 0, sizeof (struct ChatClient));
  new_entry->client = client;
  new_entry->room = room_name;
  new_entry->public_key = jrmsg->public_key;
  new_entry->meta_len = meta_len;
  if (meta_len > 0)
  {
    new_entry->member_info = GNUNET_malloc (meta_len);
    memcpy (new_entry->member_info, &roomptr[room_name_len], meta_len);
  }
  else
    new_entry->member_info = NULL;
  GNUNET_CRYPTO_hash (&new_entry->public_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &new_entry->id);
  new_entry->msg_options = ntohl (jrmsg->msg_options);
  new_entry->next = client_list_head;
  client_list_head = new_entry;
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Synchronizing room members between local clients\n");
#endif
  jnmsg = GNUNET_malloc (sizeof (struct JoinNotificationMessage) + meta_len);
  jnmsg->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION);
  jnmsg->header.size =
      htons (sizeof (struct JoinNotificationMessage) + meta_len);
  jnmsg->msg_options = jrmsg->msg_options;
  jnmsg->public_key = new_entry->public_key;
  memcpy (&jnmsg[1], &roomptr[room_name_len], meta_len);
  GNUNET_SERVER_notification_context_add (nc, client);
  entry = client_list_head;
  while (NULL != entry)
  {
    if (0 == strcmp (room_name, entry->room))
    {
      if (NULL != entry->client)
        GNUNET_SERVER_notification_context_unicast (nc, entry->client,
                                                    &jnmsg->header, GNUNET_NO);
      if (entry->client != client)
      {
        entry_jnmsg =
            GNUNET_malloc (sizeof (struct JoinNotificationMessage) +
                           entry->meta_len);
        entry_jnmsg->header.type =
            htons (GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION);
        entry_jnmsg->header.size =
            htons (sizeof (struct JoinNotificationMessage) + entry->meta_len);
        entry_jnmsg->msg_options = entry->msg_options;
        entry_jnmsg->public_key = entry->public_key;
        memcpy (&entry_jnmsg[1], entry->member_info, entry->meta_len);
        GNUNET_SERVER_notification_context_unicast (nc, client,
                                                    &entry_jnmsg->header,
                                                    GNUNET_NO);
        GNUNET_free (entry_jnmsg);
      }
    }
    entry = entry->next;
  }
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting join notification to neighbour peers\n");
#endif
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                         &send_join_noficiation, new_entry);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_free (jnmsg);
}

/**
 * Transmit a confirmation receipt to the peer.
 *
 * @param cls closure, pointer to the 'struct P2PConfirmationReceiptMessage'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_confirmation_receipt_to_peer (void *cls, size_t size, void *buf)
{
  struct P2PConfirmationReceiptMessage *receipt = cls;
  size_t msg_size;

#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting P2P confirmation receipt to '%s'\n",
              GNUNET_h2s (&receipt->target));
#endif
  if (buf == NULL)
  {
    /* client disconnected */
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Buffer is NULL, dropping the message\n");
#endif
    return 0;
  }
  msg_size = sizeof (struct P2PConfirmationReceiptMessage);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, receipt, msg_size);
  GNUNET_free (receipt);
  return msg_size;
}


/**
 * Ask to send a confirmation receipt to the peer.
 */
static int
send_confirmation_receipt (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct P2PConfirmationReceiptMessage *receipt = cls;
  struct ConnectedPeer *cp = value;
  struct GNUNET_PeerIdentity pid;
  struct P2PConfirmationReceiptMessage *my_receipt;
  size_t msg_size;

  GNUNET_PEER_resolve (cp->pid, &pid);
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending confirmation receipt to `%s'\n",
              GNUNET_i2s (&pid));
#endif
  msg_size = sizeof (struct P2PConfirmationReceiptMessage);
  my_receipt =
      GNUNET_memdup (receipt, sizeof (struct P2PConfirmationReceiptMessage));
  if (NULL ==
      GNUNET_CORE_notify_transmit_ready (core, GNUNET_YES, 1,
                                         MAX_TRANSMIT_DELAY, &pid, msg_size,
                                         &transmit_confirmation_receipt_to_peer,
                                         my_receipt))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to queue a confirmation receipt\n"));
  return GNUNET_YES;
}


/**
 * A client sent a confirmation receipt.  Broadcast the receipt to all connected
 * peers if the author of the original message is a local client.  Otherwise
 * check the signature and notify the user if the signature is valid.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_acknowledge_request (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct ConfirmationReceiptMessage *receipt;
  struct ConfirmationReceiptMessage *crmsg;
  struct P2PConfirmationReceiptMessage *p2p_crmsg;
  struct ChatClient *target;
  struct ChatClient *author;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Client sent a confirmation receipt\n");
  receipt = (const struct ConfirmationReceiptMessage *) message;
  author = client_list_head;
  while ((NULL != author) &&
         (0 !=
          memcmp (&receipt->author, &author->id, sizeof (GNUNET_HashCode))))
    author = author->next;
  if (NULL == author)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unknown author of the original message\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  target = client_list_head;
  while ((NULL != target) &&
         (0 !=
          memcmp (&receipt->target, &target->id, sizeof (GNUNET_HashCode))))
    target = target->next;
  if (NULL == target)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unknown target of the confirmation receipt\n");
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == author->client)
  {
    target->rcpt_sequence_number++;
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Broadcasting %s's receipt #%u to neighbour peers\n",
                GNUNET_h2s (&target->id), target->rcpt_sequence_number);
#endif
    p2p_crmsg = GNUNET_malloc (sizeof (struct P2PConfirmationReceiptMessage));
    p2p_crmsg->header.size =
        htons (sizeof (struct P2PConfirmationReceiptMessage));
    p2p_crmsg->header.type =
        htons (GNUNET_MESSAGE_TYPE_CHAT_P2P_CONFIRMATION_RECEIPT);
    p2p_crmsg->reserved = htonl (0);
    p2p_crmsg->signature = receipt->signature;
    p2p_crmsg->purpose = receipt->purpose;
    p2p_crmsg->msg_sequence_number = receipt->sequence_number;
    p2p_crmsg->timestamp = receipt->timestamp;
    p2p_crmsg->target = receipt->target;
    p2p_crmsg->author = receipt->author;
    p2p_crmsg->content = receipt->content;
    p2p_crmsg->sequence_number = htonl (target->rcpt_sequence_number);
    GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                           &send_confirmation_receipt,
                                           p2p_crmsg);
    GNUNET_free (p2p_crmsg);
  }
  else
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Verifying signature of the receipt\n");
#endif
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_CHAT_RECEIPT,
                                  &receipt->purpose, &receipt->signature,
                                  &target->public_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Invalid signature of the receipt\n");
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending receipt to the client which sent the original message\n");
#endif
    crmsg = GNUNET_memdup (receipt, sizeof (struct ConfirmationReceiptMessage));
    crmsg->header.type =
        htons (GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_NOTIFICATION);
    GNUNET_SERVER_notification_context_unicast (nc, author->client,
                                                &crmsg->header, GNUNET_NO);
    GNUNET_free (crmsg);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Transmit a leave notification to the peer.
 *
 * @param cls closure, pointer to the
 *        'struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_leave_notification_to_peer (void *cls, size_t size, void *buf)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key = cls;
  struct P2PLeaveNotificationMessage *m = buf;
  size_t msg_size;

#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting P2P leave notification\n");
#endif
  if (buf == NULL)
  {
    /* client disconnected */
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Buffer is NULL, dropping the message\n");
#endif
    return 0;
  }
  msg_size = sizeof (struct P2PLeaveNotificationMessage);
  GNUNET_assert (size >= msg_size);
  m = buf;
  m->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_P2P_LEAVE_NOTIFICATION);
  m->header.size = htons (msg_size);
  m->reserved = htonl (0);
  m->user = *public_key;
  GNUNET_free (public_key);
  return msg_size;
}


/**
 * Ask to send a leave notification to the peer.
 */
static int
send_leave_noficiation (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ChatClient *entry = cls;
  struct ConnectedPeer *cp = value;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key;
  size_t msg_size;

  GNUNET_PEER_resolve (cp->pid, &pid);
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending leave notification to `%s'\n",
              GNUNET_i2s (&pid));
#endif
  msg_size = sizeof (struct P2PLeaveNotificationMessage);
  public_key =
      GNUNET_memdup (&entry->public_key,
                     sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (NULL ==
      GNUNET_CORE_notify_transmit_ready (core, GNUNET_YES, 1,
                                         MAX_TRANSMIT_DELAY, &pid, msg_size,
                                         &transmit_leave_notification_to_peer,
                                         public_key))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to queue a leave notification\n"));
  return GNUNET_YES;
}


/**
 * A client disconnected.  Remove all of its data structure entries and notify
 * remaining room members.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ChatClient *entry;
  struct ChatClient *pos;
  struct ChatClient *prev;
  struct LeaveNotificationMessage lnmsg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Client disconnected\n");
  pos = client_list_head;
  prev = NULL;
  while ((NULL != pos) && (pos->client != client))
  {
    prev = pos;
    pos = pos->next;
  }
  if (NULL == pos)
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No such client. There is nothing to do\n");
#endif
    return;
  }
  if (NULL == prev)
    client_list_head = pos->next;
  else
    prev->next = pos->next;
  entry = client_list_head;
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying local room members that the client has disconnected\n");
#endif
  lnmsg.header.size = htons (sizeof (struct LeaveNotificationMessage));
  lnmsg.header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_LEAVE_NOTIFICATION);
  lnmsg.reserved = htonl (0);
  lnmsg.user = pos->public_key;
  while (NULL != entry)
  {
    if ((0 == strcmp (pos->room, entry->room)) && (NULL != entry->client))
    {
      GNUNET_SERVER_notification_context_unicast (nc, entry->client,
                                                  &lnmsg.header, GNUNET_NO);
    }
    entry = entry->next;
  }
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting leave notification to neighbour peers\n");
#endif
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                         &send_leave_noficiation, pos);
  GNUNET_free (pos->room);
  GNUNET_free_non_null (pos->member_info);
  GNUNET_free (pos);
}


/**
 * Handle P2P join notification.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of entries in atsi
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_join_notification (void *cls,
                              const struct GNUNET_PeerIdentity *other,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_ATS_Information *atsi,
                              unsigned int atsi_count)
{
  const struct P2PJoinNotificationMessage *p2p_jnmsg;
  char *room_name;
  const char *roomptr;
  uint16_t header_size;
  uint16_t meta_len;
  uint16_t room_name_len;
  struct ChatClient *new_entry;
  struct ChatClient *entry;
  struct JoinNotificationMessage *jnmsg;
  GNUNET_HashCode id;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got P2P join notification\n");
  if (ntohs (message->size) <= sizeof (struct P2PJoinNotificationMessage))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed message: wrong size\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  p2p_jnmsg = (const struct P2PJoinNotificationMessage *) message;
  header_size = ntohs (p2p_jnmsg->header.size);
  room_name_len = ntohs (p2p_jnmsg->room_name_len);
  if (header_size - sizeof (struct P2PJoinNotificationMessage) <= room_name_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed message: wrong length of the room name\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_hash (&p2p_jnmsg->public_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &id);
  entry = client_list_head;
  while (NULL != entry)
  {
    if (0 == memcmp (&entry->id, &id, sizeof (GNUNET_HashCode)))
    {
#if DEBUG_CHAT_SERVICE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "The client has already joined. There is nothing to do\n");
#endif
      return GNUNET_OK;
    }
    entry = entry->next;
  }
  meta_len =
      header_size - sizeof (struct P2PJoinNotificationMessage) - room_name_len;
  roomptr = (const char *) &p2p_jnmsg[1];
  room_name = GNUNET_malloc (room_name_len + 1);
  memcpy (room_name, roomptr, room_name_len);
  room_name[room_name_len] = '\0';
  new_entry = GNUNET_malloc (sizeof (struct ChatClient));
  memset (new_entry, 0, sizeof (struct ChatClient));
  new_entry->id = id;
  new_entry->client = NULL;
  new_entry->room = room_name;
  new_entry->public_key = p2p_jnmsg->public_key;
  new_entry->meta_len = meta_len;
  if (meta_len > 0)
  {
    new_entry->member_info = GNUNET_malloc (meta_len);
    memcpy (new_entry->member_info, &roomptr[room_name_len], meta_len);
  }
  else
    new_entry->member_info = NULL;
  new_entry->msg_options = ntohl (p2p_jnmsg->msg_options);
  new_entry->next = client_list_head;
  client_list_head = new_entry;
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying local room members that we have a new client\n");
#endif
  jnmsg = GNUNET_malloc (sizeof (struct JoinNotificationMessage) + meta_len);
  jnmsg->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION);
  jnmsg->header.size =
      htons (sizeof (struct JoinNotificationMessage) + meta_len);
  jnmsg->msg_options = p2p_jnmsg->msg_options;
  jnmsg->public_key = new_entry->public_key;
  memcpy (&jnmsg[1], &roomptr[room_name_len], meta_len);
  entry = client_list_head;
  while (NULL != entry)
  {
    if ((0 == strcmp (room_name, entry->room)) && (NULL != entry->client))
    {
      GNUNET_SERVER_notification_context_unicast (nc, entry->client,
                                                  &jnmsg->header, GNUNET_NO);
    }
    entry = entry->next;
  }
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting join notification to neighbour peers\n");
#endif
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                         &send_join_noficiation, new_entry);
  GNUNET_free (jnmsg);
  return GNUNET_OK;
}


/**
 * Handle P2P leave notification.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of entries in atsi
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_leave_notification (void *cls,
                               const struct GNUNET_PeerIdentity *other,
                               const struct GNUNET_MessageHeader *message,
                               const struct GNUNET_ATS_Information *atsi,
                               unsigned int atsi_count)
{
  const struct P2PLeaveNotificationMessage *p2p_lnmsg;
  GNUNET_HashCode id;
  struct ChatClient *pos;
  struct ChatClient *prev;
  struct ChatClient *entry;
  struct LeaveNotificationMessage lnmsg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got P2P leave notification\n");
  p2p_lnmsg = (const struct P2PLeaveNotificationMessage *) message;
  GNUNET_CRYPTO_hash (&p2p_lnmsg->user,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &id);
  pos = client_list_head;
  prev = NULL;
  while (NULL != pos)
  {
    if (0 == memcmp (&pos->id, &id, sizeof (GNUNET_HashCode)))
      break;
    prev = pos;
    pos = pos->next;
  }
  if (NULL == pos)
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No such client. There is nothing to do\n");
#endif
    return GNUNET_OK;
  }
  if (NULL == prev)
    client_list_head = pos->next;
  else
    prev->next = pos->next;
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying local room members that the client has gone away\n");
#endif
  lnmsg.header.size = htons (sizeof (struct LeaveNotificationMessage));
  lnmsg.header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_LEAVE_NOTIFICATION);
  lnmsg.reserved = htonl (0);
  lnmsg.user = pos->public_key;
  entry = client_list_head;
  while (NULL != entry)
  {
    if (0 == strcmp (pos->room, entry->room) && (NULL != entry->client))
    {
      GNUNET_SERVER_notification_context_unicast (nc, entry->client,
                                                  &lnmsg.header, GNUNET_NO);
    }
    entry = entry->next;
  }
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting leave notification to neighbour peers\n");
#endif
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                         &send_leave_noficiation, pos);
  GNUNET_free (pos->room);
  GNUNET_free_non_null (pos->member_info);
  GNUNET_free (pos);
  return GNUNET_OK;
}


/**
 * Handle P2P message notification.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of entries in atsi
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_message_notification (void *cls,
                                 const struct GNUNET_PeerIdentity *other,
                                 const struct GNUNET_MessageHeader *message,
                                 const struct GNUNET_ATS_Information *atsi,
                                 unsigned int atsi_count)
{
  const struct P2PReceiveNotificationMessage *p2p_rnmsg;
  struct P2PReceiveNotificationMessage *my_p2p_rnmsg;
  struct ReceiveNotificationMessage *rnmsg;
  struct ChatClient *sender;
  struct ChatClient *pos;
  static GNUNET_HashCode all_zeros;
  int is_priv;
  int is_anon;
  uint16_t msg_len;
  uint16_t room_name_len;
  char *room_name = NULL;
  char *text;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got P2P message notification\n");
  if (ntohs (message->size) <= sizeof (struct P2PReceiveNotificationMessage))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed message: wrong size\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  p2p_rnmsg = (const struct P2PReceiveNotificationMessage *) message;
  msg_len =
      ntohs (p2p_rnmsg->header.size) -
      sizeof (struct P2PReceiveNotificationMessage);

  is_anon = (0 != (ntohl (p2p_rnmsg->msg_options) & GNUNET_CHAT_MSG_ANONYMOUS));
  if (is_anon)
  {
    room_name_len = ntohs (p2p_rnmsg->room_name_len);
    if (msg_len <= room_name_len)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Malformed message: wrong length of the room name\n");
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    msg_len -= room_name_len;
    if (lookup_anonymous_message (p2p_rnmsg))
    {
#if DEBUG_CHAT_SERVICE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "This anonymous message has already been handled.");
#endif
      return GNUNET_OK;
    }
    remember_anonymous_message (p2p_rnmsg);
    room_name = GNUNET_malloc (room_name_len + 1);
    memcpy (room_name, (char *) &p2p_rnmsg[1], room_name_len);
    room_name[room_name_len] = '\0';
    text = (char *) &p2p_rnmsg[1] + room_name_len;
  }
  else
  {
    sender = client_list_head;
    while ((NULL != sender) &&
           (0 !=
            memcmp (&sender->id, &p2p_rnmsg->sender, sizeof (GNUNET_HashCode))))
      sender = sender->next;
    if (NULL == sender)
    {
      /* not an error since the sender may have left before we got the
       * message */
#if DEBUG_CHAT_SERVICE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Unknown source. Rejecting the message\n");
#endif
      return GNUNET_OK;
    }
    if (sender->msg_sequence_number >= ntohl (p2p_rnmsg->sequence_number))
    {
#if DEBUG_CHAT_SERVICE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "This message has already been handled."
                  " Sequence numbers (msg/sender): %u/%u\n",
                  ntohl (p2p_rnmsg->sequence_number),
                  sender->msg_sequence_number);
#endif
      return GNUNET_OK;
    }
    sender->msg_sequence_number = ntohl (p2p_rnmsg->sequence_number);
    room_name = sender->room;
    text = (char *) &p2p_rnmsg[1];
  }

#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message to local room members\n");
#endif
  rnmsg = GNUNET_malloc (sizeof (struct ReceiveNotificationMessage) + msg_len);
  rnmsg->header.size =
      htons (sizeof (struct ReceiveNotificationMessage) + msg_len);
  rnmsg->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_MESSAGE_NOTIFICATION);
  rnmsg->msg_options = p2p_rnmsg->msg_options;
  rnmsg->sequence_number = p2p_rnmsg->sequence_number;
  rnmsg->reserved = htonl (0);
  rnmsg->timestamp = p2p_rnmsg->timestamp;
  is_priv =
      (0 != memcmp (&all_zeros, &p2p_rnmsg->target, sizeof (GNUNET_HashCode)));
  if (is_priv)
    memcpy (&rnmsg->encrypted_key, &p2p_rnmsg->encrypted_key,
            sizeof (struct GNUNET_CRYPTO_RsaEncryptedData));
  rnmsg->sender = p2p_rnmsg->sender;
  memcpy (&rnmsg[1], text, msg_len);
  pos = client_list_head;
  while (NULL != pos)
  {
    if ((0 == strcmp (room_name, pos->room)) && (NULL != pos->client))
    {
      if (((!is_priv) ||
           (0 ==
            memcmp (&p2p_rnmsg->target, &pos->id, sizeof (GNUNET_HashCode)))) &&
          (0 == (ntohl (p2p_rnmsg->msg_options) & (~pos->msg_options))))
      {
        GNUNET_SERVER_notification_context_unicast (nc, pos->client,
                                                    &rnmsg->header, GNUNET_NO);
      }
    }
    pos = pos->next;
  }
  if (is_anon)
    GNUNET_free (room_name);
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting message notification to neighbour peers\n");
#endif
  my_p2p_rnmsg = GNUNET_memdup (p2p_rnmsg, ntohs (p2p_rnmsg->header.size));
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                         &send_message_noficiation,
                                         my_p2p_rnmsg);
  GNUNET_free (rnmsg);
  return GNUNET_OK;
}


/**
 * Handle P2P sync request.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of entries in atsi
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_sync_request (void *cls, const struct GNUNET_PeerIdentity *other,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information *atsi,
                         unsigned int atsi_count)
{
  struct ChatClient *entry;
  struct GNUNET_CORE_TransmitHandle *th;
  size_t msg_size;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got P2P sync request\n");
#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying the requester of all known clients\n");
#endif
  entry = client_list_head;
  while (NULL != entry)
  {
    msg_size =
        sizeof (struct P2PJoinNotificationMessage) + strlen (entry->room) +
        entry->meta_len;
    th = GNUNET_CORE_notify_transmit_ready (core, GNUNET_NO, 1,
                                            MAX_TRANSMIT_DELAY, other, msg_size,
                                            &transmit_join_notification_to_peer,
                                            entry);
    GNUNET_assert (NULL != th);
    entry = entry->next;
  }
  return GNUNET_OK;
}


/**
 * Handle P2P confirmation receipt.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved
 * @param message the actual message
 * @param atsi performance information
 * @param atsi_count number of entries in atsi
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_confirmation_receipt (void *cls,
                                 const struct GNUNET_PeerIdentity *other,
                                 const struct GNUNET_MessageHeader *message,
                                 const struct GNUNET_ATS_Information *atsi,
                                 unsigned int atsi_count)
{
  const struct P2PConfirmationReceiptMessage *p2p_crmsg;
  struct P2PConfirmationReceiptMessage *my_p2p_crmsg;
  struct ConfirmationReceiptMessage *crmsg;
  struct ChatClient *target;
  struct ChatClient *author;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Got P2P confirmation receipt\n");
  p2p_crmsg = (const struct P2PConfirmationReceiptMessage *) message;
  target = client_list_head;
  while ((NULL != target) &&
         (0 !=
          memcmp (&target->id, &p2p_crmsg->target, sizeof (GNUNET_HashCode))))
    target = target->next;
  if (NULL == target)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unknown source of the receipt. Rejecting the message\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (target->rcpt_sequence_number >= ntohl (p2p_crmsg->sequence_number))
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "This receipt has already been handled."
                " Sequence numbers (msg/sender): %u/%u\n",
                ntohl (p2p_crmsg->sequence_number),
                target->rcpt_sequence_number);
#endif
    return GNUNET_OK;
  }
  target->rcpt_sequence_number = ntohl (p2p_crmsg->sequence_number);
  author = client_list_head;
  while ((NULL != author) &&
         (0 !=
          memcmp (&author->id, &p2p_crmsg->author, sizeof (GNUNET_HashCode))))
    author = author->next;
  if (NULL == author)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unknown addressee. Rejecting the receipt\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  if (NULL == author->client)
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "The author of the original message is not a local client."
                " Broadcasting receipt to neighbour peers\n");
#endif
    my_p2p_crmsg =
        GNUNET_memdup (p2p_crmsg,
                       sizeof (struct P2PConfirmationReceiptMessage));
    GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
                                           &send_confirmation_receipt,
                                           my_p2p_crmsg);
    GNUNET_free (my_p2p_crmsg);
  }
  else
  {
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "The author of the original message is a local client."
                " Verifying signature of the receipt\n");
#endif
    crmsg = GNUNET_malloc (sizeof (struct ConfirmationReceiptMessage));
    crmsg->header.size = htons (sizeof (struct ConfirmationReceiptMessage));
    crmsg->header.type =
        htons (GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_NOTIFICATION);
    crmsg->signature = p2p_crmsg->signature;
    crmsg->purpose = p2p_crmsg->purpose;
    crmsg->sequence_number = p2p_crmsg->msg_sequence_number;
    crmsg->reserved2 = 0;
    crmsg->timestamp = p2p_crmsg->timestamp;
    crmsg->target = p2p_crmsg->target;
    crmsg->author = p2p_crmsg->author;
    crmsg->content = p2p_crmsg->content;
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_CHAT_RECEIPT,
                                  &crmsg->purpose, &crmsg->signature,
                                  &target->public_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Invalid signature of the receipt\n");
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
#if DEBUG_CHAT_SERVICE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "The author of the original message is a local client."
                " Sending receipt to the client\n");
#endif
    GNUNET_SERVER_notification_context_unicast (nc, author->client,
                                                &crmsg->header, GNUNET_NO);
    GNUNET_free (crmsg);
  }
  return GNUNET_OK;
}


/**
 * Transmit a sync request to the peer.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_sync_request_to_peer (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *m = buf;
  size_t msg_size;

#if DEBUG_CHAT_SERVICE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting P2P sync request\n");
#endif
  msg_size = sizeof (struct GNUNET_MessageHeader);
  GNUNET_assert (size >= msg_size);
  GNUNET_assert (NULL != buf);
  m = buf;
  m->type = htons (GNUNET_MESSAGE_TYPE_CHAT_P2P_SYNC_REQUEST);
  m->size = htons (msg_size);
  return msg_size;
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 */
static void
peer_connect_handler (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_ATS_Information *atsi,
                      unsigned int atsi_count)
{
  struct ConnectedPeer *cp;
  struct GNUNET_CORE_TransmitHandle *th;

  if (0 == memcmp (peer, me, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Peer connected: %s\n",
              GNUNET_i2s (peer));
  th = GNUNET_CORE_notify_transmit_ready (core, GNUNET_YES, 1,
                                          MAX_TRANSMIT_DELAY, peer,
                                          sizeof (struct GNUNET_MessageHeader),
                                          &transmit_sync_request_to_peer, NULL);
  GNUNET_assert (NULL != th);
  cp = GNUNET_CONTAINER_multihashmap_get (connected_peers, &peer->hashPubKey);
  if (NULL != cp)
  {
    GNUNET_break (0);
    return;
  }
  cp = GNUNET_malloc (sizeof (struct ConnectedPeer));
  cp->pid = GNUNET_PEER_intern (peer);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (connected_peers,
                                                   &peer->hashPubKey, cp,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
}


/**
 * Iterator to free peer entries.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
clean_peer (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ConnectedPeer *cp;
  const struct GNUNET_PeerIdentity *peer =
      (const struct GNUNET_PeerIdentity *) key;

  cp = GNUNET_CONTAINER_multihashmap_get (connected_peers, &peer->hashPubKey);
  if (cp == NULL)
    return GNUNET_YES;
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (connected_peers,
                                                      &peer->hashPubKey, cp));
  GNUNET_PEER_change_rc (cp->pid, -1);
  GNUNET_free (cp);
  return GNUNET_YES;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure, not used
 * @param peer peer identity this notification is about
 */
static void
peer_disconnect_handler (void *cls, const struct GNUNET_PeerIdentity *peer)
{

  if (0 == memcmp (peer, me, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Peer disconnected: %s\n",
              GNUNET_i2s (peer));
  clean_peer (NULL, (const GNUNET_HashCode *) peer, NULL);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct AnonymousMessage *next_msg;
  struct ChatClient *next_client;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Cleaning up\n");
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  while (NULL != client_list_head)
  {
    next_client = client_list_head->next;
    GNUNET_free (client_list_head->room);
    GNUNET_free_non_null (client_list_head->member_info);
    GNUNET_free (client_list_head);
    client_list_head = next_client;
  }
  while (NULL != anonymous_list_head)
  {
    next_msg = anonymous_list_head->next;
    GNUNET_free (anonymous_list_head);
    anonymous_list_head = next_msg;
  }
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers, &clean_peer, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (connected_peers);
  connected_peers = NULL;
}


/**
 * To be called on core init/fail.
 *
 * @param cls closure, NULL
 * @param server handle to the server for this service
 * @param my_identity the public identity of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *my_identity)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Core initialized\n");
  me = my_identity;
}


/**
 * Process chat requests.
 *
 * @param cls closure, NULL
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_join_request, NULL,
     GNUNET_MESSAGE_TYPE_CHAT_JOIN_REQUEST, 0},
    {&handle_transmit_request, NULL,
     GNUNET_MESSAGE_TYPE_CHAT_TRANSMIT_REQUEST, 0},
    {&handle_acknowledge_request, NULL,
     GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_RECEIPT,
     sizeof (struct ConfirmationReceiptMessage)},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CORE_MessageHandler p2p_handlers[] = {
    {&handle_p2p_join_notification,
     GNUNET_MESSAGE_TYPE_CHAT_P2P_JOIN_NOTIFICATION, 0},
    {&handle_p2p_leave_notification,
     GNUNET_MESSAGE_TYPE_CHAT_P2P_LEAVE_NOTIFICATION,
     sizeof (struct P2PLeaveNotificationMessage)},
    {&handle_p2p_message_notification,
     GNUNET_MESSAGE_TYPE_CHAT_P2P_MESSAGE_NOTIFICATION, 0},
    {&handle_p2p_sync_request,
     GNUNET_MESSAGE_TYPE_CHAT_P2P_SYNC_REQUEST,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_p2p_confirmation_receipt,
     GNUNET_MESSAGE_TYPE_CHAT_P2P_CONFIRMATION_RECEIPT,
     sizeof (struct P2PConfirmationReceiptMessage)},
    {NULL, 0, 0}
  };

  GNUNET_log_setup ("gnunet-service-chat",
#if DEBUG_CHAT_SERVICE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  cfg = c;
  nc = GNUNET_SERVER_notification_context_create (server, 16);
  connected_peers =
      GNUNET_CONTAINER_multihashmap_create (EXPECTED_NEIGHBOUR_COUNT);
  GNUNET_SERVER_add_handlers (server, handlers);
  core =
      GNUNET_CORE_connect (cfg, QUEUE_SIZE, NULL, &core_init,
                           &peer_connect_handler, &peer_disconnect_handler,
                           NULL, GNUNET_NO, NULL, GNUNET_NO, p2p_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the chat service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "chat", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-chat.c */

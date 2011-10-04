/*
     This file is part of GNUnet.
     (C) 2008, 2011 Christian Grothoff (and other contributing authors)

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
 * @file chat/chat.c
 * @brief convenience API for sending and receiving chat messages
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Vitaly Minko
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "chat.h"

#define DEBUG_CHAT GNUNET_EXTRA_LOGGING
#define NICK_IDENTITY_PREFIX ".chat_identity_"


/**
 * Handle for a chat room.
 */
struct GNUNET_CHAT_Room
{
  struct GNUNET_CLIENT_Connection *client;

  const struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_CONTAINER_MetaData *member_info;

  char *room_name;

  struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

  struct MemberList *members;

  int is_joined;

  GNUNET_CHAT_JoinCallback join_callback;

  void *join_callback_cls;

  GNUNET_CHAT_MessageCallback message_callback;

  void *message_callback_cls;

  GNUNET_CHAT_MemberListCallback member_list_callback;

  void *member_list_callback_cls;

  GNUNET_CHAT_MessageConfirmation confirmation_callback;

  void *confirmation_cls;

  uint32_t sequence_number;

  uint32_t msg_options;

};

/**
 * Linked list of members in the chat room.
 */
struct MemberList
{
  struct MemberList *next;

  /**
   * Description of the member.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Member ID (pseudonym).
   */
  GNUNET_HashCode id;

};

/**
 * Context for transmitting a send-message request.
 */
struct GNUNET_CHAT_SendMessageContext
{
  /**
   * Handle for the chat room.
   */
  struct GNUNET_CHAT_Room *chat_room;

  /**
   * Message that we're sending.
   */
  char *message;

  /**
   * Options for the message.
   */
  enum GNUNET_CHAT_MsgOptions options;

  /**
   * Receiver of the message. NULL to send to everyone in the room.
   */
  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *receiver;

  /**
   * Sequence id of the message.
   */
  uint32_t sequence_number;

};

/**
 * Context for transmitting a confirmation receipt.
 */
struct GNUNET_CHAT_SendReceiptContext
{
  /**
   * Handle for the chat room.
   */
  struct GNUNET_CHAT_Room *chat_room;

  /**
   * The original message that we're going to acknowledge.
   */
  struct ReceiveNotificationMessage *received_msg;

};

/**
 * Ask client to send a join request.
 */
static int
rejoin_room (struct GNUNET_CHAT_Room *chat_room);


/**
 * Transmit a confirmation receipt to the chat service.
 *
 * @param cls closure, pointer to the 'struct GNUNET_CHAT_SendReceiptContext'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_acknowledge_request (void *cls, size_t size, void *buf)
{
  struct GNUNET_CHAT_SendReceiptContext *src = cls;
  struct ConfirmationReceiptMessage *receipt;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub_key;
  uint16_t msg_len;
  size_t msg_size;

  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not transmit confirmation receipt\n"));
    return 0;
  }
#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting confirmation receipt to the service\n");
#endif
  msg_size = sizeof (struct ConfirmationReceiptMessage);
  GNUNET_assert (size >= msg_size);
  receipt = buf;
  receipt->header.size = htons (msg_size);
  receipt->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_RECEIPT);
  receipt->reserved = htonl (0);
  receipt->sequence_number = src->received_msg->sequence_number;
  receipt->reserved2 = htonl (0);
  receipt->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  GNUNET_CRYPTO_rsa_key_get_public (src->chat_room->my_private_key, &pub_key);
  GNUNET_CRYPTO_hash (&pub_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &receipt->target);
  receipt->author = src->received_msg->sender;
  receipt->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_RECEIPT);
  receipt->purpose.size =
      htonl (msg_size - sizeof (struct GNUNET_MessageHeader) -
             sizeof (uint32_t) - sizeof (struct GNUNET_CRYPTO_RsaSignature));
  msg_len =
      ntohs (src->received_msg->header.size) -
      sizeof (struct ReceiveNotificationMessage);
  GNUNET_CRYPTO_hash (&src->received_msg[1], msg_len, &receipt->content);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (src->chat_room->my_private_key,
                                         &receipt->purpose,
                                         &receipt->signature));
  GNUNET_free (src->received_msg);
  GNUNET_free (src);
  return msg_size;
}


/**
 * Handles messages received from the service.  Calls the proper client
 * callback.
 */
static void
process_result (struct GNUNET_CHAT_Room *room,
                const struct GNUNET_MessageHeader *reply)
{
  struct LeaveNotificationMessage *leave_msg;
  struct JoinNotificationMessage *join_msg;
  struct ReceiveNotificationMessage *received_msg;
  struct ConfirmationReceiptMessage *receipt;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  GNUNET_HashCode id;
  const GNUNET_HashCode *sender;
  struct GNUNET_CONTAINER_MetaData *meta;
  struct GNUNET_CHAT_SendReceiptContext *src;
  struct MemberList *pos;
  struct MemberList *prev;
  struct GNUNET_CRYPTO_AesSessionKey key;
  char decrypted_msg[MAX_MESSAGE_LENGTH];
  uint16_t size;
  uint16_t meta_len;
  uint16_t msg_len;
  char *message_content;

  size = ntohs (reply->size);
  switch (ntohs (reply->type))
  {
  case GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION:
#if DEBUG_CHAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a join notification\n");
#endif
    if (size < sizeof (struct JoinNotificationMessage))
    {
      GNUNET_break (0);
      return;
    }
    join_msg = (struct JoinNotificationMessage *) reply;
    meta_len = size - sizeof (struct JoinNotificationMessage);
    meta =
        GNUNET_CONTAINER_meta_data_deserialize ((const char *) &join_msg[1],
                                                meta_len);
    if (NULL == meta)
    {
      GNUNET_break (0);
      return;
    }
    pos = GNUNET_malloc (sizeof (struct MemberList));
    pos->meta = meta;
    GNUNET_CRYPTO_hash (&join_msg->public_key,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &pos->id);
    GNUNET_PSEUDONYM_add (room->cfg, &pos->id, meta);
    pos->next = room->members;
    room->members = pos;
    if (GNUNET_NO == room->is_joined)
    {
      GNUNET_CRYPTO_rsa_key_get_public (room->my_private_key, &pkey);
      if (0 ==
          memcmp (&join_msg->public_key, &pkey,
                  sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
      {
        room->join_callback (room->join_callback_cls);
        room->is_joined = GNUNET_YES;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("The current user must be the the first one joined\n"));
        GNUNET_break (0);
        return;
      }
    }
    else
      room->member_list_callback (room->member_list_callback_cls, meta,
                                  &join_msg->public_key,
                                  ntohl (join_msg->msg_options));
    break;
  case GNUNET_MESSAGE_TYPE_CHAT_LEAVE_NOTIFICATION:
#if DEBUG_CHAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a leave notification\n");
#endif
    if (size < sizeof (struct LeaveNotificationMessage))
    {
      GNUNET_break (0);
      return;
    }
    leave_msg = (struct LeaveNotificationMessage *) reply;
    room->member_list_callback (room->member_list_callback_cls, NULL,
                                &leave_msg->user, GNUNET_CHAT_MSG_OPTION_NONE);
    GNUNET_CRYPTO_hash (&leave_msg->user,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &id);
    prev = NULL;
    pos = room->members;
    while ((NULL != pos) &&
           (0 != memcmp (&pos->id, &id, sizeof (GNUNET_HashCode))))
    {
      prev = pos;
      pos = pos->next;
    }
    GNUNET_assert (NULL != pos);
    if (NULL == prev)
      room->members = pos->next;
    else
      prev->next = pos->next;
    GNUNET_CONTAINER_meta_data_destroy (pos->meta);
    GNUNET_free (pos);
    break;
  case GNUNET_MESSAGE_TYPE_CHAT_MESSAGE_NOTIFICATION:
#if DEBUG_CHAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a message notification\n");
#endif
    if (size <= sizeof (struct ReceiveNotificationMessage))
    {
      GNUNET_break (0);
      return;
    }
    received_msg = (struct ReceiveNotificationMessage *) reply;
    if (0 != (ntohl (received_msg->msg_options) & GNUNET_CHAT_MSG_ACKNOWLEDGED))
    {
      src = GNUNET_malloc (sizeof (struct GNUNET_CHAT_SendReceiptContext));
      src->chat_room = room;
      src->received_msg = GNUNET_memdup (received_msg, size);
      GNUNET_CLIENT_notify_transmit_ready (room->client,
                                           sizeof (struct
                                                   ConfirmationReceiptMessage),
                                           GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                           GNUNET_YES,
                                           &transmit_acknowledge_request, src);
    }
    msg_len = size - sizeof (struct ReceiveNotificationMessage);
    if (0 != (ntohl (received_msg->msg_options) & GNUNET_CHAT_MSG_PRIVATE))
    {
      if (-1 ==
          GNUNET_CRYPTO_rsa_decrypt (room->my_private_key,
                                     &received_msg->encrypted_key, &key,
                                     sizeof (struct
                                             GNUNET_CRYPTO_AesSessionKey)))
      {
        GNUNET_break (0);
        return;
      }
      msg_len =
          GNUNET_CRYPTO_aes_decrypt (&received_msg[1], msg_len, &key,
                                     (const struct
                                      GNUNET_CRYPTO_AesInitializationVector *)
                                     INITVALUE, decrypted_msg);
      message_content = decrypted_msg;
    }
    else
    {
      message_content = GNUNET_malloc (msg_len + 1);
      memcpy (message_content, &received_msg[1], msg_len);
    }
    message_content[msg_len] = '\0';
    if (0 != (ntohl (received_msg->msg_options) & GNUNET_CHAT_MSG_ANONYMOUS))
    {
      sender = NULL;
      meta = NULL;
    }
    else
    {
      pos = room->members;
      while ((NULL != pos) &&
             (0 !=
              memcmp (&pos->id, &received_msg->sender,
                      sizeof (GNUNET_HashCode))))
        pos = pos->next;
      GNUNET_assert (NULL != pos);
      sender = &received_msg->sender;
      meta = pos->meta;
    }
    room->message_callback (room->message_callback_cls, room, sender, meta,
                            message_content,
                            GNUNET_TIME_absolute_ntoh (received_msg->timestamp),
                            ntohl (received_msg->msg_options));
    if (message_content != decrypted_msg)
      GNUNET_free (message_content);
    break;
  case GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_NOTIFICATION:
#if DEBUG_CHAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a confirmation receipt\n");
#endif
    if (size < sizeof (struct ConfirmationReceiptMessage))
    {
      GNUNET_break (0);
      return;
    }
    receipt = (struct ConfirmationReceiptMessage *) reply;
    if (NULL != room->confirmation_callback)
      room->confirmation_callback (room->confirmation_cls, room,
                                   ntohl (receipt->sequence_number),
                                   GNUNET_TIME_absolute_ntoh
                                   (receipt->timestamp), &receipt->target);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Unknown message type: '%u'\n"),
                ntohs (reply->type));
    GNUNET_break_op (0);
    break;
  }
}


/**
 * Listen for incoming messages on this chat room.  Also, support servers going
 * away/coming back (i.e. rejoin chat room to keep server state up to date).
 *
 * @param cls closure, pointer to the 'struct GNUNET_CHAT_Room'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
receive_results (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CHAT_Room *chat_room = cls;

#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got a message from the service\n");
#endif
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & GNUNET_SCHEDULER_get_reason ()))
    return;
  if (NULL == msg)
  {
    GNUNET_break (0);
    rejoin_room (chat_room);
    return;
  }
  process_result (chat_room, msg);
  if (NULL == chat_room->client)
    return;                     /* fatal error */
  /* continue receiving */
  GNUNET_CLIENT_receive (chat_room->client, &receive_results, chat_room,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Read existing private key from file or create a new one if it does not exist
 * yet.
 * Returns the private key on success, NULL on error.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *
init_private_key (const struct GNUNET_CONFIGURATION_Handle *cfg,
                  const char *nick_name)
{
  char *home;
  char *keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *privKey;

#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initializing private key\n");
#endif
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "chat", "HOME", &home))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Configuration option `%s' in section `%s' missing\n"),
                "HOME", "chat");
    return NULL;
  }
  GNUNET_DISK_directory_create (home);
  if (GNUNET_OK != GNUNET_DISK_directory_test (home))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to access chat home directory `%s'\n"), home);
    GNUNET_free (home);
    return NULL;
  }
  /* read or create private key */
  keyfile =
      GNUNET_malloc (strlen (home) + strlen (NICK_IDENTITY_PREFIX) +
                     strlen (nick_name) + 2);
  strcpy (keyfile, home);
  GNUNET_free (home);
  if (keyfile[strlen (keyfile) - 1] != DIR_SEPARATOR)
    strcat (keyfile, DIR_SEPARATOR_STR);
  strcat (keyfile, NICK_IDENTITY_PREFIX);
  strcat (keyfile, nick_name);
  privKey = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  if (NULL == privKey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to create/open key in file `%s'\n"), keyfile);
  }
  GNUNET_free (keyfile);
  return privKey;
}


/**
 * Transmit a join request to the chat service.
 *
 * @param cls closure, pointer to the 'struct GNUNET_CHAT_Room'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_join_request (void *cls, size_t size, void *buf)
{
  struct GNUNET_CHAT_Room *chat_room = cls;
  struct JoinRequestMessage *join_msg;
  char *room;
  char *meta;
  size_t room_len;
  ssize_t meta_len;
  size_t size_of_join;

  if (NULL == buf)
  {
#if DEBUG_CHAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Could not transmit join request, retrying...\n");
#endif
    rejoin_room (chat_room);
    return 0;
  }
#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting join request to the service\n");
#endif
  room_len = strlen (chat_room->room_name);
  meta_len =
      GNUNET_CONTAINER_meta_data_get_serialized_size (chat_room->member_info);
  size_of_join = sizeof (struct JoinRequestMessage) + meta_len + room_len;
  GNUNET_assert (size >= size_of_join);
  join_msg = buf;
  join_msg->header.size = htons (size);
  join_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_JOIN_REQUEST);
  join_msg->msg_options = htonl (chat_room->msg_options);
  join_msg->room_name_len = htons (room_len);
  join_msg->reserved = htons (0);
  join_msg->reserved2 = htonl (0);
  GNUNET_CRYPTO_rsa_key_get_public (chat_room->my_private_key,
                                    &join_msg->public_key);
  room = (char *) &join_msg[1];
  memcpy (room, chat_room->room_name, room_len);
  meta = &room[room_len];
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_meta_data_serialize (chat_room->member_info, &meta,
                                            meta_len,
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_FULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not serialize metadata\n"));
    return 0;
  }
  GNUNET_CLIENT_receive (chat_room->client, &receive_results, chat_room,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return size_of_join;
}


/**
 * Ask to send a join request.
 */
static int
rejoin_room (struct GNUNET_CHAT_Room *chat_room)
{
  size_t size_of_join;

  size_of_join =
      sizeof (struct JoinRequestMessage) +
      GNUNET_CONTAINER_meta_data_get_serialized_size (chat_room->member_info) +
      strlen (chat_room->room_name);
  if (NULL ==
      GNUNET_CLIENT_notify_transmit_ready (chat_room->client, size_of_join,
                                           GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                           GNUNET_YES, &transmit_join_request,
                                           chat_room))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Leave a chat room.
 */
void
GNUNET_CHAT_leave_room (struct GNUNET_CHAT_Room *chat_room)
{
  struct MemberList *pos;

#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Leaving the room '%s'\n",
              chat_room->room_name);
#endif
  GNUNET_CLIENT_disconnect (chat_room->client, GNUNET_NO);
  GNUNET_free (chat_room->room_name);
  GNUNET_CONTAINER_meta_data_destroy (chat_room->member_info);
  GNUNET_CRYPTO_rsa_key_free (chat_room->my_private_key);
  while (NULL != chat_room->members)
  {
    pos = chat_room->members;
    chat_room->members = pos->next;
    GNUNET_CONTAINER_meta_data_destroy (pos->meta);
    GNUNET_free (pos);
  }
  GNUNET_free (chat_room);
}


/**
 * Join a chat room.
 *
 * @param cfg configuration
 * @param nick_name nickname of the user joining (used to
 *                  determine which public key to use);
 *                  the nickname should probably also
 *                  be used in the member_info (as "EXTRACTOR_TITLE")
 * @param member_info information about the joining member
 * @param room_name name of the room
 * @param msg_options message options of the joining user
 * @param joinCallback function to call on successful join
 * @param join_cls closure for joinCallback
 * @param messageCallback which function to call if a message has
 *        been received?
 * @param message_cls argument to callback
 * @param memberCallback which function to call for join/leave notifications
 * @param member_cls argument to callback
 * @param confirmationCallback which function to call for confirmations (maybe NULL)
 * @param confirmation_cls argument to callback
 * @param me member ID (pseudonym)
 * @return NULL on error
 */
struct GNUNET_CHAT_Room *
GNUNET_CHAT_join_room (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *nick_name,
                       struct GNUNET_CONTAINER_MetaData *member_info,
                       const char *room_name,
                       enum GNUNET_CHAT_MsgOptions msg_options,
                       GNUNET_CHAT_JoinCallback joinCallback, void *join_cls,
                       GNUNET_CHAT_MessageCallback messageCallback,
                       void *message_cls,
                       GNUNET_CHAT_MemberListCallback memberCallback,
                       void *member_cls,
                       GNUNET_CHAT_MessageConfirmation confirmationCallback,
                       void *confirmation_cls, GNUNET_HashCode * me)
{
  struct GNUNET_CHAT_Room *chat_room;
  struct GNUNET_CRYPTO_RsaPrivateKey *priv_key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub_key;
  struct GNUNET_CLIENT_Connection *client;

#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Joining the room '%s'\n", room_name);
#endif
  priv_key = init_private_key (cfg, nick_name);
  if (NULL == priv_key)
    return NULL;
  GNUNET_CRYPTO_rsa_key_get_public (priv_key, &pub_key);
  GNUNET_CRYPTO_hash (&pub_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      me);
  GNUNET_PSEUDONYM_add (cfg, me, member_info);
  client = GNUNET_CLIENT_connect ("chat", cfg);
  if (NULL == client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to the chat service\n"));
    return NULL;
  }
  if (NULL == joinCallback)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Undefined mandatory parameter: joinCallback\n"));
    return NULL;
  }
  if (NULL == messageCallback)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Undefined mandatory parameter: messageCallback\n"));
    return NULL;
  }
  if (NULL == memberCallback)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Undefined mandatory parameter: memberCallback\n"));
    return NULL;
  }
  chat_room = GNUNET_malloc (sizeof (struct GNUNET_CHAT_Room));
  chat_room->msg_options = msg_options;
  chat_room->room_name = GNUNET_strdup (room_name);
  chat_room->member_info = GNUNET_CONTAINER_meta_data_duplicate (member_info);
  chat_room->my_private_key = priv_key;
  chat_room->is_joined = GNUNET_NO;
  chat_room->join_callback = joinCallback;
  chat_room->join_callback_cls = join_cls;
  chat_room->message_callback = messageCallback;
  chat_room->message_callback_cls = message_cls;
  chat_room->member_list_callback = memberCallback;
  chat_room->member_list_callback_cls = member_cls;
  chat_room->confirmation_callback = confirmationCallback;
  chat_room->confirmation_cls = confirmation_cls;
  chat_room->cfg = cfg;
  chat_room->client = client;
  chat_room->members = NULL;
  if (GNUNET_SYSERR == rejoin_room (chat_room))
  {
    GNUNET_CHAT_leave_room (chat_room);
    return NULL;
  }
  return chat_room;
}


/**
 * Transmit a send-message request to the chat service.
 *
 * @param cls closure, pointer to the 'struct GNUNET_CHAT_SendMessageContext'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_send_request (void *cls, size_t size, void *buf)
{
  struct GNUNET_CHAT_SendMessageContext *smc = cls;
  struct TransmitRequestMessage *msg_to_send;
  size_t msg_size;

  if (NULL == buf)
  {
#if DEBUG_CHAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Could not transmit a chat message\n");
#endif
    return 0;
  }
#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting a chat message to the service\n");
#endif
  msg_size = strlen (smc->message) + sizeof (struct TransmitRequestMessage);
  GNUNET_assert (size >= msg_size);
  msg_to_send = buf;
  msg_to_send->header.size = htons (msg_size);
  msg_to_send->header.type = htons (GNUNET_MESSAGE_TYPE_CHAT_TRANSMIT_REQUEST);
  msg_to_send->msg_options = htonl (smc->options);
  msg_to_send->sequence_number = htonl (smc->sequence_number);
  msg_to_send->timestamp =
      GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  msg_to_send->reserved = htonl (0);
  if (NULL == smc->receiver)
    memset (&msg_to_send->target, 0, sizeof (GNUNET_HashCode));
  else
    GNUNET_CRYPTO_hash (smc->receiver,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &msg_to_send->target);
  memcpy (&msg_to_send[1], smc->message, strlen (smc->message));
  /**
   * Client don't encode private messages since public keys of other members are
   * stored on the service side.
   */
  if (smc->options & GNUNET_CHAT_MSG_AUTHENTICATED)
  {
    msg_to_send->purpose.purpose =
        htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
    msg_to_send->purpose.size =
        htonl (msg_size - sizeof (struct GNUNET_MessageHeader) -
               sizeof (struct GNUNET_CRYPTO_RsaSignature));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_rsa_sign (smc->chat_room->my_private_key,
                                           &msg_to_send->purpose,
                                           &msg_to_send->signature));
  }
  GNUNET_free (smc->message);
  GNUNET_free (smc);
  return msg_size;
}


/**
 * Send a message.
 *
 * @param room handle for the chat room
 * @param message message to be sent
 * @param options options for the message
 * @param receiver use NULL to send to everyone in the room
 * @param sequence_number where to write the sequence id of the message
 */
void
GNUNET_CHAT_send_message (struct GNUNET_CHAT_Room *room, const char *message,
                          enum GNUNET_CHAT_MsgOptions options,
                          const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                          *receiver, uint32_t * sequence_number)
{
  size_t msg_size;
  struct GNUNET_CHAT_SendMessageContext *smc;

#if DEBUG_CHAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending a message\n");
#endif
  room->sequence_number++;
  if (NULL != sequence_number)
    *sequence_number = room->sequence_number;
  smc = GNUNET_malloc (sizeof (struct GNUNET_CHAT_SendMessageContext));
  smc->chat_room = room;
  smc->message = GNUNET_strdup (message);
  smc->options = options;
  smc->receiver = receiver;
  smc->sequence_number = room->sequence_number;
  msg_size = strlen (message) + sizeof (struct TransmitRequestMessage);
  GNUNET_CLIENT_notify_transmit_ready (room->client, msg_size,
                                       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                       GNUNET_YES, &transmit_send_request, smc);
}

/* end of chat.c */

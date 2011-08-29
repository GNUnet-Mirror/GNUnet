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
 * @file include/gnunet_chat_service.h
 * @brief API for chatting via GNUnet
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Vitaly Minko
 */

#ifndef GNUNET_CHAT_SERVICE_H
#define GNUNET_CHAT_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#define GNUNET_CHAT_VERSION 0x00000003
#define MAX_MESSAGE_LENGTH (32 * 1024)

/**
 * Options for messaging.  Compatible options can be OR'ed together.
 */
enum GNUNET_CHAT_MsgOptions
{
    /**
     * No special options.
     */
  GNUNET_CHAT_MSG_OPTION_NONE = 0,

    /**
     * Encrypt the message so that only the receiver can decrypt it.
     */
  GNUNET_CHAT_MSG_PRIVATE = 1,

    /**
     * Hide the identity of the sender.
     */
  GNUNET_CHAT_MSG_ANONYMOUS = 2,

    /**
     * Sign the content, authenticating the sender (using the provided private
     * key, which may represent a pseudonym).
     */
  GNUNET_CHAT_MSG_AUTHENTICATED = 4,

    /**
     * Require signed acknowledgment before completing delivery (and of course,
     * only acknowledge if delivery is guaranteed).
     */
  GNUNET_CHAT_MSG_ACKNOWLEDGED = 8,

    /**
     * Authenticate for the receiver, but ensure that receiver cannot prove
     * authenticity to third parties later. (not yet implemented)
     */
  GNUNET_CHAT_MSG_OFF_THE_RECORD = 16,

};

/**
 * Handle for a (joined) chat room.
 */
struct GNUNET_CHAT_Room;

/**
 * Callback used for notification that we have joined the room.
 *
 * @param cls closure
 * @return GNUNET_OK
 */
typedef int (*GNUNET_CHAT_JoinCallback) (void *cls);

/**
 * Callback used for notification about incoming messages.
 *
 * @param cls closure
 * @param room in which room was the message received?
 * @param sender what is the ID of the sender? (maybe NULL)
 * @param member_info information about the joining member
 * @param message the message text
 * @param timestamp when was the message sent?
 * @param options options for the message
 * @return GNUNET_OK to accept the message now, GNUNET_NO to
 *         accept (but user is away), GNUNET_SYSERR to signal denied delivery
 */
typedef int (*GNUNET_CHAT_MessageCallback) (void *cls,
                                            struct GNUNET_CHAT_Room * room,
                                            const GNUNET_HashCode * sender,
                                            const struct
                                            GNUNET_CONTAINER_MetaData *
                                            member_info, const char *message,
                                            struct GNUNET_TIME_Absolute
                                            timestamp,
                                            enum GNUNET_CHAT_MsgOptions
                                            options);

/**
 * Callback used for notification that another room member has joined or left.
 *
 * @param cls closure
 * @param member_info will be non-null if the member is joining, NULL if he is
 *        leaving
 * @param member_id hash of public key of the user (for unique identification)
 * @param options what types of messages is this member willing to receive?
 * @return GNUNET_OK
 */
typedef int (*GNUNET_CHAT_MemberListCallback) (void *cls,
                                               const struct
                                               GNUNET_CONTAINER_MetaData *
                                               member_info,
                                               const struct
                                               GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                                               * member_id,
                                               enum GNUNET_CHAT_MsgOptions
                                               options);

/**
 * Callback used for message delivery confirmations.
 *
 * @param cls closure
 * @param room in which room was the message received?
 * @param orig_seq_number sequence number of the original message
 * @param timestamp when was the message received?
 * @param receiver who is confirming the receipt?
 * @return GNUNET_OK to continue, GNUNET_SYSERR to refuse processing further
 *         confirmations from anyone for this message
 */
typedef int (*GNUNET_CHAT_MessageConfirmation) (void *cls,
                                                struct GNUNET_CHAT_Room * room,
                                                uint32_t orig_seq_number,
                                                struct GNUNET_TIME_Absolute
                                                timestamp,
                                                const GNUNET_HashCode *
                                                receiver);

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
 * @param joinCallback which function to call when we've joined the room
 * @param join_cls argument to callback
 * @param messageCallback which function to call if a message has
 *        been received?
 * @param message_cls argument to callback
 * @param memberCallback which function to call for join/leave notifications
 * @param member_cls argument to callback
 * @param confirmationCallback which function to call for confirmations
 *        (maybe NULL)
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
                       void *confirmation_cls, GNUNET_HashCode * me);

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
                          *receiver, uint32_t * sequence_number);


/**
 * Leave a chat room.
 */
void
GNUNET_CHAT_leave_room (struct GNUNET_CHAT_Room *chat_room);


#if 0
/* these are not yet implemented / supported */
/**
 * Callback function to iterate over rooms.
 *
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
typedef int (*GNUNET_CHAT_RoomIterator) (const char *room, const char *topic,
                                         void *cls);

/**
 * List all of the (publically visible) chat rooms.
 * @return number of rooms on success, GNUNET_SYSERR if iterator aborted
 */
int
GNUNET_CHAT_list_rooms (struct GNUNET_GE_Context *ectx,
                        struct GNUNET_GC_Configuration *cfg,
                        GNUNET_CHAT_RoomIterator it, void *cls);
#endif


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/* end of gnunet_chat_service.h */

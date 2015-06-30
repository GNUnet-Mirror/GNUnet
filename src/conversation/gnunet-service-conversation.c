/*
  This file is part of GNUnet.
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
 * @file conversation/gnunet-service-conversation.c
 * @brief conversation service implementation
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_cadet_service.h"
#include "gnunet_conversation_service.h"
#include "conversation.h"


/**
 * How long is our signature on a call valid?  Needs to be long enough for time zone
 * differences and network latency to not matter.  No strong need for it to be short,
 * but we simply like all signatures to eventually expire.
 */
#define RING_TIMEOUT GNUNET_TIME_UNIT_DAYS


/**
 * A line connects a local client with a cadet channel (or, if it is an
 * open line, is waiting for a cadet channel).
 */
struct Line;

/**
 * The possible connection status
 */
enum ChannelStatus
{
  /**
   * Our phone is ringing, waiting for the client to pick up.
   */
  CS_CALLEE_RINGING,

  /**
   * We are talking!
   */
  CS_CALLEE_CONNECTED,

  /**
   * We're in shutdown, sending hangup messages before cleaning up.
   */
  CS_CALLEE_SHUTDOWN,

  /**
   * We are waiting for the phone to be picked up.
   */
  CS_CALLER_CALLING,

  /**
   * We are talking!
   */
  CS_CALLER_CONNECTED,

  /**
   * We're in shutdown, sending hangup messages before cleaning up.
   */
  CS_CALLER_SHUTDOWN

};


/**
 * A `struct Channel` represents a cadet channel, which is a P2P
 * connection to another conversation service.  Multiple channels can
 * be attached the the same `struct Line`, which represents a local
 * client.  We keep them in a linked list.
 */
struct Channel
{

  /**
   * This is a DLL.
   */
  struct Channel *next;

  /**
   * This is a DLL.
   */
  struct Channel *prev;

  /**
   * Line associated with the channel.
   */
  struct Line *line;

  /**
   * Handle for the reliable channel (contol data)
   */
  struct GNUNET_CADET_Channel *channel_reliable;

  /**
   * Handle for unreliable channel (audio data)
   */
  struct GNUNET_CADET_Channel *channel_unreliable;

  /**
   * Transmit handle for pending audio messages
   */
  struct GNUNET_CADET_TransmitHandle *unreliable_mth;

  /**
   * Message queue for control messages
   */
  struct GNUNET_MQ_Handle *reliable_mq;

  /**
   * Target of the line, if we are the caller.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Temporary buffer for audio data.
   */
  void *audio_data;

  /**
   * Number of bytes in @e audio_data.
   */
  size_t audio_size;

  /**
   * Channel identifier.
   */
  uint32_t cid;

  /**
   * Remote line number.
   */
  uint32_t remote_line;

  /**
   * Current status of this line.
   */
  enum ChannelStatus status;

  /**
   * #GNUNET_YES if the channel was suspended by the other peer.
   */
  int8_t suspended_remote;

  /**
   * #GNUNET_YES if the channel was suspended by the local client.
   */
  int8_t suspended_local;

};


/**
 * A `struct Line` connects a local client with cadet channels.
 */
struct Line
{
  /**
   * Kept in a DLL.
   */
  struct Line *next;

  /**
   * Kept in a DLL.
   */
  struct Line *prev;

  /**
   * This is a DLL.
   */
  struct Channel *channel_head;

  /**
   * This is a DLL.
   */
  struct Channel *channel_tail;

  /**
   * Handle to the line client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Generator for channel IDs.
   */
  uint32_t cid_gen;

  /**
   * Our line number.
   */
  uint32_t local_line;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Notification context containing all connected clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Handle for cadet
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Head of DLL of active lines.
 */
static struct Line *lines_head;

/**
 * Tail of DLL of active lines.
 */
static struct Line *lines_tail;

/**
 * Counter for generating local line numbers.
 * FIXME: randomize generation in the future
 * to eliminate information leakage.
 */
static uint32_t local_line_cnt;


/**
 * Function to register a phone.
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_register_message (void *cls,
                                struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  const struct ClientPhoneRegisterMessage *msg;
  struct Line *line;

  msg = (const struct ClientPhoneRegisterMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL != line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  line = GNUNET_new (struct Line);
  line->client = client;
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_client_set_user_context (client, line);
  GNUNET_CONTAINER_DLL_insert (lines_head,
                               lines_tail,
                               line);
  line->local_line = ntohl (msg->line) & (~ (1 << 31));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to handle a pickup request message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_pickup_message (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct ClientPhonePickupMessage *msg;
  struct GNUNET_MQ_Envelope *e;
  struct CadetPhonePickupMessage *mppm;
  struct Line *line;
  struct Channel *ch;

  msg = (const struct ClientPhonePickupMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL == line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  for (ch = line->channel_head; NULL != ch; ch = ch->next)
    if (msg->cid == ch->cid)
      break;
  if (NULL == ch)
  {
    /* could have been destroyed asynchronously, ignore message */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Channel %u not found\n",
                msg->cid);
    GNUNET_SERVER_receive_done (client, GNUNET_YES);
    return;
  }
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    ch->status = CS_CALLEE_CONNECTED;
    break;
  case CS_CALLEE_CONNECTED:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  case CS_CALLEE_SHUTDOWN:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring client's PICKUP message, line is in SHUTDOWN\n");
    break;
  case CS_CALLER_CALLING:
  case CS_CALLER_CONNECTED:
  case CS_CALLER_SHUTDOWN:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_break (CS_CALLEE_CONNECTED == ch->status);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending PICK_UP message to cadet\n");
  e = GNUNET_MQ_msg (mppm,
                     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_PICK_UP);
  GNUNET_MQ_send (ch->reliable_mq, e);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Destroy a channel.
 *
 * @param ch channel to destroy.
 */
static void
destroy_line_cadet_channels (struct Channel *ch)
{
  struct Line *line = ch->line;
  struct GNUNET_CADET_Channel *t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying cadet channels\n");
  if (NULL != ch->reliable_mq)
  {
    GNUNET_MQ_destroy (ch->reliable_mq);
    ch->reliable_mq = NULL;
  }
  if (NULL != ch->unreliable_mth)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (ch->unreliable_mth);
    ch->unreliable_mth = NULL;
  }
  if (NULL != (t = ch->channel_unreliable))
  {
    ch->channel_unreliable = NULL;
    GNUNET_CADET_channel_destroy (t);
  }
  if (NULL != (t = ch->channel_reliable))
  {
    ch->channel_reliable = NULL;
    GNUNET_CADET_channel_destroy (t);
  }
  GNUNET_CONTAINER_DLL_remove (line->channel_head,
                               line->channel_tail,
                               ch);
  GNUNET_free_non_null (ch->audio_data);
  GNUNET_free (ch);
}


/**
 * We are done signalling shutdown to the other peer.  Close down
 * the channel.
 *
 * @param cls the `struct Channel` to reset/terminate
 */
static void
mq_done_finish_caller_shutdown (void *cls)
{
  struct Channel *ch = cls;

  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    GNUNET_break (0);
    break;
  case CS_CALLEE_CONNECTED:
    GNUNET_break (0);
    break;
  case CS_CALLEE_SHUTDOWN:
    destroy_line_cadet_channels (ch);
    break;
  case CS_CALLER_CALLING:
    GNUNET_break (0);
    break;
  case CS_CALLER_CONNECTED:
    GNUNET_break (0);
    break;
  case CS_CALLER_SHUTDOWN:
    destroy_line_cadet_channels (ch);
    break;
  }
}


/**
 * Function to handle a hangup request message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_hangup_message (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct ClientPhoneHangupMessage *msg;
  struct GNUNET_MQ_Envelope *e;
  struct CadetPhoneHangupMessage *mhum;
  struct Line *line;
  struct Channel *ch;

  msg = (const struct ClientPhoneHangupMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL == line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  for (ch = line->channel_head; NULL != ch; ch = ch->next)
    if (msg->cid == ch->cid)
      break;
  if (NULL == ch)
  {
    /* could have been destroyed asynchronously, ignore message */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Channel %u not found\n",
                msg->cid);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HANGUP for channel %u which is in state %d\n",
              msg->cid,
              ch->status);
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    ch->status = CS_CALLEE_SHUTDOWN;
    break;
  case CS_CALLEE_CONNECTED:
    ch->status = CS_CALLEE_SHUTDOWN;
    break;
  case CS_CALLEE_SHUTDOWN:
    /* maybe the other peer closed asynchronously... */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  case CS_CALLER_CALLING:
    ch->status = CS_CALLER_SHUTDOWN;
    break;
  case CS_CALLER_CONNECTED:
    ch->status = CS_CALLER_SHUTDOWN;
    break;
  case CS_CALLER_SHUTDOWN:
    /* maybe the other peer closed asynchronously... */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending HANG_UP message via cadet\n");
  e = GNUNET_MQ_msg (mhum,
                     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_HANG_UP);
  GNUNET_MQ_notify_sent (e,
                         &mq_done_finish_caller_shutdown,
                         ch);
  GNUNET_MQ_send (ch->reliable_mq, e);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to handle a suspend request message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_suspend_message (void *cls,
                               struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *message)
{
  const struct ClientPhoneSuspendMessage *msg;
  struct GNUNET_MQ_Envelope *e;
  struct CadetPhoneSuspendMessage *mhum;
  struct Line *line;
  struct Channel *ch;

  msg = (const struct ClientPhoneSuspendMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL == line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  for (ch = line->channel_head; NULL != ch; ch = ch->next)
    if (msg->cid == ch->cid)
      break;
  if (NULL == ch)
  {
    /* could have been destroyed asynchronously, ignore message */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Channel %u not found\n",
                msg->cid);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_YES == ch->suspended_local)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received SUSPEND for channel %u which is in state %d\n",
              msg->cid,
              ch->status);
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  case CS_CALLEE_CONNECTED:
    ch->suspended_local = GNUNET_YES;
    break;
  case CS_CALLEE_SHUTDOWN:
    /* maybe the other peer closed asynchronously... */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  case CS_CALLER_CALLING:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  case CS_CALLER_CONNECTED:
    ch->suspended_local = GNUNET_YES;
    break;
  case CS_CALLER_SHUTDOWN:
    /* maybe the other peer closed asynchronously... */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending SUSPEND message via cadet\n");
  e = GNUNET_MQ_msg (mhum,
                     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_SUSPEND);
  GNUNET_MQ_send (ch->reliable_mq, e);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to handle a resume request message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_resume_message (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct ClientPhoneResumeMessage *msg;
  struct GNUNET_MQ_Envelope *e;
  struct CadetPhoneResumeMessage *mhum;
  struct Line *line;
  struct Channel *ch;

  msg = (const struct ClientPhoneResumeMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL == line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  for (ch = line->channel_head; NULL != ch; ch = ch->next)
    if (msg->cid == ch->cid)
      break;
  if (NULL == ch)
  {
    /* could have been destroyed asynchronously, ignore message */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Channel %u not found\n",
                msg->cid);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_YES != ch->suspended_local)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received RESUME for channel %u which is in state %d\n",
              msg->cid,
              ch->status);
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  case CS_CALLEE_CONNECTED:
    ch->suspended_local = GNUNET_NO;
    break;
  case CS_CALLEE_SHUTDOWN:
    /* maybe the other peer closed asynchronously... */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  case CS_CALLER_CALLING:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  case CS_CALLER_CONNECTED:
    ch->suspended_local = GNUNET_NO;
    break;
  case CS_CALLER_SHUTDOWN:
    /* maybe the other peer closed asynchronously... */
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending RESUME message via cadet\n");
  e = GNUNET_MQ_msg (mhum,
                     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RESUME);
  GNUNET_MQ_send (ch->reliable_mq, e);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to handle call request from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_call_message (void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct ClientCallMessage *msg;
  struct Line *line;
  struct Channel *ch;
  struct GNUNET_MQ_Envelope *e;
  struct CadetPhoneRingMessage *ring;

  msg = (const struct ClientCallMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL != line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  line = GNUNET_new (struct Line);
  line->client = client;
  line->local_line = (local_line_cnt++) | (1 << 31);
  GNUNET_SERVER_client_set_user_context (client, line);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_CONTAINER_DLL_insert (lines_head,
                               lines_tail,
                               line);
  ch = GNUNET_new (struct Channel);
  ch->line = line;
  GNUNET_CONTAINER_DLL_insert (line->channel_head,
                               line->channel_tail,
                               ch);
  ch->target = msg->target;
  ch->remote_line = ntohl (msg->line);
  ch->status = CS_CALLER_CALLING;
  ch->channel_reliable = GNUNET_CADET_channel_create (cadet,
                                                     ch,
                                                     &msg->target,
                                                     GNUNET_APPLICATION_TYPE_CONVERSATION_CONTROL,
                                                     GNUNET_CADET_OPTION_RELIABLE);
  ch->reliable_mq = GNUNET_CADET_mq_create (ch->channel_reliable);
  e = GNUNET_MQ_msg (ring, GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RING);
  ring->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CONVERSATION_RING);
  ring->purpose.size = htonl (sizeof (struct GNUNET_PeerIdentity) * 2 +
                              sizeof (struct GNUNET_TIME_AbsoluteNBO) +
                              sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                              sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  GNUNET_CRYPTO_ecdsa_key_get_public (&msg->caller_id,
                                      &ring->caller_id);
  ring->remote_line = msg->line;
  ring->source_line = htonl (line->local_line);
  ring->target = msg->target;
  ring->source = my_identity;
  ring->expiration_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_relative_to_absolute (RING_TIMEOUT));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdsa_sign (&msg->caller_id,
                                           &ring->purpose,
                                           &ring->signature));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending RING message via cadet\n");
  GNUNET_MQ_send (ch->reliable_mq, e);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Transmit audio data via unreliable cadet channel.
 *
 * @param cls the `struct Channel` we are transmitting for
 * @param size number of bytes available in @a buf
 * @param buf where to copy the data
 * @return number of bytes copied to @a buf
 */
static size_t
transmit_line_audio (void *cls,
                     size_t size,
                     void *buf)
{
  struct Channel *ch = cls;
  struct CadetAudioMessage *mam = buf;

  ch->unreliable_mth = NULL;
  if ( (NULL == buf) ||
       (size < sizeof (struct CadetAudioMessage) + ch->audio_size) )
    {
    /* eh, other error handling? */
    return 0;
  }
  mam->header.size = htons (sizeof (struct CadetAudioMessage) + ch->audio_size);
  mam->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_AUDIO);
  mam->remote_line = htonl (ch->remote_line);
  mam->source_line = htonl (ch->line->local_line);
  memcpy (&mam[1], ch->audio_data, ch->audio_size);
  GNUNET_free (ch->audio_data);
  ch->audio_data = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u bytes of audio data from line %u to remote line %u via cadet\n",
              ch->audio_size, ch->line->local_line, ch->remote_line);
  return sizeof (struct CadetAudioMessage) + ch->audio_size;
}


/**
 * Function to handle audio data from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
 */
static void
handle_client_audio_message (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  const struct ClientAudioMessage *msg;
  struct Line *line;
  struct Channel *ch;
  size_t size;

  size = ntohs (message->size) - sizeof (struct ClientAudioMessage);
  msg = (const struct ClientAudioMessage *) message;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL == line)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  for (ch = line->channel_head; NULL != ch; ch = ch->next)
    if (msg->cid == ch->cid)
      break;
  if (NULL == ch)
  {
    /* could have been destroyed asynchronously, ignore message */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Channel %u not found\n",
                msg->cid);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
  case CS_CALLER_CALLING:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  case CS_CALLEE_CONNECTED:
  case CS_CALLER_CONNECTED:
    /* common case, handled below */
    break;
  case CS_CALLEE_SHUTDOWN:
  case CS_CALLER_SHUTDOWN:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "Cadet audio channel in shutdown; audio data dropped\n");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_YES == ch->suspended_local)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "This channel is suspended locally\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == ch->channel_unreliable)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO | GNUNET_ERROR_TYPE_BULK,
                _("Cadet audio channel not ready; audio data dropped\n"));
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (NULL != ch->unreliable_mth)
  {
    /* NOTE: we may want to not do this and instead combine the data */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bandwidth insufficient; dropping previous audio data segment with %u bytes\n",
                (unsigned int) ch->audio_size);
    GNUNET_CADET_notify_transmit_ready_cancel (ch->unreliable_mth);
    ch->unreliable_mth = NULL;
    GNUNET_free (ch->audio_data);
    ch->audio_data = NULL;
  }
  ch->audio_size = size;
  ch->audio_data = GNUNET_malloc (ch->audio_size);
  memcpy (ch->audio_data,
          &msg[1],
          size);
  ch->unreliable_mth = GNUNET_CADET_notify_transmit_ready (ch->channel_unreliable,
                                                          GNUNET_NO,
                                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                                          sizeof (struct CadetAudioMessage)
                                                          + ch->audio_size,
                                                          &transmit_line_audio,
                                                          ch);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * We are done signalling shutdown to the other peer.
 * Destroy the channel.
 *
 * @param cls the `struct GNUNET_CADET_channel` to destroy
 */
static void
mq_done_destroy_channel (void *cls)
{
  struct GNUNET_CADET_Channel *channel = cls;

  GNUNET_CADET_channel_destroy (channel);
}


/**
 * Function to handle a ring message incoming over cadet
 *
 * @param cls closure, NULL
 * @param channel the channel over which the message arrived
 * @param channel_ctx the channel context, can be NULL
 *                    or point to the `struct Channel`
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_cadet_ring_message (void *cls,
                          struct GNUNET_CADET_Channel *channel,
                          void **channel_ctx,
                          const struct GNUNET_MessageHeader *message)
{
  const struct CadetPhoneRingMessage *msg;
  struct Line *line;
  struct Channel *ch;
  struct GNUNET_MQ_Envelope *e;
  struct CadetPhoneHangupMessage *hang_up;
  struct ClientPhoneRingMessage cring;
  struct GNUNET_MQ_Handle *reliable_mq;

  msg = (const struct CadetPhoneRingMessage *) message;
  if ( (msg->purpose.size != htonl (sizeof (struct GNUNET_PeerIdentity) * 2 +
                                    sizeof (struct GNUNET_TIME_AbsoluteNBO) +
                                    sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                                    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey))) ||
       (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_CONVERSATION_RING,
                                  &msg->purpose,
                                  &msg->signature,
                                  &msg->caller_id)) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CADET_receive_done (channel); /* needed? */
  for (line = lines_head; NULL != line; line = line->next)
    if (line->local_line == ntohl (msg->remote_line))
      break;
  if (NULL == line)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("No available phone for incoming call on line %u, sending HANG_UP signal\n"),
                ntohl (msg->remote_line));
    e = GNUNET_MQ_msg (hang_up,
                       GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_HANG_UP);
    GNUNET_MQ_notify_sent (e,
                           &mq_done_destroy_channel,
                           channel);
    reliable_mq = GNUNET_CADET_mq_create (channel);
    GNUNET_MQ_send (reliable_mq, e);
    /* FIXME: do we need to clean up reliable_mq somehow/somewhere? */
    return GNUNET_OK;
  }
  ch = GNUNET_new (struct Channel);
  ch->line = line;
  GNUNET_CONTAINER_DLL_insert (line->channel_head,
                               line->channel_tail,
                               ch);
  ch->status = CS_CALLEE_RINGING;
  ch->remote_line = ntohl (msg->source_line);
  ch->channel_reliable = channel;
  ch->reliable_mq = GNUNET_CADET_mq_create (ch->channel_reliable);
  ch->cid = line->cid_gen++;
  ch->target = msg->source;
  *channel_ctx = ch;
  cring.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RING);
  cring.header.size = htons (sizeof (cring));
  cring.cid = ch->cid;
  cring.caller_id = msg->caller_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending RING message to client. CID %u:(%u, %u)\n",
              ch->cid, ch->remote_line, line->local_line);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              line->client,
                                              &cring.header,
                                              GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Function to handle a hangup message incoming over cadet
 *
 * @param cls closure, NULL
 * @param channel the channel over which the message arrived
 * @param channel_ctx the channel context, can be NULL
 *                    or point to the `struct Channel`
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_cadet_hangup_message (void *cls,
                            struct GNUNET_CADET_Channel *channel,
                            void **channel_ctx,
                            const struct GNUNET_MessageHeader *message)
{
  struct Channel *ch = *channel_ctx;
  struct Line *line;
  struct ClientPhoneHangupMessage hup;
  enum ChannelStatus status;

  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "HANGUP message received for non-existing line, dropping channel.\n");
    return GNUNET_SYSERR;
  }
  line = ch->line;
  *channel_ctx = NULL;
  hup.header.size = htons (sizeof (hup));
  hup.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP);
  hup.cid = ch->cid;
  status = ch->status;
  GNUNET_CADET_receive_done (channel);
  destroy_line_cadet_channels (ch);
  switch (status)
  {
  case CS_CALLEE_RINGING:
  case CS_CALLEE_CONNECTED:
    break;
  case CS_CALLEE_SHUTDOWN:
    return GNUNET_OK;
  case CS_CALLER_CALLING:
  case CS_CALLER_CONNECTED:
    break;
  case CS_CALLER_SHUTDOWN:
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending HANG UP message to client\n");
  GNUNET_SERVER_notification_context_unicast (nc,
                                              line->client,
                                              &hup.header,
                                              GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Function to handle a pickup message incoming over cadet
 *
 * @param cls closure, NULL
 * @param channel the channel over which the message arrived
 * @param channel_ctx the channel context, can be NULL
 *                    or point to the `struct Channel`
 * @param message the incoming message
 * @return #GNUNET_OK if message was OK,
 *         #GNUNET_SYSERR if message violated the protocol
 */
static int
handle_cadet_pickup_message (void *cls,
                            struct GNUNET_CADET_Channel *channel,
                            void **channel_ctx,
                            const struct GNUNET_MessageHeader *message)
{
  struct Channel *ch = *channel_ctx;
  struct Line *line;
  struct ClientPhonePickupMessage pick;

  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "PICKUP message received for non-existing channel, dropping channel.\n");
    return GNUNET_SYSERR;
  }
  line = ch->line;
  GNUNET_CADET_receive_done (channel);
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
  case CS_CALLEE_CONNECTED:
    GNUNET_break_op (0);
    destroy_line_cadet_channels (ch);
    return GNUNET_SYSERR;
  case CS_CALLEE_SHUTDOWN:
    GNUNET_break_op (0);
    destroy_line_cadet_channels (ch);
    return GNUNET_SYSERR;
  case CS_CALLER_CALLING:
    ch->status = CS_CALLER_CONNECTED;
    break;
  case CS_CALLER_CONNECTED:
    GNUNET_break_op (0);
    return GNUNET_OK;
  case CS_CALLER_SHUTDOWN:
    GNUNET_break_op (0);
    mq_done_finish_caller_shutdown (ch);
    return GNUNET_SYSERR;
  }
  pick.header.size = htons (sizeof (pick));
  pick.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP);
  pick.cid = ch->cid;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending PICKED UP message to client\n");
  GNUNET_SERVER_notification_context_unicast (nc,
                                              line->client,
                                              &pick.header,
                                              GNUNET_NO);
  ch->channel_unreliable = GNUNET_CADET_channel_create (cadet,
                                                       ch,
                                                       &ch->target,
                                                       GNUNET_APPLICATION_TYPE_CONVERSATION_AUDIO,
                                                       GNUNET_CADET_OPTION_DEFAULT);
  if (NULL == ch->channel_unreliable)
  {
    GNUNET_break (0);
  }
  return GNUNET_OK;
}


/**
 * Function to handle a suspend message incoming over cadet
 *
 * @param cls closure, NULL
 * @param channel the channel over which the message arrived
 * @param channel_ctx the channel context, can be NULL
 *                    or point to the `struct Channel`
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_cadet_suspend_message (void *cls,
                             struct GNUNET_CADET_Channel *channel,
                             void **channel_ctx,
                             const struct GNUNET_MessageHeader *message)
{
  struct Channel *ch = *channel_ctx;
  struct Line *line;
  struct ClientPhoneSuspendMessage suspend;

  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "SUSPEND message received for non-existing line, dropping channel.\n");
    return GNUNET_SYSERR;
  }
  line = ch->line;
  suspend.header.size = htons (sizeof (suspend));
  suspend.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND);
  suspend.cid = ch->cid;
  GNUNET_CADET_receive_done (channel);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Suspending channel CID: %u(%u:%u)\n",
              ch->cid, ch->remote_line, line->local_line);
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    GNUNET_break_op (0);
    break;
  case CS_CALLEE_CONNECTED:
    ch->suspended_remote = GNUNET_YES;
    break;
  case CS_CALLEE_SHUTDOWN:
    return GNUNET_OK;
  case CS_CALLER_CALLING:
    GNUNET_break_op (0);
    break;
  case CS_CALLER_CONNECTED:
    ch->suspended_remote = GNUNET_YES;
    break;
  case CS_CALLER_SHUTDOWN:
    return GNUNET_OK;
  }
  GNUNET_SERVER_notification_context_unicast (nc,
                                              line->client,
                                              &suspend.header,
                                              GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Function to handle a resume message incoming over cadet
 *
 * @param cls closure, NULL
 * @param channel the channel over which the message arrived
 * @param channel_ctx the channel context, can be NULL
 *                    or point to the `struct Channel`
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_cadet_resume_message (void *cls,
                             struct GNUNET_CADET_Channel *channel,
                             void **channel_ctx,
                             const struct GNUNET_MessageHeader *message)
{
  struct Channel *ch = *channel_ctx;
  struct Line *line;
  struct ClientPhoneResumeMessage resume;

  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "RESUME message received for non-existing line, dropping channel.\n");
    return GNUNET_SYSERR;
  }
  line = ch->line;
  resume.header.size = htons (sizeof (resume));
  resume.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME);
  resume.cid = ch->cid;
  GNUNET_CADET_receive_done (channel);
  if (GNUNET_YES != ch->suspended_remote)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "RESUME message received for non-suspended channel, dropping channel.\n");
    return GNUNET_SYSERR;
  }
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
    GNUNET_break (0);
    break;
  case CS_CALLEE_CONNECTED:
    ch->suspended_remote = GNUNET_NO;
    break;
  case CS_CALLEE_SHUTDOWN:
    return GNUNET_OK;
  case CS_CALLER_CALLING:
    GNUNET_break (0);
    break;
  case CS_CALLER_CONNECTED:
    ch->suspended_remote = GNUNET_NO;
    break;
  case CS_CALLER_SHUTDOWN:
    return GNUNET_OK;
  }
  GNUNET_SERVER_notification_context_unicast (nc,
                                              line->client,
                                              &resume.header,
                                              GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Function to handle an audio message incoming over cadet
 *
 * @param cls closure, NULL
 * @param channel the channel over which the message arrived
 * @param channel_ctx the channel context, can be NULL
 *                    or point to the `struct Channel`
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_cadet_audio_message (void *cls,
                           struct GNUNET_CADET_Channel *channel,
                           void **channel_ctx,
                           const struct GNUNET_MessageHeader *message)
{
  const struct CadetAudioMessage *msg;
  struct Channel *ch = *channel_ctx;
  struct Line *line;
  struct GNUNET_PeerIdentity sender;
  size_t msize = ntohs (message->size) - sizeof (struct CadetAudioMessage);
  char buf[msize + sizeof (struct ClientAudioMessage)];
  struct ClientAudioMessage *cam;
  const union GNUNET_CADET_ChannelInfo *info;

  msg = (const struct CadetAudioMessage *) message;
  if (NULL == ch)
  {
    info = GNUNET_CADET_channel_get_info (channel,
                                         GNUNET_CADET_OPTION_PEER);
    if (NULL == info)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    sender = info->peer;
    for (line = lines_head; NULL != line; line = line->next)
      if (line->local_line == ntohl (msg->remote_line))
      {
        for (ch = line->channel_head; NULL != ch; ch = ch->next)
        {
          if ( (CS_CALLEE_CONNECTED == ch->status) &&
               (0 == memcmp (&ch->target,
                             &sender,
                             sizeof (struct GNUNET_PeerIdentity))) &&
               (NULL == ch->channel_unreliable) &&
               (ch->remote_line == ntohl (msg->source_line)) )
            break;
        }
        break;
      }
    if (NULL == line)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received %u bytes of AUDIO data for non-existing line %u, dropping.\n",
                  msize, ntohl (msg->remote_line));
      return GNUNET_SYSERR;
    }
    if (NULL == ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received %u bytes of AUDIO data for unknown sender.\n",
                  msize);
      return GNUNET_SYSERR;
    }
    if ((GNUNET_YES == ch->suspended_local) || (GNUNET_YES == ch->suspended_remote))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received %u bytes of AUDIO data on suspended channel CID %u:(%u:%u); dropping\n",
                  msize, ch->cid, ch->remote_line, line->local_line);
      GNUNET_CADET_receive_done (channel);
      return GNUNET_OK;
    }
    ch->channel_unreliable = channel;
    *channel_ctx = ch;
  }
  GNUNET_CADET_receive_done (channel);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding %u bytes of AUDIO data to client CID %u:(%u:%u)\n",
              msize, ch->cid, ch->remote_line, ch->line->local_line);
  cam = (struct ClientAudioMessage *) buf;
  cam->header.size = htons (sizeof (buf));
  cam->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO);
  cam->cid = ch->cid;
  memcpy (&cam[1], &msg[1], msize);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              ch->line->client,
                                              &cam->header,
                                              GNUNET_YES);
  return GNUNET_OK;
}


/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port port
 * @param options channel option flags
 * @return initial channel context for the channel;
 *         (can be NULL -- that's not an error)
 */
static void *
inbound_channel (void *cls,
                struct GNUNET_CADET_Channel *channel,
		const struct GNUNET_PeerIdentity *initiator,
                uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Received incoming Cadet channel on port %u\n"),
              (unsigned int) port);
  return NULL;
}


/**
 * Function called whenever an inbound channel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored;
 *                   may point to the `struct Channel`
 */
static void
inbound_end (void *cls,
             const struct GNUNET_CADET_Channel *channel,
	     void *channel_ctx)
{
  struct Channel *ch = channel_ctx;
  struct Line *line;
  struct ClientPhoneHangupMessage hup;

  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cadet channel destroyed, but channel is unknown to us\n");
    return;
  }
  line = ch->line;
  if (ch->channel_unreliable == channel)
  {
    if (NULL != ch->unreliable_mth)
    {
      GNUNET_CADET_notify_transmit_ready_cancel (ch->unreliable_mth);
      ch->unreliable_mth = NULL;
    }
    ch->channel_unreliable = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Unreliable channel destroyed\n");
    return;
  }
  if (ch->channel_reliable != channel)
  {
    /* recursive call, I'm the one destroying 'ch' right now */
    return;
  }
  ch->channel_reliable = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Cadet channel destroyed by Cadet in state %d\n",
              ch->status);
  hup.header.size = htons (sizeof (hup));
  hup.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP);
  hup.cid = ch->cid;
  switch (ch->status)
  {
  case CS_CALLEE_RINGING:
  case CS_CALLEE_CONNECTED:
    GNUNET_SERVER_notification_context_unicast (nc,
                                                line->client,
                                                &hup.header,
                                                GNUNET_NO);
    break;
  case CS_CALLEE_SHUTDOWN:
    break;
  case CS_CALLER_CALLING:
  case CS_CALLER_CONNECTED:
    GNUNET_SERVER_notification_context_unicast (nc,
                                                line->client,
                                                &hup.header,
                                                GNUNET_NO);
    break;
  case CS_CALLER_SHUTDOWN:
    break;
  }
  destroy_line_cadet_channels (ch);
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client *client)
{
  struct Line *line;

  if (NULL == client)
    return;
  line = GNUNET_SERVER_client_get_user_context (client, struct Line);
  if (NULL == line)
    return;
  GNUNET_SERVER_client_set_user_context (client, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client disconnected, closing line\n");
  GNUNET_CONTAINER_DLL_remove (lines_head,
                               lines_tail,
                               line);
  while (NULL != line->channel_head)
    destroy_line_cadet_channels (line->channel_head);
  GNUNET_free (line);
}


/**
 * Shutdown nicely
 *
 * @param cls closure, NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Line *line;
  struct Channel *ch;

  while (NULL != (line = lines_head))
  {
    while (NULL != (ch = line->channel_head))
      destroy_line_cadet_channels (ch);
    GNUNET_CONTAINER_DLL_remove (lines_head,
                                 lines_tail,
                                 line);
    GNUNET_SERVER_client_set_user_context (line->client, NULL);
    GNUNET_free (line);
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param server server handle
 * @param c configuration
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    {&handle_client_register_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_REGISTER,
     sizeof (struct ClientPhoneRegisterMessage)},
    {&handle_client_pickup_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP,
     sizeof (struct ClientPhonePickupMessage) },
    {&handle_client_suspend_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND,
     sizeof (struct ClientPhoneSuspendMessage) },
    {&handle_client_resume_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME,
     sizeof (struct ClientPhoneResumeMessage) },
    {&handle_client_hangup_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP,
     sizeof (struct ClientPhoneHangupMessage) },
    {&handle_client_call_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL,
     sizeof (struct ClientCallMessage) },
    {&handle_client_audio_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO,
     0},
    {NULL, NULL, 0, 0}
  };
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {&handle_cadet_ring_message,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RING,
     sizeof (struct CadetPhoneRingMessage)},
    {&handle_cadet_hangup_message,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_HANG_UP,
     sizeof (struct CadetPhoneHangupMessage)},
    {&handle_cadet_pickup_message,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_PICK_UP,
     sizeof (struct CadetPhonePickupMessage)},
    {&handle_cadet_suspend_message,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_SUSPEND,
     sizeof (struct CadetPhoneSuspendMessage)},
    {&handle_cadet_resume_message,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RESUME,
     sizeof (struct CadetPhoneResumeMessage)},
    {&handle_cadet_audio_message, GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_AUDIO,
     0},
    {NULL, 0, 0}
  };
  static uint32_t ports[] = {
    GNUNET_APPLICATION_TYPE_CONVERSATION_CONTROL,
    GNUNET_APPLICATION_TYPE_CONVERSATION_AUDIO,
    0
  };

  cfg = c;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_get_peer_identity (cfg,
                                                  &my_identity));
  cadet = GNUNET_CADET_connect (cfg,
			      NULL,
			      &inbound_channel,
			      &inbound_end,
                              cadet_handlers,
                              ports);

  if (NULL == cadet)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  nc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown,
				NULL);
}


/**
 * The main function for the conversation service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  return (GNUNET_OK ==
	  GNUNET_SERVICE_run (argc, argv,
                              "conversation",
                              GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-conversation.c */

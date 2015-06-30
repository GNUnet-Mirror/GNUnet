/*
  This file is part of GNUnet
  Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @file conversation/conversation_api.c
 * @brief phone and caller API to the conversation service
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_conversation_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gns_service.h"
#include "conversation.h"


/**
 * Possible states of a caller.
 */
enum CallerState
{
  /**
   * The phone is ringing (user knows about incoming call).
   */
  CS_RINGING,

  /**
   * The phone is in an active conversation.
   */
  CS_ACTIVE,

  /**
   * We suspended the conversation.
   */
  CS_CALLEE_SUSPENDED,

  /**
   * Caller suspended the conversation.
   */
  CS_CALLER_SUSPENDED,

  /**
   * Both sides suspended the conversation.
   */
  CS_BOTH_SUSPENDED
};



/**
 * A caller is the handle we have for an incoming call.
 */
struct GNUNET_CONVERSATION_Caller
{

  /**
   * We keep all callers in a DLL.
   */
  struct GNUNET_CONVERSATION_Caller *next;

  /**
   * We keep all callers in a DLL.
   */
  struct GNUNET_CONVERSATION_Caller *prev;

  /**
   * Our phone.
   */
  struct GNUNET_CONVERSATION_Phone *phone;

  /**
   * Function to call for phone events.
   */
  GNUNET_CONVERSATION_CallerEventHandler event_handler;

  /**
   * Closure for @e event_handler
   */
  void *event_handler_cls;

  /**
   * Speaker, or NULL if none is attached.
   */
  struct GNUNET_SPEAKER_Handle *speaker;

  /**
   * Microphone, or NULL if none is attached.
   */
  struct GNUNET_MICROPHONE_Handle *mic;

  /**
   * Identity of the person calling us.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey caller_id;

  /**
   * Internal handle to identify the caller with the service.
   */
  uint32_t cid;

  /**
   * State machine for the phone.
   */
  enum CallerState state;

};


/**
 * Possible states of a phone.
 */
enum PhoneState
{
  /**
   * We still need to register the phone.
   */
  PS_REGISTER = 0,

  /**
   * We are waiting for calls.
   */
  PS_READY

};


/**
 * A phone is a device that can ring to signal an incoming call and
 * that you can pick up to answer the call and hang up to terminate
 * the call.  You can also hang up a ringing phone immediately
 * (without picking it up) to stop it from ringing.  Phones have
 * caller ID.  You can ask the phone for its record and make that
 * record available (via GNS) to enable others to call you.
 * Multiple phones maybe connected to the same line (the line is
 * something rather internal to a phone and not obvious from it).
 * You can only have one conversation per phone at any time.
 */
struct GNUNET_CONVERSATION_Phone
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle to talk with CONVERSATION service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * We keep all callers in a DLL.
   */
  struct GNUNET_CONVERSATION_Caller *caller_head;

  /**
   * We keep all callers in a DLL.
   */
  struct GNUNET_CONVERSATION_Caller *caller_tail;

  /**
   * Function to call for phone events.
   */
  GNUNET_CONVERSATION_PhoneEventHandler event_handler;

  /**
   * Closure for @e event_handler
   */
  void *event_handler_cls;

  /**
   * Connection to NAMESTORE (for reverse lookup).
   */
  struct GNUNET_NAMESTORE_Handle *ns;

  /**
   * Handle for transmitting to the CONVERSATION service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * This phone's record.
   */
  struct GNUNET_CONVERSATION_PhoneRecord my_record;

  /**
   * My GNS zone.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey my_zone;

  /**
   * State machine for the phone.
   */
  enum PhoneState state;

};


/**
 * The phone got disconnected, reconnect to the service.
 *
 * @param phone phone to reconnect
 */
static void
reconnect_phone (struct GNUNET_CONVERSATION_Phone *phone);


/**
 * Process recorded audio data.
 *
 * @param cls closure with the `struct GNUNET_CONVERSATION_Caller`
 * @param data_size number of bytes in @a data
 * @param data audio data to play
 */
static void
transmit_phone_audio (void *cls,
                      size_t data_size,
                      const void *data)
{
  struct GNUNET_CONVERSATION_Caller *caller = cls;
  struct GNUNET_CONVERSATION_Phone *phone = caller->phone;
  struct GNUNET_MQ_Envelope *e;
  struct ClientAudioMessage *am;

  e = GNUNET_MQ_msg_extra (am,
                           data_size,
                           GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO);
  am->cid = caller->cid;
  memcpy (&am[1], data, data_size);
  GNUNET_MQ_send (phone->mq, e);
}


/**
 * We received a `struct ClientPhoneRingMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param msg the message
 */
static void
handle_phone_ring (void *cls,
                   const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  const struct ClientPhoneRingMessage *ring;
  struct GNUNET_CONVERSATION_Caller *caller;

  ring = (const struct ClientPhoneRingMessage *) msg;
  switch (phone->state)
  {
  case PS_REGISTER:
    GNUNET_assert (0);
    break;
  case PS_READY:
    caller = GNUNET_new (struct GNUNET_CONVERSATION_Caller);
    caller->phone = phone;
    GNUNET_CONTAINER_DLL_insert (phone->caller_head,
                                 phone->caller_tail,
                                 caller);
    caller->caller_id = ring->caller_id;
    caller->cid = ring->cid;
    caller->state = CS_RINGING;
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_PHONE_RING,
                          caller,
                          &caller->caller_id);
    break;
  }
}


/**
 * We received a `struct ClientPhoneHangupMessage`.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone *`
 * @param msg the message
 */
static void
handle_phone_hangup (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  const struct ClientPhoneHangupMessage *hang;
  struct GNUNET_CONVERSATION_Caller *caller;

  hang = (const struct ClientPhoneHangupMessage *) msg;
  for (caller = phone->caller_head; NULL != caller; caller = caller->next)
    if (hang->cid == caller->cid)
      break;
  if (NULL == caller)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received HANG_UP message for unknown caller ID %u\n",
                (unsigned int) hang->cid);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received HANG_UP message, terminating call with `%s'\n",
              GNUNET_GNSRECORD_pkey_to_zkey (&caller->caller_id));
  switch (caller->state)
  {
  case CS_RINGING:
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_PHONE_HUNG_UP,
                          caller,
                          &caller->caller_id);
    break;
  case CS_ACTIVE:
    caller->speaker->disable_speaker (caller->speaker->cls);
    caller->mic->disable_microphone (caller->mic->cls);
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_PHONE_HUNG_UP,
                          caller,
                          &caller->caller_id);
    break;
  case CS_CALLEE_SUSPENDED:
  case CS_CALLER_SUSPENDED:
  case CS_BOTH_SUSPENDED:
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_PHONE_HUNG_UP,
                          caller,
                          &caller->caller_id);
    break;
  }
  GNUNET_CONTAINER_DLL_remove (phone->caller_head,
                               phone->caller_tail,
                               caller);
  GNUNET_free (caller);
}


/**
 * We received a `struct ClientPhoneSuspendMessage`.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param msg the message
 */
static void
handle_phone_suspend (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  struct GNUNET_CONVERSATION_Caller *caller;
  const struct ClientPhoneSuspendMessage *suspend;

  suspend = (const struct ClientPhoneSuspendMessage *) msg;
  for (caller = phone->caller_head; NULL != caller; caller = caller->next)
    if (suspend->cid == caller->cid)
      break;
  if (NULL == caller)
    return;
  switch (caller->state)
  {
  case CS_RINGING:
    GNUNET_break_op (0);
    break;
  case CS_ACTIVE:
    caller->state = CS_CALLER_SUSPENDED;
    caller->speaker->disable_speaker (caller->speaker->cls);
    caller->mic->disable_microphone (caller->mic->cls);
    caller->event_handler (caller->event_handler_cls,
                           GNUNET_CONVERSATION_EC_CALLER_SUSPEND);
    break;
  case CS_CALLEE_SUSPENDED:
    caller->state = CS_BOTH_SUSPENDED;
    caller->event_handler (caller->event_handler_cls,
                           GNUNET_CONVERSATION_EC_CALLER_SUSPEND);
    break;
  case CS_CALLER_SUSPENDED:
  case CS_BOTH_SUSPENDED:
    GNUNET_break_op (0);
    break;
  }
}


/**
 * We received a `struct ClientPhoneResumeMessage`.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param msg the message
 */
static void
handle_phone_resume (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  struct GNUNET_CONVERSATION_Caller *caller;
  const struct ClientPhoneResumeMessage *resume;

  resume = (const struct ClientPhoneResumeMessage *) msg;
  for (caller = phone->caller_head; NULL != caller; caller = caller->next)
    if (resume->cid == caller->cid)
      break;
  if (NULL == caller)
    return;
  switch (caller->state)
  {
  case CS_RINGING:
    GNUNET_break_op (0);
    break;
  case CS_ACTIVE:
  case CS_CALLEE_SUSPENDED:
    GNUNET_break_op (0);
    break;
  case CS_CALLER_SUSPENDED:
    caller->state = CS_ACTIVE;
    caller->speaker->enable_speaker (caller->speaker->cls);
    caller->mic->enable_microphone (caller->mic->cls,
                                    &transmit_phone_audio,
                                    caller);
    caller->event_handler (caller->event_handler_cls,
                           GNUNET_CONVERSATION_EC_CALLER_RESUME);
    break;
  case CS_BOTH_SUSPENDED:
    caller->state = CS_CALLEE_SUSPENDED;
    caller->event_handler (caller->event_handler_cls,
                           GNUNET_CONVERSATION_EC_CALLER_RESUME);
    break;
  }
}


/**
 * We received a `struct ClientAudioMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param msg the message
 */
static void
handle_phone_audio_message (void *cls,
                            const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  const struct ClientAudioMessage *am;
  struct GNUNET_CONVERSATION_Caller *caller;

  am = (const struct ClientAudioMessage *) msg;
  for (caller = phone->caller_head; NULL != caller; caller = caller->next)
    if (am->cid == caller->cid)
      break;
  if (NULL == caller)
    return;
  switch (caller->state)
  {
  case CS_RINGING:
    GNUNET_break_op (0);
    break;
  case CS_ACTIVE:
    caller->speaker->play (caller->speaker->cls,
                           ntohs (msg->size) - sizeof (struct ClientAudioMessage),
                           &am[1]);
    break;
  case CS_CALLEE_SUSPENDED:
  case CS_CALLER_SUSPENDED:
  case CS_BOTH_SUSPENDED:
    break;
  }
}


/**
 * We encountered an error talking with the conversation service.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param error details about the error
 */
static void
phone_error_handler (void *cls,
                     enum GNUNET_MQ_Error error)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _("Connection to conversation service lost, trying to reconnect\n"));
  reconnect_phone (phone);
}


/**
 * Clean up all callers of the given phone.
 *
 * @param phone phone to clean up callers for
 */
static void
clean_up_callers (struct GNUNET_CONVERSATION_Phone *phone)
{
  struct GNUNET_CONVERSATION_Caller *caller;

  while (NULL != (caller = phone->caller_head))
  {
    /* make sure mic/speaker are disabled *before* callback */
    if (CS_ACTIVE == caller->state)
    {
      caller->speaker->disable_speaker (caller->speaker->cls);
      caller->mic->disable_microphone (caller->mic->cls);
      caller->state = CS_CALLER_SUSPENDED;
    }
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_PHONE_HUNG_UP,
                          caller,
                          &caller->caller_id);
    GNUNET_CONVERSATION_caller_hang_up (caller);
  }
}


/**
 * The phone got disconnected, reconnect to the service.
 *
 * @param phone phone to reconnect
 */
static void
reconnect_phone (struct GNUNET_CONVERSATION_Phone *phone)
{
  static struct GNUNET_MQ_MessageHandler handlers[] =
  {
    { &handle_phone_ring,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RING,
      sizeof (struct ClientPhoneRingMessage) },
    { &handle_phone_hangup,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP,
      sizeof (struct ClientPhoneHangupMessage) },
    { &handle_phone_suspend,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND,
      sizeof (struct ClientPhoneSuspendMessage) },
    { &handle_phone_resume,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME,
      sizeof (struct ClientPhoneResumeMessage) },
    { &handle_phone_audio_message,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO,
      0 },
    { NULL, 0, 0 }
  };
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneRegisterMessage *reg;

  clean_up_callers (phone);
  if (NULL != phone->mq)
  {
    GNUNET_MQ_destroy (phone->mq);
    phone->mq = NULL;
  }
  if (NULL != phone->client)
  {
    GNUNET_CLIENT_disconnect (phone->client);
    phone->client = NULL;
  }
  phone->state = PS_REGISTER;
  phone->client = GNUNET_CLIENT_connect ("conversation", phone->cfg);
  if (NULL == phone->client)
    return;
  phone->mq = GNUNET_MQ_queue_for_connection_client (phone->client,
                                                     handlers,
                                                     &phone_error_handler,
                                                     phone);
  e = GNUNET_MQ_msg (reg, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_REGISTER);
  reg->line = phone->my_record.line;
  GNUNET_MQ_send (phone->mq, e);
  phone->state = PS_READY;
}


/**
 * Create a new phone.
 *
 * @param cfg configuration for the phone; specifies the phone service and
 *        which line the phone is to be connected to
 * @param ego ego to use for name resolution (when determining caller ID)
 * @param event_handler how to notify the owner of the phone about events
 * @param event_handler_cls closure for @a event_handler
 * @return NULL on error (no valid line configured)
 */
struct GNUNET_CONVERSATION_Phone *
GNUNET_CONVERSATION_phone_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  const struct GNUNET_IDENTITY_Ego *ego,
                                  GNUNET_CONVERSATION_PhoneEventHandler event_handler,
				  void *event_handler_cls)
{
  struct GNUNET_CONVERSATION_Phone *phone;
  unsigned long long line;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "CONVERSATION",
                                             "LINE",
                                             &line))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "CONVERSATION",
                               "LINE");
    return NULL;
  }
  if (line >= (1 << 31))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "CONVERSATION",
                               "LINE",
                               _("number too large"));
    return NULL;
  }
  phone = GNUNET_new (struct GNUNET_CONVERSATION_Phone);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_get_peer_identity (cfg,
                                       &phone->my_record.peer))
  {
    GNUNET_break (0);
    GNUNET_free (phone);
    return NULL;
  }
  phone->cfg = cfg;
  phone->my_zone = *GNUNET_IDENTITY_ego_get_private_key (ego);
  phone->event_handler = event_handler;
  phone->event_handler_cls = event_handler_cls;
  phone->ns = GNUNET_NAMESTORE_connect (cfg);
  phone->my_record.line = htonl ((uint32_t) line);
  phone->my_record.version = htonl (0);
  reconnect_phone (phone);
  if ( (NULL == phone->client) ||
       (NULL == phone->ns) )
  {
    GNUNET_break (0);
    GNUNET_CONVERSATION_phone_destroy (phone);
    return NULL;
  }
  return phone;
}


/**
 * Fill in a namestore record with the contact information
 * for this phone.  Note that the filled in "data" value
 * is only valid until the phone is destroyed.
 *
 * @param phone phone to create a record for
 * @param rd namestore record to fill in
 */
void
GNUNET_CONVERSATION_phone_get_record (struct GNUNET_CONVERSATION_Phone *phone,
				      struct GNUNET_GNSRECORD_Data *rd)
{
  rd->data = &phone->my_record;
  rd->expiration_time = 0;
  rd->data_size = sizeof (struct GNUNET_CONVERSATION_PhoneRecord);
  rd->record_type = GNUNET_GNSRECORD_TYPE_PHONE;
  rd->flags = GNUNET_GNSRECORD_RF_NONE;
}


/**
 * Picks up a (ringing) phone.  This will connect the speaker
 * to the microphone of the other party, and vice versa.
 *
 * @param caller handle that identifies which caller should be answered
 * @param event_handler how to notify about events by the caller
 * @param event_handler_cls closure for @a event_handler
 * @param speaker speaker to use
 * @param mic microphone to use
 */
void
GNUNET_CONVERSATION_caller_pick_up (struct GNUNET_CONVERSATION_Caller *caller,
                                    GNUNET_CONVERSATION_CallerEventHandler event_handler,
                                    void *event_handler_cls,
                                    struct GNUNET_SPEAKER_Handle *speaker,
                                    struct GNUNET_MICROPHONE_Handle *mic)
{
  struct GNUNET_CONVERSATION_Phone *phone = caller->phone;
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhonePickupMessage *pick;

  GNUNET_assert (CS_RINGING == caller->state);
  caller->speaker = speaker;
  caller->mic = mic;
  e = GNUNET_MQ_msg (pick, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP);
  pick->cid = caller->cid;
  GNUNET_MQ_send (phone->mq, e);
  caller->state = CS_ACTIVE;
  caller->event_handler = event_handler;
  caller->event_handler_cls = event_handler_cls;
  caller->speaker->enable_speaker (caller->speaker->cls);
  caller->mic->enable_microphone (caller->mic->cls,
                                  &transmit_phone_audio,
                                  caller);
}


/**
 * Hang up up a (possibly ringing) phone.  This will notify the other
 * party that we are no longer interested in talking with them.
 *
 * @param caller conversation to hang up on
 */
void
GNUNET_CONVERSATION_caller_hang_up (struct GNUNET_CONVERSATION_Caller *caller)
{
  struct GNUNET_CONVERSATION_Phone *phone = caller->phone;
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneHangupMessage *hang;

  switch (caller->state)
  {
  case CS_ACTIVE:
    caller->speaker->disable_speaker (caller->speaker->cls);
    caller->mic->disable_microphone (caller->mic->cls);
    break;
  default:
    break;
  }
  GNUNET_CONTAINER_DLL_remove (phone->caller_head,
                               phone->caller_tail,
                               caller);
  e = GNUNET_MQ_msg (hang,
                     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP);
  hang->cid = caller->cid;
  GNUNET_MQ_send (phone->mq, e);
  GNUNET_free (caller);
}


/**
 * Destroys a phone.
 *
 * @param phone phone to destroy
 */
void
GNUNET_CONVERSATION_phone_destroy (struct GNUNET_CONVERSATION_Phone *phone)
{
  clean_up_callers (phone);
  if (NULL != phone->ns)
  {
    GNUNET_NAMESTORE_disconnect (phone->ns);
    phone->ns = NULL;
  }
  if (NULL != phone->mq)
  {
    GNUNET_MQ_destroy (phone->mq);
    phone->mq = NULL;
  }
  if (NULL != phone->client)
  {
    GNUNET_CLIENT_disconnect (phone->client);
    phone->client = NULL;
  }
  GNUNET_free (phone);
}


/**
 * Pause conversation of an active call.  This will disconnect the speaker
 * and the microphone.  The call can later be resumed with
 * #GNUNET_CONVERSATION_caller_resume.
 *
 * @param caller call to suspend
 */
void
GNUNET_CONVERSATION_caller_suspend (struct GNUNET_CONVERSATION_Caller *caller)
{
  struct GNUNET_CONVERSATION_Phone *phone = caller->phone;
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneSuspendMessage *suspend;

  GNUNET_assert ( (CS_ACTIVE == caller->state) ||
                  (CS_CALLER_SUSPENDED == caller->state) );
  if (CS_ACTIVE == caller->state)
  {
    caller->speaker->disable_speaker (caller->speaker->cls);
    caller->mic->disable_microphone (caller->mic->cls);
  }
  caller->speaker = NULL;
  caller->mic = NULL;
  e = GNUNET_MQ_msg (suspend, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND);
  suspend->cid = caller->cid;
  GNUNET_MQ_send (phone->mq, e);
  if (CS_ACTIVE == caller->state)
    caller->state = CS_CALLEE_SUSPENDED;
  else
    caller->state = CS_BOTH_SUSPENDED;
}


/**
 * Resume suspended conversation of a phone.
 *
 * @param caller call to resume
 * @param speaker speaker to use
 * @param mic microphone to use
 */
void
GNUNET_CONVERSATION_caller_resume (struct GNUNET_CONVERSATION_Caller *caller,
                                   struct GNUNET_SPEAKER_Handle *speaker,
                                   struct GNUNET_MICROPHONE_Handle *mic)
{
  struct GNUNET_CONVERSATION_Phone *phone = caller->phone;
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneResumeMessage *resume;

  GNUNET_assert ( (CS_CALLEE_SUSPENDED == caller->state) ||
                  (CS_BOTH_SUSPENDED == caller->state) );
  caller->speaker = speaker;
  caller->mic = mic;
  e = GNUNET_MQ_msg (resume, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME);
  resume->cid = caller->cid;
  GNUNET_MQ_send (phone->mq, e);
  if (CS_CALLEE_SUSPENDED == caller->state)
  {
    caller->state = CS_ACTIVE;
    caller->speaker->enable_speaker (caller->speaker->cls);
    caller->mic->enable_microphone (caller->mic->cls,
                                    &transmit_phone_audio,
                                    caller);
  }
  else
  {
    caller->state = CS_CALLER_SUSPENDED;
  }
}

/* end of conversation_api.c */

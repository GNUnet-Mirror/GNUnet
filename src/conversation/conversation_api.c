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
 * @file conversation/conversation_api2.c
 * @brief API to the conversation service
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_conversation_service.h"
#include "gnunet_gns_service.h"
#include "conversation.h"


/**
 * Possible states of the phone.
 */
enum PhoneState
{
  /**
   * We still need to register the phone.
   */
  PS_REGISTER = 0,

  /**
   * We are waiting for a call.
   */
  PS_WAITING,

  /**
   * The phone is ringing.
   */
  PS_RINGING,

  /**
   * The phone is in an active conversation.
   */
  PS_ACTIVE
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
   * Function to call for phone events.
   */
  GNUNET_CONVERSATION_EventHandler event_handler;

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
   * Connection to NAMESTORE (for reverse lookup).
   */
  struct GNUNET_NAMESTORE_Handle *ns;

  /**
   * Active NAMESTORE lookup (or NULL).
   */
  struct GNUNET_NAMESTORE_QueueEntry *qe;

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
  struct GNUNET_CRYPTO_EccPrivateKey my_zone;

  /**
   * Identity of the person calling us (valid while in state #PS_RINGING).
   */
  struct GNUNET_CRYPTO_EccPublicSignKey caller_id;

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
 * We have resolved the caller ID using our name service.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param zone our zone used for resolution
 * @param label name of the caller
 * @param rd_count number of records we have in @a rd
 * @param rd records we have for the caller's label
 */
static void
handle_caller_name (void *cls,
                    const struct GNUNET_CRYPTO_EccPrivateKey *zone,
                    const char *label,
                    unsigned int rd_count,
                    const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  char *name;

  phone->qe = NULL;
  if (NULL == label)
    name = GNUNET_strdup (GNUNET_NAMESTORE_pkey_to_zkey (&phone->caller_id));
  else
    GNUNET_asprintf (&name, "%.gnu", label);
  phone->event_handler (phone->event_handler_cls,
                        GNUNET_CONVERSATION_EC_RING,
                        name);
  GNUNET_free (name);
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

  ring = (const struct ClientPhoneRingMessage *) msg;
  switch (phone->state)
  {
  case PS_REGISTER:
    GNUNET_assert (0);
    break;
  case PS_WAITING:
    phone->state = PS_RINGING;
    phone->caller_id = ring->caller_id;
    phone->qe = GNUNET_NAMESTORE_zone_to_name (phone->ns,
                                               &phone->my_zone,
                                               &ring->caller_id,
                                               &handle_caller_name,
                                               phone);
    break;
  case PS_RINGING:
    GNUNET_break (0);
    reconnect_phone (phone);
    break;
  case PS_ACTIVE:
    GNUNET_break (0);
    reconnect_phone (phone);
    break;
  }
}


/**
 * We received a `struct ClientPhoneHangupMessage`.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Phone`
 * @param msg the message
 */
static void
handle_phone_hangup (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  const struct ClientPhoneHangupMessage *hang;
  size_t len;
  const char *reason;

  hang = (const struct ClientPhoneHangupMessage *) msg;
  reason = (const char *) &hang[1];
  len = htons (hang->header.size) - sizeof (struct ClientPhoneHangupMessage);
  if ( (0 == len) ||
       ('\0' != reason[len-1]) )
  {
    GNUNET_break (0);
    reconnect_phone (phone);
    return;
  }
  switch (phone->state)
  {
  case PS_REGISTER:
    GNUNET_assert (0);
    break;
  case PS_WAITING:
    GNUNET_break (0);
    reconnect_phone (phone);
    break;
  case PS_RINGING:
    if (NULL != phone->qe)
    {
      GNUNET_NAMESTORE_cancel (phone->qe);
      phone->qe = NULL;
      phone->state = PS_WAITING;
      break;
    }
    phone->state = PS_WAITING;
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_TERMINATED,
                          reason);
    break;
  case PS_ACTIVE:
    GNUNET_break (NULL == phone->qe);
    phone->state = PS_WAITING;
    phone->event_handler (phone->event_handler_cls,
                          GNUNET_CONVERSATION_EC_TERMINATED,
                          reason);
    phone->speaker->disable_speaker (phone->speaker->cls);
    phone->mic->disable_microphone (phone->mic->cls);
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

  am = (const struct ClientAudioMessage *) msg;
  switch (phone->state)
  {
  case PS_REGISTER:
    GNUNET_assert (0);
    break;
  case PS_WAITING:
    GNUNET_break (0);
    reconnect_phone (phone);
    break;
  case PS_RINGING:
    GNUNET_break (0);
    reconnect_phone (phone);
    break;
  case PS_ACTIVE:
    phone->speaker->play (phone->speaker->cls,
                          ntohs (msg->size) - sizeof (struct ClientAudioMessage),
                          &am[1]);
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

  GNUNET_break (0);
  FPRINTF (stderr,
           _("Internal error %d\n"),
           error);
  reconnect_phone (phone);
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
      0 },
    { &handle_phone_audio_message,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO,
      0 },
    { NULL, 0, 0 }
  };
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneRegisterMessage *reg;

  if (PS_ACTIVE == phone->state)
  {
    phone->speaker->disable_speaker (phone->speaker->cls);
    phone->mic->disable_microphone (phone->mic->cls);
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
  phone->state = PS_WAITING;
}


/**
 * Create a new phone.
 *
 * @param cfg configuration for the phone; specifies the phone service and
 *        which line the phone is to be connected to
 * @param ego ego to use for name resolution (when determining caller ID)
 * @param event_handler how to notify the owner of the phone about events
 * @param event_handler_cls closure for @a event_handler
 */
struct GNUNET_CONVERSATION_Phone *
GNUNET_CONVERSATION_phone_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  const struct GNUNET_IDENTITY_Ego *ego,
                                  GNUNET_CONVERSATION_EventHandler event_handler,
				  void *event_handler_cls)
{
  struct GNUNET_CONVERSATION_Phone *phone;
  unsigned long long line;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "CONVERSATION",
                                             "LINE",
                                             &line))
    return NULL;
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
				      struct GNUNET_NAMESTORE_RecordData *rd)
{
  rd->data = &phone->my_record;
  rd->expiration_time = 0;
  rd->data_size = sizeof (struct GNUNET_CONVERSATION_PhoneRecord);
  rd->record_type = GNUNET_NAMESTORE_TYPE_PHONE;
  rd->flags = GNUNET_NAMESTORE_RF_NONE;
}


/**
 * Process recorded audio data.
 *
 * @param cls closure with the `struct GNUNET_CONVERSATION_Phone`
 * @param data_size number of bytes in @a data
 * @param data audio data to play
 */
static void
transmit_phone_audio (void *cls,
                      size_t data_size,
                      const void *data)
{
  struct GNUNET_CONVERSATION_Phone *phone = cls;
  struct GNUNET_MQ_Envelope *e;
  struct ClientAudioMessage *am;

  GNUNET_assert (PS_ACTIVE == phone->state);
  e = GNUNET_MQ_msg_extra (am,
                           data_size,
                           GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO);
  memcpy (&am[1], data, data_size);
  GNUNET_MQ_send (phone->mq, e);
}


/**
 * Picks up a (ringing) phone.  This will connect the speaker
 * to the microphone of the other party, and vice versa.
 *
 * @param phone phone to pick up
 * @param metadata meta data to give to the other user about the pick up event
 * @param speaker speaker to use
 * @param mic microphone to use
 */
void
GNUNET_CONVERSATION_phone_pick_up (struct GNUNET_CONVERSATION_Phone *phone,
                                   const char *metadata,
                                   struct GNUNET_SPEAKER_Handle *speaker,
                                   struct GNUNET_MICROPHONE_Handle *mic)
{
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhonePickupMessage *pick;
  size_t slen;

  GNUNET_assert (PS_RINGING == phone->state);
  phone->speaker = speaker;
  phone->mic = mic;
  slen = strlen (metadata) + 1;
  e = GNUNET_MQ_msg_extra (pick, slen, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP);
  memcpy (&pick[1], metadata, slen);
  GNUNET_MQ_send (phone->mq, e);
  phone->state = PS_ACTIVE;
  phone->speaker->enable_speaker (phone->speaker->cls);
  phone->mic->enable_microphone (phone->mic->cls,
                                 &transmit_phone_audio,
                                 phone);
}


/**
 * Hang up up a (possibly ringing) phone.  This will notify the other
 * party that we are no longer interested in talking with them.
 *
 * @param phone phone to pick up
 * @param reason text we give to the other party about why we terminated the conversation
 */
void
GNUNET_CONVERSATION_phone_hang_up (struct GNUNET_CONVERSATION_Phone *phone,
                                   const char *reason)
{
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneHangupMessage *hang;
  size_t slen;

  GNUNET_assert ( (PS_RINGING == phone->state) ||
                  (PS_ACTIVE == phone->state) );
  phone->speaker->disable_speaker (phone->speaker->cls);
  phone->mic->disable_microphone (phone->mic->cls);
  phone->speaker = NULL;
  phone->mic = NULL;
  slen = strlen (reason) + 1;
  e = GNUNET_MQ_msg_extra (hang, slen, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP);
  memcpy (&hang[1], reason, slen);
  GNUNET_MQ_send (phone->mq, e);
  phone->state = PS_WAITING;
}


/**
 * Destroys a phone.
 *
 * @param phone phone to destroy
 */
void
GNUNET_CONVERSATION_phone_destroy (struct GNUNET_CONVERSATION_Phone *phone)
{
  if (NULL != phone->speaker)
  {
    phone->speaker->disable_speaker (phone->speaker->cls);
    phone->speaker = NULL;
  }
  if (NULL != phone->mic)
  {
    phone->mic->disable_microphone (phone->mic->cls);
    phone->mic = NULL;
  }
  if (NULL != phone->qe)
  {
    GNUNET_NAMESTORE_cancel (phone->qe);
    phone->qe = NULL;
  }
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


/* ******************************* Call API *************************** */

/**
 * Possible states of the phone.
 */
enum CallState
{
  /**
   * We still need to lookup the callee.
   */
  CS_LOOKUP = 0,

  /**
   * The call is ringing.
   */
  CS_RINGING,

  /**
   * The call is in an active conversation.
   */
  CS_ACTIVE,

  /**
   * The call is in termination.
   */
  CS_SHUTDOWN
};


/**
 * Handle for an outgoing call.
 */
struct GNUNET_CONVERSATION_Call
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
   * Our caller identity.
   */
  struct GNUNET_IDENTITY_Ego *caller_id;

  /**
   * Target callee as a GNS address/name.
   */
  char *callee;

  /**
   * Our speaker.
   */
  struct GNUNET_SPEAKER_Handle *speaker;

  /**
   * Our microphone.
   */
  struct GNUNET_MICROPHONE_Handle *mic;

  /**
   * Function to call with events.
   */
  GNUNET_CONVERSATION_EventHandler event_handler;

  /**
   * Closure for @e event_handler
   */
  void *event_handler_cls;

  /**
   * Handle for transmitting to the CONVERSATION service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Connection to GNS (can be NULL).
   */
  struct GNUNET_GNS_Handle *gns;

  /**
   * Active GNS lookup (or NULL).
   */
  struct GNUNET_GNS_LookupRequest *gns_lookup;

  /**
   * Target phone record, only valid after the lookup is done.
   */
  struct GNUNET_CONVERSATION_PhoneRecord phone_record;

  /**
   * State machine for the call.
   */
  enum CallState state;

};


/**
 * The call got disconnected, reconnect to the service.
 *
 * @param call call to reconnect
 */
static void
reconnect_call (struct GNUNET_CONVERSATION_Call *call);


/**
 * We received a `struct ClientPhoneBusyMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_busy (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;

  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_RINGING:
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_BUSY);
    GNUNET_CONVERSATION_call_stop (call, NULL);
    break;
  case CS_ACTIVE:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call, NULL);
    break;
  }
}


/**
 * Process recorded audio data.
 *
 * @param cls closure with the `struct GNUNET_CONVERSATION_Call`
 * @param data_size number of bytes in @a data
 * @param data audio data to play
 */
static void
transmit_call_audio (void *cls,
                     size_t data_size,
                     const void *data)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  struct GNUNET_MQ_Envelope *e;
  struct ClientAudioMessage *am;

  GNUNET_assert (CS_ACTIVE == call->state);
  e = GNUNET_MQ_msg_extra (am,
                           data_size,
                           GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO);
  memcpy (&am[1], data, data_size);
  GNUNET_MQ_send (call->mq, e);
}


/**
 * We received a `struct ClientPhonePickedupMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_picked_up (void *cls,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  const struct ClientPhonePickedupMessage *am;
  const char *metadata;
  size_t size;

  am = (const struct ClientPhonePickedupMessage *) msg;
  size = ntohs (am->header.size) - sizeof (struct ClientPhonePickedupMessage);
  metadata = (const char *) &am[1];
  if ( (0 == size) ||
       ('\0' != metadata[size - 1]) )
    metadata = NULL;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_RINGING:
    call->state = CS_ACTIVE;
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_READY,
                         metadata);
    call->speaker->enable_speaker (call->speaker->cls);
    call->mic->enable_microphone (call->mic->cls,
                                  &transmit_call_audio,
                                  call);
    break;
  case CS_ACTIVE:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call, NULL);
    break;
  }
}


/**
 * We received a `struct ClientPhoneHangupMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_hangup (void *cls,
                    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  const struct ClientPhoneHangupMessage *am;
  const char *reason;
  size_t size;

  am = (const struct ClientPhoneHangupMessage *) msg;
  size = ntohs (am->header.size) - sizeof (struct ClientPhoneHangupMessage);
  reason = (const char *) &am[1];
  if ( (0 == size) ||
       ('\0' != reason[size - 1]) )
    reason = NULL;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_RINGING:
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_TERMINATED,
                         reason);
    GNUNET_CONVERSATION_call_stop (call, NULL);
    return;
  case CS_ACTIVE:
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_TERMINATED,
                         reason);
    GNUNET_CONVERSATION_call_stop (call, NULL);
    return;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call, NULL);
    break;
  }
}


/**
 * We received a `struct ClientAudioMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_audio_message (void *cls,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  const struct ClientAudioMessage *am;

  am = (const struct ClientAudioMessage *) msg;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_RINGING:
    GNUNET_break (0);
    reconnect_call (call);
    break;
  case CS_ACTIVE:
    call->speaker->play (call->speaker->cls,
                         ntohs (msg->size) - sizeof (struct ClientAudioMessage),
                         &am[1]);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call, NULL);
    break;

  }
}


/**
 * Iterator called on obtained result for a GNS lookup.
 *
 * @param cls closure with the `struct GNUNET_CONVERSATION_Call`
 * @param rd_count number of records in @a rd
 * @param rd the records in reply
 */
static void
handle_gns_response (void *cls,
                     uint32_t rd_count,
                     const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  uint32_t i;
  struct GNUNET_MQ_Envelope *e;
  struct ClientCallMessage *ccm;

  call->gns_lookup = NULL;
  for (i=0;i<rd_count;i++)
  {
    if (GNUNET_NAMESTORE_TYPE_PHONE == rd[i].record_type)
    {
      if (rd[i].data_size != sizeof (struct GNUNET_CONVERSATION_PhoneRecord))
      {
        GNUNET_break_op (0);
        continue;
      }
      memcpy (&call->phone_record,
              rd[i].data,
              rd[i].data_size);
      e = GNUNET_MQ_msg (ccm, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL);
      ccm->line = call->phone_record.line;
      ccm->target = call->phone_record.peer;
      ccm->caller_id = *GNUNET_IDENTITY_ego_get_private_key (call->caller_id);
      GNUNET_MQ_send (call->mq, e);
      call->state = CS_RINGING;
      call->event_handler (call->event_handler_cls,
                           GNUNET_CONVERSATION_EC_RINGING);
      return;
    }
  }
  /* not found */
  call->event_handler (call->event_handler_cls,
                       GNUNET_CONVERSATION_EC_GNS_FAIL);
  GNUNET_CONVERSATION_call_stop (call, NULL);
}


/**
 * We encountered an error talking with the conversation service.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param error details about the error
 */
static void
call_error_handler (void *cls,
                    enum GNUNET_MQ_Error error)
{
  struct GNUNET_CONVERSATION_Call *call = cls;

  GNUNET_break (0);
  FPRINTF (stderr,
           _("Internal error %d\n"),
           error);
  reconnect_call (call);
}


/**
 * The call got disconnected, reconnect to the service.
 *
 * @param call call to reconnect
 */
static void
reconnect_call (struct GNUNET_CONVERSATION_Call *call)
{
  static struct GNUNET_MQ_MessageHandler handlers[] =
  {
    { &handle_call_busy,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_BUSY,
      sizeof (struct ClientPhoneBusyMessage) },
    { &handle_call_picked_up,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP,
      0 },
    { &handle_call_hangup,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP,
      0 },
    { &handle_call_audio_message,
      GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO,
      0 },
    { NULL, 0, 0 }
  };
  struct GNUNET_CRYPTO_EccPublicSignKey my_zone;

  if (CS_ACTIVE == call->state)
  {
    call->speaker->disable_speaker (call->speaker->cls);
    call->mic->disable_microphone (call->mic->cls);
  }
  if (NULL != call->mq)
  {
    GNUNET_MQ_destroy (call->mq);
    call->mq = NULL;
  }
  if (NULL != call->client)
  {
    GNUNET_CLIENT_disconnect (call->client);
    call->client = NULL;
  }
  call->state = CS_SHUTDOWN;
  call->client = GNUNET_CLIENT_connect ("conversation", call->cfg);
  if (NULL == call->client)
    return;
  call->mq = GNUNET_MQ_queue_for_connection_client (call->client,
                                                    handlers,
                                                    &call_error_handler,
                                                    call);
  call->state = CS_LOOKUP;
  GNUNET_IDENTITY_ego_get_public_key (call->caller_id,
                                      &my_zone);
  call->gns_lookup = GNUNET_GNS_lookup (call->gns,
                                        call->callee,
                                        &my_zone,
                                        GNUNET_NAMESTORE_TYPE_PHONE,
                                        GNUNET_NO,
                                        NULL /* FIXME: add shortening support */,
                                        &handle_gns_response, call);
  GNUNET_assert (NULL != call->gns_lookup);
}


/**
 * Call the phone of another user.
 *
 * @param cfg configuration to use, specifies our phone service
 * @param caller_id identity of the caller
 * @param callee GNS name of the callee (used to locate the callee's record)
 * @param speaker speaker to use (will be used automatically immediately once the
 *        #GNUNET_CONVERSATION_EC_READY event is generated); we will NOT generate
 *        a ring tone on the speaker
 * @param mic microphone to use (will be used automatically immediately once the
 *        #GNUNET_CONVERSATION_EC_READY event is generated)
 * @param event_handler how to notify the owner of the phone about events
 * @param event_handler_cls closure for @a event_handler
 */
struct GNUNET_CONVERSATION_Call *
GNUNET_CONVERSATION_call_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				struct GNUNET_IDENTITY_Ego *caller_id,
				const char *callee,
				struct GNUNET_SPEAKER_Handle *speaker,
				struct GNUNET_MICROPHONE_Handle *mic,
				GNUNET_CONVERSATION_EventHandler event_handler,
				void *event_handler_cls)
{
  struct GNUNET_CONVERSATION_Call *call;

  call = GNUNET_new (struct GNUNET_CONVERSATION_Call);
  call->cfg = cfg;
  call->caller_id = caller_id;
  call->callee = GNUNET_strdup (callee);
  call->speaker = speaker;
  call->mic = mic;
  call->event_handler = event_handler;
  call->event_handler_cls = event_handler_cls;
  call->gns = GNUNET_GNS_connect (cfg);
  reconnect_call (call);

  if ( (NULL == call->client) ||
       (NULL == call->gns) )
  {
    GNUNET_CONVERSATION_call_stop (call, NULL);
    return NULL;
  }
  return call;
}


/**
 * Terminate a call.  The call may be ringing or ready at this time.
 *
 * @param call call to terminate
 * @param reason if the call was active (ringing or ready) this will be the
 *        reason given to the other user for why we hung up
 */
void
GNUNET_CONVERSATION_call_stop (struct GNUNET_CONVERSATION_Call *call,
			       const char *reason)
{
  if (NULL != reason)
  {
    // FIXME: transmit reason to service... (not implemented!)
    GNUNET_break (0);
    // return;
  }
  if (NULL != call->speaker)
  {
    if (CS_ACTIVE == call->state)
      call->speaker->disable_speaker (call->speaker->cls);
    call->speaker = NULL;
  }
  if (NULL != call->mic)
  {
    if (CS_ACTIVE == call->state)
      call->mic->disable_microphone (call->mic->cls);
    call->mic =NULL;
  }
  if (NULL != call->mq)
  {
    GNUNET_MQ_destroy (call->mq);
    call->mq = NULL;
  }
  if (NULL != call->client)
  {
    GNUNET_CLIENT_disconnect (call->client);
    call->client = NULL;
  }
  if (NULL != call->gns_lookup)
  {
    GNUNET_GNS_lookup_cancel (call->gns_lookup);
    call->gns_lookup = NULL;
  }
  if (NULL != call->gns)
  {
    GNUNET_GNS_disconnect (call->gns);
    call->gns = NULL;
  }
  GNUNET_free (call->callee);
  GNUNET_free (call);
}


/* end of conversation_api.c */

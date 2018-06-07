/*
  This file is part of GNUnet
  Copyright (C) 2013, 2016 GNUnet e.V.

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
 */

/**
 * @file conversation/conversation_api_call.c
 * @brief call API to the conversation service
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
  CS_SHUTDOWN,

  /**
   * The call was suspended by the caller.
   */
  CS_SUSPENDED_CALLER,

  /**
   * The call was suspended by the callee.
   */
  CS_SUSPENDED_CALLEE,

  /**
   * The call was suspended by both caller and callee.
   */
  CS_SUSPENDED_BOTH
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
  GNUNET_CONVERSATION_CallEventHandler event_handler;

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
  struct GNUNET_GNS_LookupWithTldRequest *gns_lookup;

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
fail_call (struct GNUNET_CONVERSATION_Call *call);


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
  GNUNET_memcpy (&am[1],
                 data,
                 data_size);
  GNUNET_MQ_send (call->mq,
                  e);
}


/**
 * We received a #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_suspend (void *cls,
                     const struct ClientPhoneSuspendMessage *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;

  (void) msg;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_RINGING:
    GNUNET_break_op (0);
    fail_call (call);
    break;
  case CS_SUSPENDED_CALLER:
    call->state = CS_SUSPENDED_BOTH;
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_CALL_SUSPENDED);
    break;
  case CS_SUSPENDED_CALLEE:
  case CS_SUSPENDED_BOTH:
    GNUNET_break_op (0);
    break;
  case CS_ACTIVE:
    call->state = CS_SUSPENDED_CALLEE;
    call->speaker->disable_speaker (call->speaker->cls);
    call->mic->disable_microphone (call->mic->cls);
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_CALL_SUSPENDED);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call);
    break;
  }
}


/**
 * We received a #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_resume (void *cls,
                     const struct ClientPhoneResumeMessage *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;

  (void) msg;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_RINGING:
    GNUNET_break_op (0);
    fail_call (call);
    break;
  case CS_SUSPENDED_CALLER:
    GNUNET_break_op (0);
    break;
  case CS_SUSPENDED_CALLEE:
    call->state = CS_ACTIVE;
    call->speaker->enable_speaker (call->speaker->cls);
    call->mic->enable_microphone (call->mic->cls,
                                  &transmit_call_audio,
                                  call);
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_CALL_RESUMED);
    break;
  case CS_SUSPENDED_BOTH:
    call->state = CS_SUSPENDED_CALLER;
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_CALL_RESUMED);
    break;
  case CS_ACTIVE:
    GNUNET_break_op (0);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call);
    break;
  }
}


/**
 * We received a #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_picked_up (void *cls,
                       const struct ClientPhonePickedupMessage *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;

  (void) msg;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_RINGING:
    call->state = CS_ACTIVE;
    call->speaker->enable_speaker (call->speaker->cls);
    call->mic->enable_microphone (call->mic->cls,
                                  &transmit_call_audio,
                                  call);
    call->event_handler (call->event_handler_cls,
                         GNUNET_CONVERSATION_EC_CALL_PICKED_UP);
    break;
  case CS_SUSPENDED_CALLER:
  case CS_SUSPENDED_CALLEE:
  case CS_SUSPENDED_BOTH:
  case CS_ACTIVE:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call);
    break;
  }
}


/**
 * We received a #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_HANG_UP.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_hangup (void *cls,
                    const struct ClientPhoneHangupMessage *msg)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  GNUNET_CONVERSATION_CallEventHandler eh;
  void *eh_cls;

  (void) msg;
  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_RINGING:
  case CS_SUSPENDED_CALLER:
  case CS_SUSPENDED_CALLEE:
  case CS_SUSPENDED_BOTH:
  case CS_ACTIVE:
    eh = call->event_handler;
    eh_cls = call->event_handler_cls;
    GNUNET_CONVERSATION_call_stop (call);
    eh (eh_cls,
        GNUNET_CONVERSATION_EC_CALL_HUNG_UP);
    return;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call);
    break;
  }
}


/**
 * We received a `struct ClientAudioMessage`, check it is well-formed.
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 * @return #GNUNET_OK (always well-formed)
 */
static int
check_call_audio (void *cls,
                  const struct ClientAudioMessage *am)
{
  (void) cls;
  (void) am;
  /* any payload is OK */
  return GNUNET_OK;
}


/**
 * We received a `struct ClientAudioMessage`
 *
 * @param cls the `struct GNUNET_CONVERSATION_Call`
 * @param msg the message
 */
static void
handle_call_audio (void *cls,
                   const struct ClientAudioMessage *am)
{
  struct GNUNET_CONVERSATION_Call *call = cls;

  switch (call->state)
  {
  case CS_LOOKUP:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_RINGING:
    GNUNET_break (0);
    fail_call (call);
    break;
  case CS_SUSPENDED_CALLER:
    /* can happen: we suspended, other peer did not yet
       learn about this. */
    break;
  case CS_SUSPENDED_CALLEE:
  case CS_SUSPENDED_BOTH:
    /* can (rarely) also happen: other peer suspended, but cadet might
       have had delayed data on the unreliable channel */
    break;
  case CS_ACTIVE:
    call->speaker->play (call->speaker->cls,
                         ntohs (am->header.size) - sizeof (struct ClientAudioMessage),
                         &am[1]);
    break;
  case CS_SHUTDOWN:
    GNUNET_CONVERSATION_call_stop (call);
    break;
  }
}


/**
 * Iterator called on obtained result for a GNS lookup.
 *
 * @param cls closure with the `struct GNUNET_CONVERSATION_Call`
 * @param was_gns #GNUNET_NO if name was not a GNS name
 * @param rd_count number of records in @a rd
 * @param rd the records in reply
 */
static void
handle_gns_response (void *cls,
		     int was_gns,
                     uint32_t rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_CONVERSATION_Call *call = cls;
  struct GNUNET_MQ_Envelope *e;
  struct ClientCallMessage *ccm;

  (void) was_gns;
  GNUNET_break (NULL != call->gns_lookup);
  GNUNET_break (CS_LOOKUP == call->state);
  call->gns_lookup = NULL;
  for (uint32_t i=0;i<rd_count;i++)
  {
    if (GNUNET_GNSRECORD_TYPE_PHONE == rd[i].record_type)
    {
      if (rd[i].data_size != sizeof (struct GNUNET_CONVERSATION_PhoneRecord))
      {
        GNUNET_break_op (0);
        continue;
      }
      GNUNET_memcpy (&call->phone_record,
                     rd[i].data,
                     rd[i].data_size);
      e = GNUNET_MQ_msg (ccm,
                         GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL);
      ccm->line_port = call->phone_record.line_port;
      ccm->target = call->phone_record.peer;
      ccm->caller_id = *GNUNET_IDENTITY_ego_get_private_key (call->caller_id);
      GNUNET_MQ_send (call->mq,
                      e);
      call->state = CS_RINGING;
      call->event_handler (call->event_handler_cls,
                           GNUNET_CONVERSATION_EC_CALL_RINGING);
      return;
    }
  }
  /* not found */
  call->event_handler (call->event_handler_cls,
                       GNUNET_CONVERSATION_EC_CALL_GNS_FAIL);
  GNUNET_CONVERSATION_call_stop (call);
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

  (void) error;
  if (CS_SHUTDOWN == call->state)
  {
    GNUNET_CONVERSATION_call_stop (call);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _("Connection to conversation service lost, trying to reconnect\n"));
  fail_call (call);
}


/**
 * The call got disconnected, destroy the handle.
 *
 * @param call call to reconnect
 */
static void
fail_call (struct GNUNET_CONVERSATION_Call *call)
{
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
  call->state = CS_SHUTDOWN;
  call->event_handler (call->event_handler_cls,
                       GNUNET_CONVERSATION_EC_CALL_ERROR);
  GNUNET_CONVERSATION_call_stop (call);
}


/**
 * Call the phone of another user.
 *
 * @param cfg configuration to use, specifies our phone service
 * @param caller_id identity of the caller
 * @param callee GNS name of the callee (used to locate the callee's record)
 * @param speaker speaker to use (will be used automatically immediately once the
 *        #GNUNET_CONVERSATION_EC_CALL_PICKED_UP event is generated); we will NOT generate
 *        a ring tone on the speaker
 * @param mic microphone to use (will be used automatically immediately once the
 *        #GNUNET_CONVERSATION_EC_CALL_PICKED_UP event is generated)
 * @param event_handler how to notify the owner of the phone about events
 * @param event_handler_cls closure for @a event_handler
 * @return handle for the call, NULL on hard errors
 */
struct GNUNET_CONVERSATION_Call *
GNUNET_CONVERSATION_call_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				struct GNUNET_IDENTITY_Ego *caller_id,
				const char *callee,
				struct GNUNET_SPEAKER_Handle *speaker,
				struct GNUNET_MICROPHONE_Handle *mic,
				GNUNET_CONVERSATION_CallEventHandler event_handler,
				void *event_handler_cls)
{
  struct GNUNET_CONVERSATION_Call *call
    = GNUNET_new (struct GNUNET_CONVERSATION_Call);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (call_suspend,
                             GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND,
                             struct ClientPhoneSuspendMessage,
                             call),
    GNUNET_MQ_hd_fixed_size (call_resume,
                             GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME,
                             struct ClientPhoneResumeMessage,
                             call),
    GNUNET_MQ_hd_fixed_size (call_picked_up,
                             GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP,
                             struct ClientPhonePickedupMessage,
                             call),
    GNUNET_MQ_hd_fixed_size (call_hangup,
                             GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP,
                             struct ClientPhoneHangupMessage,
                             call),
    GNUNET_MQ_hd_var_size (call_audio,
                           GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO,
                           struct ClientAudioMessage,
                           call),
    GNUNET_MQ_handler_end ()
  };

  call->mq = GNUNET_CLIENT_connect (cfg,
                                    "conversation",
                                    handlers,
                                    &call_error_handler,
                                    call);
  if (NULL == call->mq)
  {
    GNUNET_break (0);
    GNUNET_free (call);
    return NULL;
  }
  call->cfg = cfg;
  call->caller_id = caller_id;
  call->callee = GNUNET_strdup (callee);
  call->speaker = speaker;
  call->mic = mic;
  call->event_handler = event_handler;
  call->event_handler_cls = event_handler_cls;
  call->gns = GNUNET_GNS_connect (cfg);
  if (NULL == call->gns)
  {
    GNUNET_CONVERSATION_call_stop (call);
    return NULL;
  }
  call->state = CS_LOOKUP;
  call->gns_lookup = GNUNET_GNS_lookup_with_tld (call->gns,
						 call->callee,
						 GNUNET_GNSRECORD_TYPE_PHONE,
						 GNUNET_NO,
						 &handle_gns_response,
						 call);
  if (NULL == call->gns_lookup)
  {
    GNUNET_CONVERSATION_call_stop (call);
    return NULL;
  }
  return call;
}


/**
 * Terminate a call.  The call may be ringing or ready at this time.
 *
 * @param call call to terminate
 */
void
GNUNET_CONVERSATION_call_stop (struct GNUNET_CONVERSATION_Call *call)
{
  if ( (NULL != call->speaker) &&
       (CS_ACTIVE == call->state) )
    call->speaker->disable_speaker (call->speaker->cls);
  if ( (NULL != call->mic) &&
       (CS_ACTIVE == call->state) )
    call->mic->disable_microphone (call->mic->cls);
  if (CS_SHUTDOWN != call->state)
  {
    call->state = CS_SHUTDOWN;
  }
  if (NULL != call->mq)
  {
    GNUNET_MQ_destroy (call->mq);
    call->mq = NULL;
  }
  if (NULL != call->gns_lookup)
  {
    GNUNET_GNS_lookup_with_tld_cancel (call->gns_lookup);
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


/**
 * Pause a call.  Temporarily suspends the use of speaker and
 * microphone.
 *
 * @param call call to pause
 */
void
GNUNET_CONVERSATION_call_suspend (struct GNUNET_CONVERSATION_Call *call)
{
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneSuspendMessage *suspend;

  GNUNET_assert ( (CS_SUSPENDED_CALLEE == call->state) ||
                  (CS_ACTIVE == call->state) );
  if (CS_ACTIVE == call->state)
  {
    call->speaker->disable_speaker (call->speaker->cls);
    call->mic->disable_microphone (call->mic->cls);
  }
  call->speaker = NULL;
  call->mic = NULL;
  e = GNUNET_MQ_msg (suspend,
                     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND);
  GNUNET_MQ_send (call->mq,
                  e);
  if (CS_SUSPENDED_CALLER == call->state)
    call->state = CS_SUSPENDED_BOTH;
  else
    call->state = CS_SUSPENDED_CALLER;
}


/**
 * Resumes a call after #GNUNET_CONVERSATION_call_suspend.
 *
 * @param call call to resume
 * @param speaker speaker to use
 *        a ring tone on the speaker
 * @param mic microphone to use
 */
void
GNUNET_CONVERSATION_call_resume (struct GNUNET_CONVERSATION_Call *call,
                                 struct GNUNET_SPEAKER_Handle *speaker,
                                 struct GNUNET_MICROPHONE_Handle *mic)
{
  struct GNUNET_MQ_Envelope *e;
  struct ClientPhoneResumeMessage *resume;

  GNUNET_assert ( (CS_SUSPENDED_CALLER == call->state) ||
                  (CS_SUSPENDED_BOTH == call->state) );
  e = GNUNET_MQ_msg (resume, GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME);
  GNUNET_MQ_send (call->mq, e);
  call->speaker = speaker;
  call->mic = mic;
  if (CS_SUSPENDED_CALLER == call->state)
  {
    call->state = CS_ACTIVE;
    call->speaker->enable_speaker (call->speaker->cls);
    call->mic->enable_microphone (call->mic->cls,
                                  &transmit_call_audio,
                                  call);
  }
  else
  {
    call->state = CS_SUSPENDED_CALLEE;
  }
}


/* end of conversation_api_call.c */

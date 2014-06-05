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
 * @file include/gnunet_conversation_service.h
 * @brief API to the conversation service
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 *
 *
 * NOTE: This API is deliberately deceptively simple; the idea
 * is that advanced features (such as answering machines) will
 * be done with a separate service (an answering machine service)
 * with its own APIs; the speaker/microphone abstractions are
 * used to facilitate plugging in custom logic for implementing
 * such a service later by creating "software" versions of
 * speakers and microphones that record to disk or play a file.
 * Notifications about missed calls should similarly be done
 * using a separate service; CONVERSATION is supposed to be just
 * the "bare bones" voice service.
 *
 * As this is supposed to be a "secure" service, caller ID is of
 * course provided as part of the basic implementation, as only the
 * CONVERSATION service can know for sure who it is that we are
 * talking to.
 */
#ifndef GNUNET_CONVERSATION_SERVICE_H
#define GNUNET_CONVERSATION_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_speaker_lib.h"
#include "gnunet_microphone_lib.h"


/**
 * Version of the conversation API.
 */
#define GNUNET_CONVERSATION_VERSION 0x00000003

/**
 * Handle to identify a particular caller.  A caller is an entity that
 * initiate a call to a phone.  This struct identifies the caller to
 * the user operating the phone.  The entity that initiated the call
 * will have a `struct GNUNET_CONVERSATION_Call`.
 */
struct GNUNET_CONVERSATION_Caller;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * A phone record specifies which peer is hosting a given user and
 * may also specify the phone line that is used (typically zero).
 * The version is also right now always zero.
 */
struct GNUNET_CONVERSATION_PhoneRecord
{

  /**
   * Version of the phone record, for now always zero.  We may
   * use other versions for anonymously hosted phone lines in
   * the future.
   */
  uint32_t version GNUNET_PACKED;

  /**
   * Phone line to use at the peer.
   */
  uint32_t line GNUNET_PACKED;

  /**
   * Identity of the peer hosting the phone service.
   */
  struct GNUNET_PeerIdentity peer;

};

GNUNET_NETWORK_STRUCT_END

/**
 * Information about active callers to a phone.
 */
enum GNUNET_CONVERSATION_PhoneEventCode
{
  /**
   * We are the callee and the phone is ringing.
   * We should accept the call or hang up.
   */
  GNUNET_CONVERSATION_EC_PHONE_RING,

  /**
   * The conversation was terminated by the caller.
   * We must no longer use the caller's handle.
   */
  GNUNET_CONVERSATION_EC_PHONE_HUNG_UP

};


/**
 * Function called with an event emitted by a phone.
 *
 * @param cls closure
 * @param code type of the event
 * @param caller handle for the caller
 * @param caller_id name of the caller in GNS
 */
typedef void
(*GNUNET_CONVERSATION_PhoneEventHandler)(void *cls,
                                         enum GNUNET_CONVERSATION_PhoneEventCode code,
                                         struct GNUNET_CONVERSATION_Caller *caller,
                                         const char *caller_id);


/**
 * Information about the current status of a call.  Each call
 * progresses from ring over ready to terminated.  Steps may
 * be skipped.
 */
enum GNUNET_CONVERSATION_CallerEventCode
{

  /**
   * We are the callee and the caller suspended the call.  Note that
   * both sides can independently suspend and resume calls; a call is
   * only "working" of both sides are active.
   */
  GNUNET_CONVERSATION_EC_CALLER_SUSPEND,

  /**
   * We are the callee and the caller resumed the call.  Note that
   * both sides can independently suspend and resume calls; a call is
   * only "working" of both sides are active.
   */
  GNUNET_CONVERSATION_EC_CALLER_RESUME

};


/**
 * Function called with an event emitted by a caller.
 * These events are only generated after the phone is
 * picked up.
 *
 * @param cls closure
 * @param code type of the event for this caller
 */
typedef void
(*GNUNET_CONVERSATION_CallerEventHandler)(void *cls,
                                          enum GNUNET_CONVERSATION_CallerEventCode code);


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
struct GNUNET_CONVERSATION_Phone;


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
				  GNUNET_CONVERSATION_PhoneEventHandler event_handler,
				  void *event_handler_cls);


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
				      struct GNUNET_GNSRECORD_Data *rd);


/**
 * Picks up a (ringing) phone call.  This will connect the speaker
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
                                    struct GNUNET_MICROPHONE_Handle *mic);


/**
 * Pause conversation of an active call.  This will disconnect the speaker
 * and the microphone.  The call can later be resumed with
 * #GNUNET_CONVERSATION_caller_resume.
 *
 * @param caller call to suspend
 */
void
GNUNET_CONVERSATION_caller_suspend (struct GNUNET_CONVERSATION_Caller *caller);


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
                                   struct GNUNET_MICROPHONE_Handle *mic);


/**
 * Hang up up a (possibly ringing or paused) phone.  This will notify
 * the caller that we are no longer interested in talking with them.
 *
 * @param caller who should we hang up on
 */
void
GNUNET_CONVERSATION_caller_hang_up (struct GNUNET_CONVERSATION_Caller *caller);


/**
 * Destroys a phone.
 *
 * @param phone phone to destroy
 */
void
GNUNET_CONVERSATION_phone_destroy (struct GNUNET_CONVERSATION_Phone *phone);


/* *********************** CALL API ************************ */

/**
 * Handle for an outgoing call.
 */
struct GNUNET_CONVERSATION_Call;


/**
 * Information about the current status of a call.
 */
enum GNUNET_CONVERSATION_CallEventCode
{
  /**
   * We are the caller and are now ringing the other party (GNS lookup
   * succeeded).
   */
  GNUNET_CONVERSATION_EC_CALL_RINGING,

  /**
   * We are the caller and are now ready to talk as the callee picked up.
   */
  GNUNET_CONVERSATION_EC_CALL_PICKED_UP,

  /**
   * We are the caller and failed to locate a phone record in GNS.
   * After this invocation, the respective call handle will be
   * automatically destroyed and the client must no longer call
   * #GNUNET_CONVERSATION_call_stop or any other function on the
   * call object.
   */
  GNUNET_CONVERSATION_EC_CALL_GNS_FAIL,

  /**
   * We are the caller and the callee called
   * #GNUNET_CONVERSATION_caller_hang_up.  After this invocation, the
   * respective call handle will be automatically destroyed and the
   * client must no longer call #GNUNET_CONVERSATION_call_stop.
   */
  GNUNET_CONVERSATION_EC_CALL_HUNG_UP,

  /**
   * We are the caller and the callee suspended the call.  Note that
   * both sides can independently suspend and resume calls; a call is
   * only "working" of both sides are active.
   */
  GNUNET_CONVERSATION_EC_CALL_SUSPENDED,

  /**
   * We are the caller and the callee suspended the call.  Note that
   * both sides can independently suspend and resume calls; a call is
   * only "working" of both sides are active.
   */
  GNUNET_CONVERSATION_EC_CALL_RESUMED,

  /**
   * We had an error handing the call, and are now restarting it
   * (back to lookup).  This happens, for example, if the peer
   * is restarted during a call.
   */
  GNUNET_CONVERSATION_EC_CALL_ERROR

};


/**
 * Function called with an event emitted for a call.
 *
 * @param cls closure
 * @param code type of the event on the call
 */
typedef void
(*GNUNET_CONVERSATION_CallEventHandler)(void *cls,
                                        enum GNUNET_CONVERSATION_CallEventCode code);


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
 * @return handle for the call
 */
struct GNUNET_CONVERSATION_Call *
GNUNET_CONVERSATION_call_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				struct GNUNET_IDENTITY_Ego *caller_id,
				const char *callee,
				struct GNUNET_SPEAKER_Handle *speaker,
				struct GNUNET_MICROPHONE_Handle *mic,
				GNUNET_CONVERSATION_CallEventHandler event_handler,
				void *event_handler_cls);


/**
 * Pause a call.  Temporarily suspends the use of speaker and
 * microphone.
 *
 * @param call call to pause
 */
void
GNUNET_CONVERSATION_call_suspend (struct GNUNET_CONVERSATION_Call *call);


/**
 * Resumes a call after #GNUNET_CONVERSATION_call_suspend.
 *
 * @param call call to resume
 * @param speaker speaker to use
 * @param mic microphone to use
 */
void
GNUNET_CONVERSATION_call_resume (struct GNUNET_CONVERSATION_Call *call,
                                 struct GNUNET_SPEAKER_Handle *speaker,
                                 struct GNUNET_MICROPHONE_Handle *mic);


/**
 * Terminate a call.  The call may be ringing or ready at this time.
 *
 * @param call call to terminate
 */
void
GNUNET_CONVERSATION_call_stop (struct GNUNET_CONVERSATION_Call *call);


#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

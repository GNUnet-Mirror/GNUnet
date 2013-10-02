/*
      This file is part of GNUnet
      (C) 

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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

/**
 * Version of the conversation API.
 */
#define GNUNET_conversation_VERSION 0x00000001

enum GNUNET_CONVERSATION_RejectReason
{
  REJECT_REASON_GENERIC = 0,
  REJECT_REASON_NOT_AVAILABLE,
  REJECT_REASON_NO_CLIENT,
  REJECT_REASON_ACTIVE_CALL,
  REJECT_REASON_NOT_WANTED,
  REJECT_REASON_NO_ANSWER

};

enum GNUNET_CONVERSATION_NotificationType
{
  NotificationType_SERVICE_BLOCKED = 0,
  NotificationType_NO_PEER,
  NotificationType_NO_ANSWER,
  NotificationType_AVAILABLE_AGAIN,
  NotificationType_CALL_ACCEPTED,
  NotificationType_CALL_TERMINATED
};



/**
*
*/
struct GNUNET_CONVERSATION_MissedCall
{
  struct GNUNET_PeerIdentity peer;
  struct GNUNET_TIME_Absolute time;

};

struct GNUNET_CONVERSATION_MissedCallNotification
{
  int number;
  struct GNUNET_CONVERSATION_MissedCall *calls;
};

struct GNUNET_CONVERSATION_CallInformation;
struct GNUNET_CONVERSATION_Handle;

/**
 * Method called whenever a call is incoming
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param caller peer that calls you
 */
typedef void (GNUNET_CONVERSATION_CallHandler) (void *cls,
					struct
					GNUNET_CONVERSATION_Handle
					* handle,
					const struct
					GNUNET_PeerIdentity * caller);

/**
 * Method called whenever a call is rejected
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param peer peer that rejected your call
 */
typedef void (GNUNET_CONVERSATION_RejectHandler) (void *cls,
					  struct
					  GNUNET_CONVERSATION_Handle
					  * handle,
					  int
					  reason,
					  const struct
					  GNUNET_PeerIdentity * peer);

/**
 * Method called whenever a notification is there
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param type the type of the notification
 * @param peer peer that the notification is about
 */
typedef void (GNUNET_CONVERSATION_NotificationHandler) (void *cls,
						struct
						GNUNET_CONVERSATION_Handle
						* handle,
						int
						type,
						const struct
						GNUNET_PeerIdentity * peer);

/**
 * Method called whenever a notification for missed calls is there
 *
 * @param cls closure
 * @param handle to the conversation session
 * @param missed_calls a list of missed calls
 */
typedef void (GNUNET_CONVERSATION_MissedCallHandler) (void *cls,
					      struct
					      GNUNET_CONVERSATION_Handle
					      * handle,
					      struct
					      GNUNET_CONVERSATION_MissedCallNotification
					      * missed_calls);

/**
 * Connect to the VoIP service
 *
 * @param cfg configuration
 * @param cls NULL
 * @param call_handler the callback which is called when a call is incoming
 * @param reject_handler the callback which is called when a call is rejected
 * @param notification_handler the callback which is called when there is a notification
 * @param missed_call_handler the callback which is called when the service notifies the client aabout missed clients
 * @return handle to the connection to the conversation service
 */
struct GNUNET_CONVERSATION_Handle *GNUNET_CONVERSATION_connect (const struct
						GNUNET_CONFIGURATION_Handle
						*cfg, void *cls,
						GNUNET_CONVERSATION_CallHandler *
						call_handler,
						GNUNET_CONVERSATION_RejectHandler *
						reject_handler,
						GNUNET_CONVERSATION_NotificationHandler
						* notification_handler,
						GNUNET_CONVERSATION_MissedCallHandler
						* missed_call_handler);

/**
 * Disconnect from the VoIP service
 *
 * @param handle handle to the VoIP connection
 */
void GNUNET_CONVERSATION_disconnect (struct GNUNET_CONVERSATION_Handle *handle);

/**
 * Establish a call
 *
 * @param handle handle to the VoIP connection
 * @param callee the peer (PeerIdentity or GNS name) to call
 * @param doGnsLookup 0 = no GNS lookup or 1  = GNS lookup
 */
void
GNUNET_CONVERSATION_call (struct GNUNET_CONVERSATION_Handle *handle, const char *callee,
		  int doGnsLookup);

/**
 * Terminate the active call
 *
 * @param handle handle to the VoIP connection
 */
void GNUNET_CONVERSATION_hangup (struct GNUNET_CONVERSATION_Handle *handle);

/**
 * Accept an incoming call
 *
 * @param handle handle to the VoIP connection
 */
void GNUNET_CONVERSATION_accept (struct GNUNET_CONVERSATION_Handle *handle);

/**
 * Reject an incoming call
 *
 * @param handle handle to the VoIP connection
 */
void GNUNET_CONVERSATION_reject (struct GNUNET_CONVERSATION_Handle *handle);

#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

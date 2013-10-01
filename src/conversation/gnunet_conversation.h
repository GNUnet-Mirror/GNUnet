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
 * @file include/gnunet_conversation.h
 * @brief Header to the conversation service
 * @author Simon Dieterle
 * @author Andreas Fuchs
 */
#ifndef GNUNET_CONVERSATION_H
#define GNUNET_CONVERSATION_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif

#define MAX_TRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
* Reasons for rejecting an incoming call
*/
enum reject_reason
{
  REJECT_REASON_GENERIC = 0,
  REJECT_REASON_NOT_AVAILABLE,
  REJECT_REASON_NO_CLIENT,
  REJECT_REASON_ACTIVE_CALL,
  REJECT_REASON_NO_ANSWER
};

/*
* The possible connection status
*/
enum connection_status
{
  LISTEN,
  CALLER,
  CALLEE,
  CONNECTED
};

/**
 * VoipClient.
 */
struct VoipClient
{
  /**
   * Handle for a conversation client.
   */
  struct GNUNET_SERVER_Client *client;
};

/**
* The connection status of the service
*/
struct ConnectionStatus
{
	/**
	* The client which is in interaction
	*/
  struct GNUNET_SERVER_Client *client;

	/**
	* The PeerIdentity of the peer
	*/
  struct GNUNET_PeerIdentity peer;

	/**
	* The status (see enum)
	*/
  int status;
};

/**
* Iformation about a missed call
*/
struct MissedCall
{
	/**
	* The PeerIdentity of the peer
	*/
  struct GNUNET_PeerIdentity peer;

	/**
	* The time the call was
	*/
  struct GNUNET_TIME_Absolute time;

};

/**
* Transmit a mesh message
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the error message
 * @return number of bytes written to buf
 */
static size_t transmit_mesh_message (void *cls, size_t size, void *buf);

/**
 * Function called to send a peer no answer message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the peer no answer message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_no_answer_message (void *cls, size_t size, void *buf);

/**
 * Task to schedule a audio transmission.
 * 
 * @param cls Closure.
 * @param tc Task Context.
 */
static void
transmit_audio_task (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
* Start the audio helpers
*/
int start_helpers (void);

/**
* Stop the audio helpers
*/
void stop_helpers (void);



#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/*
		 This file is part of GNUnet.
		 (C) 

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
 * @file conversation/gnunet-service-conversation.c
 * @brief conversation service implementation
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * STRUCTURE:
 * - Variables
 * - AUXILIARY FUNCTIONS
 * - SENDING FUNCTIONS CL -> SERVER
 * - RECEIVE FUNCTIONS CL -> SERVER
 * - SENDING FUNCTIONS MESH
 * - RECEIVE FUNCTIONS MESH
 * - HELPER
 * - TUNNEL HANDLING
 * - CLIENT HANDLING
 */
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_constants.h>
#include <gnunet/gnunet_mesh_service.h>
#include "gnunet_conversation.h"
#include "gnunet_protocols_conversation.h"

/******************************************************** 
 * Ugly hack because of not working MESH API
*/
typedef uint32_t MESH_TunnelNumber;
struct GNUNET_MESH_Tunnel
{
  struct GNUNET_MESH_Tunnel *next;
  struct GNUNET_MESH_Tunnel *prev;
  struct GNUNET_MESH_Handle *mesh;
  MESH_TunnelNumber tid;
  uint32_t port;
  GNUNET_PEER_Id peer;
  void *ctx;
  unsigned int packet_size;
  int buffering;
  int reliable;
  int allow_send;
};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Head of the list of current clients.
 */
static struct GNUNET_CONTAINER_SList *clients;

/**
 * Notification context containing all connected clients.
 */
struct GNUNET_SERVER_NotificationContext *nc = NULL;

/**
* The connection status
*/
static struct ConnectionStatus connection;

/**
* Handle for the record helper
*/
static struct GNUNET_HELPER_Handle *record_helper;

/** Handle for the playback handler
*
*/
static struct GNUNET_HELPER_Handle *playback_helper;

/**
* Handle for mesh
*/
static struct GNUNET_MESH_Handle *mesh;

/**
* Transmit handle for audio messages
*/
static struct GNUNET_MESH_TransmitHandle *mth = NULL;

/**
* Handle for the reliable tunnel (contol data)
*/
static struct GNUNET_MESH_Tunnel *tunnel_reliable;

/**
* Handle for unreliable tunnel (audio data)
*/
static struct GNUNET_MESH_Tunnel *tunnel_unreliable;

/**
* List for missed calls
*/
struct GNUNET_CONTAINER_SList *missed_calls;

/**
* List for peers to notify that we are available again
*/
struct GNUNET_CONTAINER_SList *peers_to_notify;

/**
* Audio buffer (outgoing)
*/
struct GNUNET_CONTAINER_SList *audio_buffer;

/**
* The pointer to the task for sending audio
*/
GNUNET_SCHEDULER_TaskIdentifier audio_task;

/**
* The pointer to the task for checking timeouts an calling a peer
*/
GNUNET_SCHEDULER_TaskIdentifier timeout_task;

/**
* Sequencenumber for the pakets (for evaltuation purposes)
*/
int SequenceNumber = 0;

/**
* Timestamp for call statistics
*/
static struct GNUNET_TIME_Absolute start_time;

/**
 * Number of payload packes sent
 */
static int data_sent;
static int data_sent_size;

/**
 * Number of payload packets received
 */
static int data_received;
static int data_received_size;

/******************************************************************************/
/***********************     AUXILIARY FUNCTIONS      *************************/
/******************************************************************************/

/**
* Function which displays some call stats
*/
static void
show_end_data (void)
{
  static struct GNUNET_TIME_Absolute end_time;
  static struct GNUNET_TIME_Relative total_time;

  end_time = GNUNET_TIME_absolute_get ();
  total_time = GNUNET_TIME_absolute_get_difference (start_time, end_time);
  FPRINTF (stderr, "\nResults of send\n");
  FPRINTF (stderr, "Test time %llu ms\n",
	   (unsigned long long) total_time.rel_value);
  FPRINTF (stderr, "Test total packets: %d\n", data_sent);
  FPRINTF (stderr, "Test bandwidth: %f kb/s\n", data_sent_size * 1.0 / total_time.rel_value);	// 4bytes * ms
  FPRINTF (stderr, "Test throughput: %f packets/s\n\n", data_sent * 1000.0 / total_time.rel_value);	// packets * ms

  FPRINTF (stderr, "\nResults of recv\n");
  FPRINTF (stderr, "Test time %llu ms\n",
	   (unsigned long long) total_time.rel_value);
  FPRINTF (stderr, "Test total packets: %d\n", data_received);
  FPRINTF (stderr, "Test bandwidth: %f kb/s\n", data_received_size * 1.0 / total_time.rel_value);	// 4bytes * ms
  FPRINTF (stderr, "Test throughput: %f packets/s\n\n", data_received * 1000.0 / total_time.rel_value);	// packets * ms
}

/**
* Function which sets the connection state to LISTEN
*/
static void
status_to_listen (void)
{

  if (CONNECTED == connection.status)
    {
      show_end_data ();
    }

  if (timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (timeout_task);
      timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }

  stop_helpers ();

  connection.status = LISTEN;
  connection.client = NULL;

  data_sent = 0;
  data_sent_size = 0;
  data_received = 0;
  data_received_size = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Changed connection status to %s\n"),
	      "LISTEN");
}

/**
* Function to terminate the active call
*/
static void
terminate_call ()
{
  size_t msg_size;
  msg_size = sizeof (struct MeshSessionTerminateMessage);
  struct MeshSessionTerminateMessage *message_mesh_terminate =
    (struct MeshSessionTerminateMessage *) GNUNET_malloc (msg_size);

  if (NULL == message_mesh_terminate)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not create MeshSessionTerminateMessage\n"));
      status_to_listen ();

      return;
    }

  message_mesh_terminate->header.size = htons (msg_size);
  message_mesh_terminate->header.type =
    htons (GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_TERMINATE);

  if (NULL ==
      GNUNET_MESH_notify_transmit_ready (tunnel_reliable, 0,
					 MAX_TRANSMIT_DELAY, msg_size,
					 &transmit_mesh_message,
					 (void *) message_mesh_terminate))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not queue MeshSessionTerminateMessage\n"));
      GNUNET_free (message_mesh_terminate);
      status_to_listen ();
    }
}

/**
* Function to reject a call
*
* @param tunnel the tunnel where to reject the incoming call
* @param reason te reson why the call is rejected
*/
static void
reject_call (struct GNUNET_MESH_Tunnel *tunnel, int reason)
{
  size_t msg_size;
  msg_size = sizeof (struct MeshSessionRejectMessage);
  struct MeshSessionRejectMessage *message_mesh_reject =
    (struct MeshSessionRejectMessage *) GNUNET_malloc (msg_size);

  if (NULL == message_mesh_reject)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not create MeshSessionRejectMessage\n"));
      status_to_listen ();

      return;
    }

  message_mesh_reject->header.size = htons (msg_size);
  message_mesh_reject->header.type =
    htons (GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_REJECT);
  message_mesh_reject->reason = htons (reason);

  if (NULL ==
      GNUNET_MESH_notify_transmit_ready (tunnel_reliable, 0,
					 MAX_TRANSMIT_DELAY, msg_size,
					 &transmit_mesh_message,
					 (void *) message_mesh_reject))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not queue MeshSessionRejectMessage\n"));
      GNUNET_free (message_mesh_reject);
      status_to_listen ();
    }
}

/**
 * Check for timeout when calling a peer
 *
 * @param cls closure, NULL
 * @param tc the task context (can be NULL)
 */
static void
check_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Call timeout\n");

  if (NULL ==
      GNUNET_SERVER_notify_transmit_ready (connection.client,
					   sizeof (struct
						   ServerClientNoAnswerMessage),
					   MAX_TRANSMIT_DELAY,
					   &transmit_server_no_answer_message,
					   NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not queue ServerClientNoAnswerMessage\n"));
    }

  terminate_call ();
}

/******************************************************************************/
/***********************  SENDING FUNCTIONS CL -> SERVER    *******************/
/******************************************************************************/

/**
 * Function called to send a session initiate message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the initiate message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_initiate_message (void *cls, size_t size, void *buf)
{
  struct ServerClientSessionInitiateMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientSessionInitiateMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientSessionInitiateMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_INITIATE);
  memcpy (&(msg->peer), (struct GNUNET_PeerIdentity *) cls,
	  sizeof (struct GNUNET_PeerIdentity));

  return msg_size;
}

/**
 * Function called to send a session accept message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the accept message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_accept_message (void *cls, size_t size, void *buf)
{
  struct ServerClientSessionAcceptMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientSessionAcceptMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientSessionAcceptMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_ACCEPT);

  return msg_size;
}

/**
 * Function called to send a session reject message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the reject message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_reject_message (void *cls, size_t size, void *buf)
{
  struct ServerClientSessionRejectMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientSessionRejectMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientSessionRejectMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_REJECT);

  if (NULL == cls)
    {
      msg->reason = htons (REJECT_REASON_NOT_AVAILABLE);
    }
  else
    {
      msg->reason = ((struct MeshSessionRejectMessage *) cls)->reason;
    }

  return msg_size;
}

/**
 * Function called to send a session terminate message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the terminate message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_terminate_message (void *cls, size_t size, void *buf)
{
  struct ServerClientSessionTerminateMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientSessionTerminateMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientSessionTerminateMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SESSION_TERMINATE);

  return msg_size;
}

/**
 * Function called to send a missed call message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the missed call message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_missed_call_message (void *cls, size_t size, void *buf)
{
  struct ServerClientMissedCallMessage *msg;
  msg = (struct ServerClientMissedCallMessage *) cls;

  memcpy (buf, msg, size);
  GNUNET_free (msg);

  return size;
}

/**
 * Function called to send a service blocked message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the service blocked message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_service_blocked_message (void *cls, size_t size, void *buf)
{
  struct ServerClientServiceBlockedMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientServiceBlockedMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientServiceBlockedMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_SERVICE_BLOCKED);

  return msg_size;
}

/**
 * Function called to send a peer not connected message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the peer not connected message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_peer_not_connected_message (void *cls, size_t size, void *buf)
{
  struct ServerClientPeerNotConnectedMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientPeerNotConnectedMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientPeerNotConnectedMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_PEER_NOT_CONNECTED);

  return msg_size;
}

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
transmit_server_no_answer_message (void *cls, size_t size, void *buf)
{
  struct ServerClientNoAnswerMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientNoAnswerMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientNoAnswerMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_NO_ANSWER);

  return msg_size;
}

/**
 * Function called to send a error message to the client.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the error message
 * @return number of bytes written to buf
 */
static size_t
transmit_server_error_message (void *cls, size_t size, void *buf)
{
  struct ServerClientErrorMessage *msg;
  size_t msg_size;

  msg_size = sizeof (struct ServerClientErrorMessage);

  GNUNET_assert (size >= msg_size);

  msg = (struct ServerClientErrorMessage *) buf;
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_ERROR);

  return msg_size;
}

/******************************************************************************/
/***********************  RECEIVE FUNCTIONS CL -> SERVER   ********************/
/******************************************************************************/

/**
 * Function to handle a session initiate message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
*/
static void
handle_session_initiate_message (void *cls,
				 struct GNUNET_SERVER_Client *client,
				 const struct GNUNET_MessageHeader *message)
{
  static uint32_t port = 50002;
  size_t msg_size;
  struct ClientServerSessionInitiateMessage *msg =
    (struct ClientServerSessionInitiateMessage *) message;
  struct GNUNET_PeerIdentity *peer = &(msg->peer);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  if (NULL != connection.client)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("There is already a peer in interaction\n"));
      GNUNET_SERVER_notify_transmit_ready (client,
					   sizeof (struct
						   ServerClientServiceBlockedMessage),
					   MAX_TRANSMIT_DELAY,
					   &transmit_server_service_blocked_message,
					   NULL);

      return;
    }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Creating tunnel to: %s\n"),
	      GNUNET_i2s_full (peer));
  tunnel_reliable =
    GNUNET_MESH_tunnel_create (mesh, NULL, peer, port, GNUNET_NO, GNUNET_NO);
  if (NULL == tunnel_reliable)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not create reliable tunnel\n"));
      GNUNET_SERVER_notify_transmit_ready (client,
					   sizeof (struct
						   ServerClientPeerNotConnectedMessage),
					   MAX_TRANSMIT_DELAY,
					   &transmit_server_peer_not_connected_message,
					   NULL);

      return;
    }

  msg_size = sizeof (struct MeshSessionInitiateMessage);
  struct MeshSessionInitiateMessage *message_mesh_initiate =
    (struct MeshSessionInitiateMessage *) GNUNET_malloc (msg_size);

  if (NULL == message_mesh_initiate)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not create MeshSessionInitiateMessage\n"));
      GNUNET_MESH_tunnel_destroy (tunnel_reliable);
      tunnel_reliable = NULL;
      GNUNET_SERVER_notify_transmit_ready (client,
					   sizeof (struct
						   ServerClientErrorMessage),
					   MAX_TRANSMIT_DELAY,
					   &transmit_server_error_message,
					   NULL);

      return;
    }

  message_mesh_initiate->header.size = htons (msg_size);
  message_mesh_initiate->header.type =
    htons (GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_INITIATE);

  if (NULL ==
      GNUNET_MESH_notify_transmit_ready (tunnel_reliable, 0,
					 MAX_TRANSMIT_DELAY, msg_size,
					 &transmit_mesh_message,
					 (void *) message_mesh_initiate))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not queue MeshSessionInitiateMessage\n"));
      GNUNET_MESH_tunnel_destroy (tunnel_reliable);
      tunnel_reliable = NULL;
      GNUNET_free (message_mesh_initiate);
      GNUNET_SERVER_notify_transmit_ready (client,
					   sizeof (struct
						   ServerClientErrorMessage),
					   MAX_TRANSMIT_DELAY,
					   &transmit_server_error_message,
					   NULL);

      return;
    }

  connection.status = CALLER;
  connection.client = client;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Changed connection status to %d\n"),
	      connection.status);
  memcpy (&(connection.peer), peer, sizeof (struct GNUNET_PeerIdentity));

  return;
}

/**
 * Function to handle a session accept message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
*/
static void
handle_session_accept_message (void *cls, struct GNUNET_SERVER_Client *client,
			       const struct GNUNET_MessageHeader *message)
{
  size_t msg_size;

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  if (connection.status != CALLEE)
    {
      // TODO send illegal command
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _
		  ("handle_session_accept_message called when not allowed\n"));
      return;
    }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Accepting the call of: %s\n"),
	      GNUNET_i2s_full (&(connection.peer)));

  msg_size = sizeof (struct MeshSessionAcceptMessage);
  struct MeshSessionAcceptMessage *message_mesh_accept =
    (struct MeshSessionAcceptMessage *) GNUNET_malloc (msg_size);

  if (NULL == message_mesh_accept)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not create MeshSessionAcceptMessage\n"));
      return;
    }

  message_mesh_accept->header.size = htons (msg_size);
  message_mesh_accept->header.type =
    htons (GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_ACCEPT);

  if (NULL ==
      GNUNET_MESH_notify_transmit_ready (tunnel_reliable, 0,
					 MAX_TRANSMIT_DELAY, msg_size,
					 &transmit_mesh_message,
					 (void *) message_mesh_accept))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not queue MeshSessionAcceptMessage\n"));
      GNUNET_free (message_mesh_accept);
      return;
    }

  connection.status = CONNECTED;
  connection.client = client;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Changed connection status to %d\n"),
	      connection.status);

  return;
}

/**
 * Function to handle a session reject message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
*/
static void
handle_session_reject_message (void *cls, struct GNUNET_SERVER_Client *client,
			       const struct GNUNET_MessageHeader *message)
{
  struct ClientServerSessionRejectMessage *message_received;

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  if (connection.status != CALLEE)
    {
      // TODO send illegal command
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _
		  ("handle_session_reject_message called when not allowed\n"));
      return;
    }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Rejecting the call of: %s\n"),
	      GNUNET_i2s_full (&(connection.peer)));
  message_received = (struct ClientServerSessionRejectMessage *) message;
  reject_call (tunnel_reliable, ntohs (message_received->reason));

  return;
}

/**
 * Function to handle a session terminate message from the client
 *
 * @param cls closure, NULL
 * @param client the client from which the message is
 * @param message the message from the client
*/
static void
handle_session_terminate_message (void *cls,
				  struct GNUNET_SERVER_Client *client,
				  const struct GNUNET_MessageHeader *message)
{
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  if (connection.client == NULL || connection.status == CALLEE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _
		  ("handle_session_terminate_message called when not allowed\n"));
      return;
    }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Terminating the call with: %s\n"),
	      GNUNET_i2s_full (&(connection.peer)));
  terminate_call ();
}

/******************************************************************************/
/***********************       SENDING FUNCTIONS MESH       *******************/
/******************************************************************************/

/**
* Transmit a mesh message
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_mesh_message (void *cls, size_t size, void *buf)
{
  struct VoIPMeshMessageHeader *msg_header =
    (struct VoIPMeshMessageHeader *) cls;
  msg_header->SequenceNumber = SequenceNumber += 1;
  msg_header->time = GNUNET_TIME_absolute_get ();

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transmitting message over mesh\n"));

  memcpy (buf, cls, size);
  // Check if this is correct


  if ((GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_TERMINATE ==
       ntohs (msg_header->header.type))
      || (GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_REJECT ==
	  ntohs (msg_header->header.type)))
    {
      status_to_listen ();
    }
  else if (GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_INITIATE ==
	   ntohs (msg_header->header.type))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting timeout task.\n"));
      timeout_task =
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
				      (GNUNET_TIME_UNIT_SECONDS, 30),
				      &check_timeout, NULL);
    }

  GNUNET_free (cls);

  return size;
}

/**
* Transmit a audo message over mesh
 * @param cls closure, NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_mesh_audio_message (void *cls, size_t size, void *buf)
{
  struct AudioMessage *message = (struct AudioMessage *) cls;

  if (size < sizeof (struct AudioMessage) || NULL == buf)
    {
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "size %u, buf %p, data_sent %u, data_received %u\n",
		  size, buf, data_sent, data_received);
      return 0;
    }

  memcpy (buf, message, size);

  data_sent++;
  data_sent_size += size;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " Sent packet %d\n", data_sent);

  audio_task = GNUNET_SCHEDULER_add_now (&transmit_audio_task, NULL);

  return size;
}

/**
 * Task to schedule a audio transmission.
 * 
 * @param cls Closure.
 * @param tc Task Context.
 */
static void
transmit_audio_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONTAINER_SList_Iterator iterator;
  struct AudioMessage *msg;
  int ab_length = GNUNET_CONTAINER_slist_count (audio_buffer);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "We have %d packets.\n", ab_length);

  if (NULL == cls)
    {
      if (0 == ab_length && CONNECTED == connection.status)
	{
	  audio_task =
	    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
					  (GNUNET_TIME_UNIT_MILLISECONDS, 10),
					  &transmit_audio_task, NULL);
	  return;
	}

      iterator = GNUNET_CONTAINER_slist_begin (audio_buffer);
      msg =
	(struct AudioMessage *) GNUNET_CONTAINER_slist_get (&iterator, NULL);
      msg->SequenceNumber = SequenceNumber += 1;
      msg->time = GNUNET_TIME_absolute_get ();

      GNUNET_CONTAINER_slist_erase (&iterator);
      GNUNET_CONTAINER_slist_iter_destroy (&iterator);
    }
  else
    {
      msg = (struct AudioMessage *) cls;
    }

  if (NULL == tunnel_unreliable)
    {
      GNUNET_CONTAINER_slist_clear (audio_buffer);
      return;
    }

  mth = GNUNET_MESH_notify_transmit_ready (tunnel_unreliable, GNUNET_NO,
					   MAX_TRANSMIT_DELAY,
					   sizeof (struct AudioMessage),
					   &transmit_mesh_audio_message,
					   (void *) msg);

  if (NULL == mth)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Need to retransmit audio packet\n");
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "  in 1 ms\n");
      audio_task =
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				      &transmit_audio_task, (void *) msg);
    }
}

/******************************************************************************/
/***********************       RECEIVE FUNCTIONS MESH      ********************/
/******************************************************************************/

/**
* Function to handle a initiation messaage incoming over mesh
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @pram tunnel_ctx the tunnel context, can be NULL
 * @pram message the incoming message
 * 
 * @return GNUNET_OK
*/
int
handle_mesh_initiate_message (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
			      void **tunnel_ctx,
			      const struct GNUNET_MessageHeader *message)
{
  int reject_reason;
  //struct GNUNET_PeerIdentity *peer =  (GNUNET_MESH_tunnel_get_info(tunnel, GNUNET_MESH_OPTION_PEER))->peer;
  const struct GNUNET_PeerIdentity *peer =
    GNUNET_PEER_resolve2 (tunnel->peer);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Handling MeshSessionInitiateMessage from peer: %s\n"),
	      GNUNET_i2s_full (peer));
  GNUNET_MESH_receive_done (tunnel);

  if (LISTEN != connection.status
      || 1 > GNUNET_CONTAINER_slist_count (clients))
    {

      if (CONNECTED == connection.status)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _
		      ("Rejected call from %s because there is an active call"),
		      GNUNET_i2s_full (peer));
	  reject_reason = htons (REJECT_REASON_ACTIVE_CALL);

	  // Notifying client about missed call
	  size_t msg_size =
	    sizeof (struct ServerClientMissedCallMessage) +
	    sizeof (struct MissedCall);
	  struct ServerClientMissedCallMessage *message =
	    GNUNET_malloc (msg_size);

	  message->header.size = htons (msg_size);
	  message->header.type =
	    htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_MISSED_CALL);
	  message->number = 1;

	  memcpy (&(message->missed_call->peer), peer,
		  sizeof (struct GNUNET_PeerIdentity));
	  message->missed_call->time = GNUNET_TIME_absolute_get ();

	  if (NULL ==
	      GNUNET_SERVER_notify_transmit_ready (connection.client,
						   sizeof (struct
							   ServerClientMissedCallMessage),
						   MAX_TRANSMIT_DELAY,
						   &transmit_server_missed_call_message,
						   (void *) message))
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			  _
			  ("Could not queue ServerClientMissedCallMessage\n"));
	      GNUNET_free (message);
	    }
	}

      if (1 > GNUNET_CONTAINER_slist_count (clients))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Got a call from %s while no client connected.\n"),
		      GNUNET_i2s_full (peer));
	  reject_reason = htons (REJECT_REASON_NO_CLIENT);
	  // Store missed calls
	  struct MissedCall call;
	  memcpy (&(call.peer), peer, sizeof (struct GNUNET_PeerIdentity));
	  call.time = GNUNET_TIME_absolute_get ();
	  GNUNET_CONTAINER_slist_add_end (missed_calls,
					  GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
					  &call, sizeof (struct MissedCall));

	}

      reject_call (tunnel, reject_reason);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Initiated call from: %s\n"),
		  GNUNET_i2s_full (peer));
      tunnel_reliable = tunnel;
      connection.status = CALLEE;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Changed connection status to %d\n"), connection.status);
      memcpy (&(connection.peer), peer, sizeof (struct GNUNET_PeerIdentity));

      struct GNUNET_CONTAINER_SList_Iterator iterator =
	GNUNET_CONTAINER_slist_begin (clients);
      do
	{
	  struct VoipClient *conversation_client =
	    (struct VoipClient *) GNUNET_CONTAINER_slist_get (&iterator,
							      NULL);
	  struct GNUNET_SERVER_Client *client = conversation_client->client;
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Client found: %p\n"),
		      client);

	  if (NULL ==
	      GNUNET_SERVER_notify_transmit_ready (client,
						   sizeof (struct
							   ServerClientSessionInitiateMessage),
						   MAX_TRANSMIT_DELAY,
						   &transmit_server_initiate_message,
						   (void *) peer))
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			  _
			  ("Could not queue ServerClientSessionInitiateMessage\n"));
	    }

	  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Client notified.\n"));
	}
      while (GNUNET_OK == GNUNET_CONTAINER_slist_next (&iterator));

      GNUNET_CONTAINER_slist_iter_destroy (&iterator);

    }

  return GNUNET_OK;
}

/**
* Function to handle an accept messaage incoming over mesh
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @pram tunnel_ctx the tunnel context, can be NULL
 * @pram message the incoming message
 * 
 * @return GNUNET_OK
*/
int
handle_mesh_accept_message (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
			    void **tunnel_ctx,
			    const struct GNUNET_MessageHeader *message)
{
  static uint32_t port = 50003;
  //struct GNUNET_PeerIdentity *peer =  (GNUNET_MESH_tunnel_get_info(tunnel, GNUNET_MESH_OPTION_PEER))->peer;
  const struct GNUNET_PeerIdentity *peer =
    GNUNET_PEER_resolve2 (tunnel->peer);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Handling MeshSessionAccpetMessage from peer: %s (connection.peer: %s)\n"),
	      GNUNET_i2s_full (peer), GNUNET_i2s_full (&(connection.peer)));
  GNUNET_MESH_receive_done (tunnel);

  if (0 ==
      memcmp (peer, &(connection.peer), sizeof (struct GNUNET_PeerIdentity))
      && connection.status == CALLER)
    {
      tunnel_unreliable =
	GNUNET_MESH_tunnel_create (mesh, NULL, peer, port, GNUNET_NO,
				   GNUNET_NO);
      if (NULL == tunnel_unreliable)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Could not create unreliable tunnel\n"));

	  status_to_listen ();

	  GNUNET_SERVER_notify_transmit_ready (connection.client,
					       sizeof (struct
						       ServerClientSessionRejectMessage),
					       MAX_TRANSMIT_DELAY,
					       &transmit_server_reject_message,
					       NULL);
	  return GNUNET_SYSERR;
	}

      if (timeout_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (timeout_task);
	  timeout_task = GNUNET_SCHEDULER_NO_TASK;
	}

      connection.status = CONNECTED;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Changed connection status to %d\n"), connection.status);

      if (NULL ==
	  GNUNET_SERVER_notify_transmit_ready (connection.client,
					       sizeof (struct
						       ServerClientSessionAcceptMessage),
					       MAX_TRANSMIT_DELAY,
					       &transmit_server_accept_message,
					       (void *) message))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _
		      ("Could not queue ServerClientSessionAcceptMessage\n"));
	  return GNUNET_SYSERR;
	}

      start_time = GNUNET_TIME_absolute_get ();
      start_helpers ();
      audio_task = GNUNET_SCHEDULER_add_now (&transmit_audio_task, NULL);
    }

  return GNUNET_OK;
}

/**
* Function to handle a reject messaage incoming over mesh
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @pram tunnel_ctx the tunnel context, can be NULL
 * @pram message the incoming message
 * 
 * @return GNUNET_OK
*/
int
handle_mesh_reject_message (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
			    void **tunnel_ctx,
			    const struct GNUNET_MessageHeader *message)
{
  //struct GNUNET_PeerIdentity *peer =  (GNUNET_MESH_tunnel_get_info(tunnel, GNUNET_MESH_OPTION_PEER))->peer;
  const struct GNUNET_PeerIdentity *peer =
    GNUNET_PEER_resolve2 (tunnel->peer);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Handling MeshSessionRejectMessage from peer: %s (connection.peer: %s)\n"),
	      GNUNET_i2s_full (peer), GNUNET_i2s_full (&(connection.peer)));
  GNUNET_MESH_receive_done (tunnel);

  if (0 ==
      memcmp (peer, &(connection.peer), sizeof (struct GNUNET_PeerIdentity))
      && connection.status == CALLER)
    {
      if (NULL ==
	  GNUNET_SERVER_notify_transmit_ready (connection.client,
					       sizeof (struct
						       ServerClientSessionRejectMessage),
					       MAX_TRANSMIT_DELAY,
					       &transmit_server_reject_message,
					       (void *) message))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _
		      ("Could not queue ServerClientSessionRejectMessage\n"));
	}

      status_to_listen ();

      if (NULL != tunnel_reliable)
	{
	  GNUNET_MESH_tunnel_destroy (tunnel_reliable);
	  tunnel_reliable = NULL;
	}
    }

  return GNUNET_OK;
}

/**
* Function to handle a terminate messaage incoming over mesh
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @pram tunnel_ctx the tunnel context, can be NULL
 * @pram message the incoming message
 * 
 * @return GNUNET_OK
*/
int
handle_mesh_terminate_message (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
			       void **tunnel_ctx,
			       const struct GNUNET_MessageHeader *message)
{
  //struct GNUNET_PeerIdentity *peer =  (GNUNET_MESH_tunnel_get_info(tunnel, GNUNET_MESH_OPTION_PEER))->peer;
  const struct GNUNET_PeerIdentity *peer =
    GNUNET_PEER_resolve2 (tunnel->peer);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _
	      ("Handling MeshSessionTerminateMessage from peer: %s (connection.peer: %s)\n"),
	      GNUNET_i2s_full (peer), GNUNET_i2s_full (&(connection.peer)));
  GNUNET_MESH_receive_done (tunnel);

  if (!memcmp (peer, &(connection.peer), sizeof (struct GNUNET_PeerIdentity))
      && (connection.status == CONNECTED || connection.status == CALLEE))
    {
      status_to_listen ();

      if (NULL != tunnel_unreliable)
	{
	  GNUNET_MESH_tunnel_destroy (tunnel_unreliable);
	  tunnel_unreliable = NULL;
	}

      if (NULL != tunnel_reliable)
	{
	  GNUNET_MESH_tunnel_destroy (tunnel_reliable);
	  tunnel_reliable = NULL;
	}
    }

  return GNUNET_OK;
}

/**
* Function to handle a audio messaage incoming over mesh
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @pram tunnel_ctx the tunnel context, can be NULL
 * @pram message the incoming message
 * 
 * @return GNUNET_OK
*/
int
handle_mesh_audio_message (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
			   void **tunnel_ctx,
			   const struct GNUNET_MessageHeader *message)
{

  GNUNET_MESH_receive_done (tunnel);

  if (CONNECTED != connection.status)
    return GNUNET_OK;


  struct AudioMessage *audio;
  size_t msg_size;
  msg_size = sizeof (struct AudioMessage);

  audio = (struct AudioMessage *) message;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "[RECV] %dbytes\n", audio->length);

  if (NULL == playback_helper)
    return GNUNET_OK;

  (void) GNUNET_HELPER_send (playback_helper,
			     message, GNUNET_YES, NULL, NULL);

  data_received++;
  data_received_size += msg_size;

  return GNUNET_OK;
}

/******************************************************************************/
/***********************  		      HELPER                *******************/
/******************************************************************************/

/**
* Function to process the audio from the record helper
 * @param cls closure, NULL
 * @param client NULL
 * @param msg the message from the helper
 * 
 * @return GNUNET_OK
*/
static int
process_record_messages (void *cls GNUNET_UNUSED, void *client,
			 const struct GNUNET_MessageHeader *msg)
{
  size_t msg_size;
  struct AudioMessage *message = (struct AudioMessage *) msg;
  msg_size = sizeof (struct AudioMessage);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, " [REC] %dbyte\n", message->length);
  GNUNET_CONTAINER_slist_add_end (audio_buffer,
				  GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
				  message, msg_size);

  return GNUNET_OK;
}

/**
* Function to to start the playback helper
 * 
 * @return 0 ok, 1 on error
*/
int
start_playback_helper (void)
{
  static char *playback_helper_argv[1];
  int success = 1;

  playback_helper_argv[0] = "gnunet-helper-audio-playback";
  playback_helper = GNUNET_HELPER_start (GNUNET_NO,
					 "gnunet-helper-audio-playback",
					 playback_helper_argv,
					 NULL, NULL, NULL);

  if (NULL == playback_helper)
    {
      success = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not start playback audio helper.\n"));
    }

  return success;
}

/**
* Function to to start the record helper
 * 
 * @return 0 ok, 1 on error
*/
int
start_record_helper (void)
{
  static char *record_helper_argv[1];
  int success = 1;

  record_helper_argv[0] = "gnunet-helper-audio-record";
  record_helper = GNUNET_HELPER_start (GNUNET_NO,
				       "gnunet-helper-audio-record",
				       record_helper_argv,
				       &process_record_messages, NULL, NULL);

  if (NULL == record_helper)
    {
      success = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not start record audio helper\n"));
    }

  return success;
}


/**
* Function to to start both helpers
 * 
 * @return 0 ok, 1 on error
*/
int
start_helpers (void)
{

  if (0 == start_playback_helper () || 0 == start_record_helper ())
    {
      stop_helpers ();
      return 0;
    }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Started helpers\n"));

  return 1;
}

/**
* Function to to stop the playback helper
*/
void
stop_playback_helper (void)
{
  if (NULL != playback_helper)
    {
      GNUNET_HELPER_stop (playback_helper, GNUNET_NO);
      playback_helper = NULL;

      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Stopped playback helper\n"));
    }
}

/**
* Function to to stop the record helper
*/
void
stop_record_helper (void)
{
  if (NULL != record_helper)
    {
      GNUNET_HELPER_stop (record_helper, GNUNET_NO);
      record_helper = NULL;

      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Stopped record helper\n"));
    }
}

/**
* Function to stop both audio helpers
*/
void
stop_helpers (void)
{
  stop_playback_helper ();
  stop_record_helper ();
}

/******************************************************************************/
/***********************  		 TUNNEL HANDLING            *******************/
/******************************************************************************/

/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param port port
 * @return initial tunnel context for the tunnel (can be NULL -- that's not an error)
 */
static void *
inbound_tunnel (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
		const struct GNUNET_PeerIdentity *initiator, uint32_t port)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Received incoming tunnel on port %d\n"), port);
  if (50003 == port)
    {
      tunnel_unreliable = tunnel;

      start_time = GNUNET_TIME_absolute_get ();

      start_helpers ();
      audio_task = GNUNET_SCHEDULER_add_now (&transmit_audio_task, NULL);
    }

  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
inbound_end (void *cls, const struct GNUNET_MESH_Tunnel *tunnel,
	     void *tunnel_ctx)
{
  if (tunnel == tunnel_unreliable)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Tunnel closed: audio\n");

      stop_helpers ();
      tunnel_unreliable = NULL;
    }

  if (tunnel == tunnel_reliable)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Tunnel closed: control\n");

      if (LISTEN != connection.status && NULL != connection.client)
	{
	  if (NULL ==
	      GNUNET_SERVER_notify_transmit_ready (connection.client,
						   sizeof (struct
							   ServerClientSessionTerminateMessage),
						   MAX_TRANSMIT_DELAY,
						   &transmit_server_terminate_message,
						   NULL))
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			  _
			  ("Could not queue ServerClientSessionTerminateMessage\n"));
	    }
	}

      status_to_listen ();
    }
}

/******************************************************************************/
/***********************          CLIENT HANDLING           *******************/
/******************************************************************************/

/**
 * A client connected.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */

static void
handle_client_connect (void *cls, struct GNUNET_SERVER_Client *cl)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Client connected\n");
  struct ServerClientMissedCallMessage *message;
  size_t msg_size;
  struct VoipClient c;
  c.client = cl;

  GNUNET_CONTAINER_slist_add_end (clients,
				  GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
				  &c, sizeof (struct VoipClient));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Client added: %p\n"), cl);

  if (0 < GNUNET_CONTAINER_slist_count (missed_calls))
    {
      int i = 0;
      msg_size =
	sizeof (struct ServerClientMissedCallMessage) +
	GNUNET_CONTAINER_slist_count (missed_calls) *
	sizeof (struct MissedCall);
      message =
	(struct ServerClientMissedCallMessage *) GNUNET_malloc (msg_size);

      message->header.size = htons (msg_size);
      message->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_SC_MISSED_CALL);
      message->number = GNUNET_CONTAINER_slist_count (missed_calls);

      struct GNUNET_CONTAINER_SList_Iterator iterator =
	GNUNET_CONTAINER_slist_begin (missed_calls);
      do
	{
	  memcpy (&(message->missed_call[i]),
		  GNUNET_CONTAINER_slist_get (&iterator, NULL),
		  sizeof (struct MissedCall));
	  i++;
	}
      while (GNUNET_OK == GNUNET_CONTAINER_slist_next (&iterator));

      GNUNET_CONTAINER_slist_iter_destroy (&iterator);
      GNUNET_CONTAINER_slist_clear (missed_calls);


      if (NULL ==
	  GNUNET_SERVER_notify_transmit_ready (cl, msg_size,
					       MAX_TRANSMIT_DELAY,
					       &transmit_server_missed_call_message,
					       (void *) message))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Could not queue ServerClientMissedCallMessage\n"));
	  GNUNET_free (message);
	}
    }

  return;
}

/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *cl)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Client disconnected\n");

  if (connection.client == cl)
    {
      if (CONNECTED == connection.status)
	{
	  terminate_call ();
	}
      else
	{
	  status_to_listen ();
	}
    }

  struct GNUNET_CONTAINER_SList_Iterator iterator =
    GNUNET_CONTAINER_slist_begin (clients);
  do
    {
      if (((struct VoipClient *)
	   GNUNET_CONTAINER_slist_get (&iterator, NULL))->client == cl)
	{
	  GNUNET_CONTAINER_slist_erase (&iterator);
	}
    }
  while (GNUNET_OK == GNUNET_CONTAINER_slist_next (&iterator));

  GNUNET_CONTAINER_slist_iter_destroy (&iterator);

  return;
}

/******************************************************************************/
/***********************  		      SERVICE               *******************/
/******************************************************************************/

/**
 * Shutdown nicely
 * 
 * @param cls closure, NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutdown\n");

  stop_helpers ();

  if (NULL != tunnel_reliable)
    {
      GNUNET_MESH_tunnel_destroy (tunnel_reliable);
    }

  if (NULL != tunnel_unreliable)
    {
      GNUNET_MESH_tunnel_destroy (tunnel_unreliable);
    }

  if (NULL != mesh)
    {
      GNUNET_MESH_disconnect (mesh);
    }

  if (NULL != nc)
    {
      GNUNET_SERVER_notification_context_destroy (nc);
      nc = NULL;
    }

  GNUNET_CONTAINER_slist_destroy (audio_buffer);
  GNUNET_CONTAINER_slist_destroy (clients);
  GNUNET_CONTAINER_slist_destroy (missed_calls);
  GNUNET_CONTAINER_slist_destroy (peers_to_notify);
}


/**
 * Handler array for traffic received
 */
static struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
  {&handle_mesh_initiate_message,
   GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_INITIATE,
   sizeof (struct MeshSessionInitiateMessage)},
  {&handle_mesh_accept_message, GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_ACCEPT,
   sizeof (struct MeshSessionAcceptMessage)},
  {&handle_mesh_reject_message, GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_REJECT,
   sizeof (struct MeshSessionRejectMessage)},
  {&handle_mesh_terminate_message,
   GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_SESSION_TERMINATE,
   sizeof (struct MeshSessionTerminateMessage)},
  {&handle_mesh_audio_message, GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO,
   sizeof (struct AudioMessage)},
  {NULL, 0, 0}
};

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param server server handle
 * @param c configuration
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{

  static uint32_t ports[] = { 50002, 50003, NULL };
  cfg = c;

  mesh = GNUNET_MESH_connect (cfg,
			      NULL,
			      &inbound_tunnel,
			      &inbound_end, mesh_handlers, ports);

  if (NULL == mesh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Couldn't connect to mesh\n");
      return;
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connected to mesh\n");
    }

  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    {&handle_session_initiate_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_INITIATE,
     sizeof (struct ClientServerSessionInitiateMessage)},
    {&handle_session_accept_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_ACCEPT,
     sizeof (struct ClientServerSessionAcceptMessage)},
    {&handle_session_reject_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_REJECT,
     sizeof (struct ClientServerSessionRejectMessage)},
    {&handle_session_terminate_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_SESSION_TERMINATE,
     sizeof (struct ClientServerSessionTerminateMessage)},
    {NULL, NULL, 0, 0}
  };

  connection.status = LISTEN;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Changed connection status to %d\n"),
	      connection.status);

  nc = GNUNET_SERVER_notification_context_create (server, 16);

  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SERVER_connect_notify (server, &handle_client_connect, NULL);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_shutdown,
				NULL);

  clients = GNUNET_CONTAINER_slist_create ();

  // Missed calls
  missed_calls = GNUNET_CONTAINER_slist_create ();
  peers_to_notify = GNUNET_CONTAINER_slist_create ();
  audio_buffer = GNUNET_CONTAINER_slist_create ();

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Voip service running\n"));
}

/**
 * The main function for the conversation service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
	  GNUNET_SERVICE_run (argc, argv, "conversation", GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-conversation.c */

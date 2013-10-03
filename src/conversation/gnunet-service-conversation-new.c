/*
  This file is part of GNUnet.
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
#include "gnunet_mesh_service.h"
#include "gnunet_conversation_service.h"
#include "conversation.h"


/**
 * The possible connection status
 */
enum LineStatus
{
  /**
   * We are waiting for incoming calls.
   */
  LS_CALLEE_LISTEN,

  /**
   * Our phone is ringing, waiting for the client to pick up.
   */
  LS_CALLEE_RINGING,

  /**
   * We are talking!
   */
  LS_CALLEE_CONNECTED,

  /**
   * We are waiting for the phone to be picked up.
   */
  LS_CALLER_CALLING,

  /**
   * We are talking!
   */
  LS_CALLER_CONNECTED,

  /**
   * We're in shutdown, sending hangup messages before cleaning up.
   */
  LS_CALLER_SHUTDOWN
};


/**
 * A line connects a local client with a mesh tunnel (or, if it is an
 * open line, is waiting for a mesh tunnel).
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
   * Handle for the reliable tunnel (contol data)
   */
  struct GNUNET_MESH_Tunnel *tunnel_reliable;
  
  /**
   * Handle for unreliable tunnel (audio data)
   */
  struct GNUNET_MESH_Tunnel *tunnel_unreliable;

  /**
   * Transmit handle for pending audio messages
   */
  struct GNUNET_MESH_TransmitHandle *mth;

  /**
   * Our line number.
   */
  uint32_t line;

  /**
   * Current status of this line.
   */ 
  enum LineStatus status;

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
 * Handle for mesh
 */
static struct GNUNET_MESH_Handle *mesh;

/**
 * Head of DLL of active lines.
 */
static struct Line *lines_head;

/**
 * Tail of DLL of active lines.
 */
static struct Line *lines_tail;


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

  msg = (struct ClientPhoneRegisterMessage *) message;
  GNUNET_break (0); // FIXME
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

  msg = (struct ClientPhonePickupMessage *) message;
  GNUNET_break (0); // FIXME
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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

  msg = (struct ClientPhoneHangupMessage *) message;
  GNUNET_break (0); // FIXME
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to handle call request the client
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

  msg = (struct ClientCallMessage *) message;
  GNUNET_break (0); // FIXME
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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

  msg = (struct ClientAudioMessage *) message;
  GNUNET_break (0); // FIXME
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to handle a ring message incoming over mesh
 *
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @param tunnel_ctx the tunnel context, can be NULL
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_mesh_ring_message (void *cls,
                          struct GNUNET_MESH_Tunnel *tunnel,
                          void **tunnel_ctx,
                          const struct GNUNET_MessageHeader *message)
{
  const struct MeshPhoneRingMessage *msg;
  
  msg = (const struct MeshPhoneRingMessage *) message;
  GNUNET_break (0); // FIXME
  return GNUNET_OK;
}


/**
 * Function to handle a hangup message incoming over mesh
 *
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @param tunnel_ctx the tunnel context, can be NULL
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_mesh_hangup_message (void *cls,
                            struct GNUNET_MESH_Tunnel *tunnel,
                            void **tunnel_ctx,
                            const struct GNUNET_MessageHeader *message)
{
  const struct MeshPhoneHangupMessage *msg;
  
  msg = (const struct MeshPhoneHangupMessage *) message;
  GNUNET_break (0); // FIXME
  return GNUNET_OK;
}


/**
 * Function to handle a pickup message incoming over mesh
 *
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @param tunnel_ctx the tunnel context, can be NULL
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_mesh_pickup_message (void *cls,
                            struct GNUNET_MESH_Tunnel *tunnel,
                            void **tunnel_ctx,
                            const struct GNUNET_MessageHeader *message)
{
  const struct MeshPhonePickupMessage *msg;
  
  msg = (const struct MeshPhonePickupMessage *) message;
  GNUNET_break (0); // FIXME
  return GNUNET_OK;
}


/**
 * Function to handle a busy message incoming over mesh
 *
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @param tunnel_ctx the tunnel context, can be NULL
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_mesh_busy_message (void *cls,
                          struct GNUNET_MESH_Tunnel *tunnel,
                          void **tunnel_ctx,
                          const struct GNUNET_MessageHeader *message)
{
  const struct MeshPhoneBusyMessage *msg;
  
  msg = (const struct MeshPhoneBusyMessage *) message;
  GNUNET_break (0); // FIXME
  return GNUNET_OK;
}


/**
 * Function to handle an audio message incoming over mesh
 *
 * @param cls closure, NULL
 * @param tunnel the tunnel over which the message arrived
 * @param tunnel_ctx the tunnel context, can be NULL
 * @param message the incoming message
 * @return #GNUNET_OK
 */
static int
handle_mesh_audio_message (void *cls,
                           struct GNUNET_MESH_Tunnel *tunnel,
                           void **tunnel_ctx,
                           const struct GNUNET_MessageHeader *message)
{
  const struct MeshAudioMessage *msg;
  
  msg = (const struct MeshAudioMessage *) message;
  GNUNET_break (0); // FIXME
  return GNUNET_OK;
}


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
inbound_tunnel (void *cls,
                struct GNUNET_MESH_Tunnel *tunnel,
		const struct GNUNET_PeerIdentity *initiator, 
                uint32_t port)
{
  GNUNET_break (0); // FIXME
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Received incoming tunnel on port %d\n"), port);
  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
inbound_end (void *cls,
             const struct GNUNET_MESH_Tunnel *tunnel,
	     void *tunnel_ctx)
{
  GNUNET_break (0); // FIXME
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, 
                          struct GNUNET_SERVER_Client *cl)
{
  GNUNET_break (0); // FIXME
}


/**
 * Shutdown nicely
 * 
 * @param cls closure, NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_break (0); // FIXME
  if (NULL != mesh)
  {
    GNUNET_MESH_disconnect (mesh);
    mesh = NULL;
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
     0},
    {&handle_client_hangup_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP,
     0},
    {&handle_client_call_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL,
     0},
    {&handle_client_audio_message, NULL,
     GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO,
     0},
    {NULL, NULL, 0, 0}
  };
  static struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
    {&handle_mesh_ring_message,
     GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_RING,
     sizeof (struct MeshPhoneRingMessage)},
    {&handle_mesh_hangup_message, 
     GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_HANG_UP,
     0},
    {&handle_mesh_pickup_message, 
     GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_PICK_UP,
     0},
    {&handle_mesh_busy_message, 
     GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_PHONE_BUSY,
     sizeof (struct MeshPhoneBusyMessage)},
    {&handle_mesh_audio_message, GNUNET_MESSAGE_TYPE_CONVERSATION_MESH_AUDIO,
     0},
    {NULL, 0, 0}
  };
  static uint32_t ports[] = { 
    GNUNET_APPLICATION_TYPE_CONVERSATION_CONTROL,
    GNUNET_APPLICATION_TYPE_CONVERSATION_AUDIO,
    0 
  };

  cfg = c;
  mesh = GNUNET_MESH_connect (cfg,
			      NULL,
			      &inbound_tunnel,
			      &inbound_end, 
                              mesh_handlers, 
                              ports);

  if (NULL == mesh)
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

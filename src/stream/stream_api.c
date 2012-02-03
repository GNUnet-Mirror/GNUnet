/*
  This file is part of GNUnet.
  (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file stream/stream_api.c
 * @brief Implementation of the stream library
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_stream_lib.h"

/**
 * states in the Protocol
 */
enum State
  {
    /**
     * Client initialization state
     */
    STATE_INIT,

    /**
     * Listener initialization state 
     */
    STATE_LISTEN,

    /**
     * Pre-connection establishment state
     */
    STATE_HELLO_WAIT,

    /**
     * State where a connection has been established
     */
    STATE_ESTABLISHED,

    /**
     * State where the socket is closed on our side and waiting to be ACK'ed
     */
    STATE_RECEIVE_CLOSE_WAIT,

    /**
     * State where the socket is closed for reading
     */
    STATE_RECEIVE_CLOSED,

    /**
     * State where the socket is closed on our side and waiting to be ACK'ed
     */
    STATE_TRANSMIT_CLOSE_WAIT,

    /**
     * State where the socket is closed for writing
     */
    STATE_TRANSMIT_CLOSED,

    /**
     * State where the socket is closed on our side and waiting to be ACK'ed
     */
    STATE_CLOSE_WAIT,

    /**
     * State where the socket is closed
     */
    STATE_CLOSED 
  };


/**
 * The STREAM Socket Handler
 */
struct GNUNET_STREAM_Socket
{
  /**
   * The mesh handle
   */
  struct GNUNET_MESH_Handle *mesh;

  /**
   * The mesh tunnel handle
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * The session id associated with this stream connection
   */
  uint32_t session_id;

  /**
   * The peer identity of the peer at the other end of the stream
   */
  GNUNET_PeerIdentity other_peer;

  /**
   * Stream open closure
   */
  void *open_cls;

  /**
   * Stream open callback
   */
  GNUNET_STREAM_OpenCallback open_cb;

  /**
   * Retransmission timeout
   */
  struct GNUNET_TIME_Relative retransmit_timeout;

  /**
   * The state of the protocol associated with this socket
   */
  enum State state;

  /**
   * The status of the socket
   */
  enum GNUNET_STREAM_Status status;

  /**
   * The current transmit handle (if a pending transmit request exists)
   */
  struct GNUNET_MESH_TransmitHandle *transmit_handle;

  /**
   * The current message associated with the transmit handle
   */
  struct GNUNET_MessageHeader *message;
};


/**
 * A socket for listening
 */
struct GNUNET_STREAM_ListenSocket
{

  /**
   * The mesh handle
   */
  struct GNUNET_MESH_Handle *mesh;

  /**
   * The service port
   */
  GNUNET_MESH_ApplicationType port;

  /**
   * The callback function which is called after successful opening socket
   */
  GNUNET_STREAM_ListenCallback listen_cb;

  /**
   * The call back closure
   */
  void *listen_cb_cls;

};

/**
 * Default value in seconds for various timeouts
 */
static unsigned int default_timeout = 300;


/**
 * Callback function from send_message
 *
 * @param cls closure the socket on which the send message was called
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_message_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  size_t ret;

  socket->transmit_handle = NULL; /* Remove the transmit handle */
  if (0 == size)                /* Socket closed? */
    {
      // statistics ("message timeout")
      
      
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Message not sent as tunnel was closed \n");
      ret = 0;
    }
  else                          /* Size is more or equal to what was requested */
    {
      ret = ntohs (socket->message->size);
      GNUNET_assert (size >= ret);
      memcpy (buf, socket->message, ret);
    }
  GNUNET_free (socket->message); /* Free the message memory */
  socket->message = NULL;
  return ret;
}


/**
 * Sends a message using the mesh connection of a socket
 *
 * @param socket the socket whose mesh connection is used
 * @param message the message to be sent
 */
static void
send_message (struct GNUNET_STREAM_Socket *socket,
              struct GNUNET_MessageHeader *message)
{
  socket->message = message;
  socket->transmit_handle = 
    GNUNET_MESH_notify_transmit_ready (socket->tunnel,
                                       0, /* Corking */
                                       timeout, /* FIXME: Maxdelay */
                                       socket->other_peer,
                                       ntohs (message->size),
                                       &send_message_notify,
                                       socket);
}

/**
 * Makes state transition dependending on the given state
 *
 * @param socket the socket whose state has to be transitioned
 */
static void
make_state_transition (struct GNUNET_STREAM_Socket *socket)
{

}


/**
 * Message Handler for mesh
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_data (void *cls,
             struct GNUNET_MESH_Tunnel *tunnel,
             void **tunnel_ctx,
             const struct GNUNET_PeerIdentity *sender,
             const struct GNUNET_MessageHeader *message,
             const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  uint16_t size;
  const struct GNUNET_STREAM_DataMessage *data_msg;
  const void *payload;

  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_STREAM_DataMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  data_msg = (const struct GNUNET_STREAM_DataMessage *) message;
  size -= sizeof (Struct GNUNET_STREAM_DataMessage);
  payload = &data_msg[1];
  /* ... */
  
  return GNUNET_OK;
}


/**
 * Message Handler for mesh
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_ack (void *cls,
	    struct GNUNET_MESH_Tunnel *tunnel,
	    void **tunnel_ctx,
	    const struct GNUNET_PeerIdentity *sender,
	    const struct GNUNET_MessageHeader *message,
	    const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  const struct GNUNET_STREAM_AckMessage *ack = (const struct GNUNET_STREAM_AckMessage *) message;

}


static struct GNUNET_MESH_MessageHandler message_handlers[] = {
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_DATA, 0},
  {&handle_ack, GNUNET_MESSAGE_TYPE_STREAM_ACK, sizeof (struct GNUNET_STREAM_AckMessage) },
  {&handle_hello, GNUNET_MESSAGE_TYPE_STREAM_HELLO, 0},
  {&handle_hello_ack, GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK, 0},
  {&handle_reset, GNUNET_MESSAGE_TYPE_STREAM_RESET, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_CLOSE, 0},
  {&handle_data, GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK, 0},
  {NULL, 0, 0}
};


/**
 * Function called when our target peer is connected to our tunnel
 *
 * @param peer the peer identity of the target
 * @param atsi performance data for the connection
 */
static void
mesh_peer_connect_callback (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_ATS_Information * atsi)
{
  const struct GNUNET_STREAM_Socket *socket = cls;

  if (0 != memcmp (socket->other_peer, 
                   peer, 
                   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "A peer (%s) which is not our target has\
  connected to our tunnel", GNUNET_i2s (peer));
      return;
    }
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Target peer %s connected\n", GNUNET_i2s (peer));
  
  /* Set state to INIT */
  socket->state = STATE_INIT;

  /* Try to achieve ESTABLISHED state */
  make_state_transition (socket);

  /* Call open callback */
  if (NULL == open_cls)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "STREAM_open callback is NULL\n");
    }
  if (NULL != socket->open_cb)
    {
      socket->open_cb (socket->open_cls, socket);
    }
}


/**
 * Function called when our target peer is disconnected from our tunnel
 *
 * @param peer the peer identity of the target
 */
static void
mesh_peer_disconnect_callback (void *cls,
                               const struct GNUNET_PeerIdentity *peer)
{

}


/**
 * Function to find the mapped socket of a tunnel
 *
 * @param tunnel the tunnel whose associated socket has to be retrieved
 * @return the socket corresponding to the tunnel
 */
static struct GNUNET_STREAM_Socket *
find_socket (const struct GNUNET_MESH_Tunnel *tunnel)
{
  /* Search tunnel in a list or hashtable and retrieve the socket */
}

/*****************/
/* API functions */
/*****************/


/**
 * Tries to open a stream to the target peer
 *
 * @param cfg configuration to use
 * @param target the target peer to which the stream has to be opened
 * @param app_port the application port number which uniquely identifies this
 *            stream
 * @param open_cb this function will be called after stream has be established 
 * @param open_cb_cls the closure for open_cb
 * @param ... options to the stream, terminated by GNUNET_STREAM_OPTION_END
 * @return if successful it returns the stream socket; NULL if stream cannot be
 *         opened 
 */
struct GNUNET_STREAM_Socket *
GNUNET_STREAM_open (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_PeerIdentity *target,
                    GNUNET_MESH_ApplicationType app_port,
                    GNUNET_STREAM_OpenCallback open_cb,
                    void *open_cb_cls,
                    ...)
{
  struct GNUNET_STREAM_Socket *socket;
  enum GNUNET_STREAM_Option option;
  va_list vargs;                /* Variable arguments */

  socket = GNUNET_malloc (sizeof (struct GNUNET_STREAM_Socket));
  socket->other_peer = *target;
  socket->open_cb = open_cb;
  socket->open_cls = open_cb_cls;

  /* Set defaults */
  socket->retransmit_timeout = 
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, default_timeout);

  va_start (vargs, open_cb_cls); /* Parse variable args */
  do {
    option = va_arg (vargs, enum GNUNET_STREAM_Option);
    switch (option)
      {
      case GNUNET_STREAM_OPTION_INITIAL_RETRANSMIT_TIMEOUT:
        /* Expect struct GNUNET_TIME_Relative */
        socket->retransmit_timeout = va_arg (vargs,
                                             struct GNUNET_TIME_Relative);
        break;
      case GNUNET_STREAM_OPTION_END:
        break;
      }

  } while (0 != option);
  va_end (vargs);               /* End of variable args parsing */

  socket->mesh = GNUNET_MESH_connect (cfg, /* the configuration handle */
                                      1,  /* QUEUE size as parameter? */
                                      socket, /* cls */
                                      NULL, /* No inbound tunnel handler */
                                      NULL, /* No inbound tunnel cleaner */
                                      message_handlers,
                                      NULL); /* We don't get inbound tunnels */
  // FIXME: if (NULL == socket->mesh) ...

  /* Now create the mesh tunnel to target */
  socket->tunnel = GNUNET_MESH_tunnel_create (socket->mesh,
                                              NULL, /* Tunnel context */
                                              &mesh_peer_connect_callback,
                                              &mesh_peer_disconnect_callback,
                                              (void *) socket);
  // FIXME: if (NULL == socket->tunnel) ...

  return socket;
}


/**
 * Closes the stream
 *
 * @param socket the stream socket
 */
void
GNUNET_STREAM_close (struct GNUNET_STREAM_Socket *socket)
{
  /* Clear Transmit handles */
  if (NULL != socket->transmit_handle)
    {
      GNUNET_MESH_notify_transmit_ready_cancel (socket->transmit_handle);
    }
  /* Clear existing message queue message */
  if (NULL != socket->message)
    {
      GNUNET_free (socket->message);
    }
  /* Close associated tunnel */
  if (NULL != socket->tunnel)
    {
      GNUNET_MESH_tunnel_destroy (socket->tunnel);
    }
  /* Close mesh connection */
  if (NULL != socket->mesh)
    {
      GNUNET_MESH_disconnect (socket->mesh);
    }
  GNUNET_free (socket);
}


/**
 * Method called whenever a peer creates a tunnel to us
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
static void 
new_tunnel_notify (void *cls,
                   struct GNUNET_MESH_Tunnel *tunnel,
                   const struct GNUNET_PeerIdentity *initiator,
                   const struct GNUNET_ATS_Information *atsi)
{
  struct GNUNET_STREAM_ListenSocket *lsocket = cls;
  struct GNUNET_STREAM_Socket *socket;

  socket = GNUNET_malloc (sizeof (struct GNUNET_STREAM_Socket));
  socket->tunnel = tunnel;
  socket->session_id = 0;       /* FIXME */
  socket->other_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  memcpy (socket->other_peer, initiator, sizeof (struct GNUNET_PeerIdentity));
  socket->state = STATE_LISTEN;

  if (GNUNET_SYSERR == lsocket->listen_cb (lsocket->listen_cb_cls,
                                           socket,
                                           socket->other_peer))
    {
      socket->state = STATE_CLOSED;
      make_state_transition (socket);
      GNUNET_free (socket->other_peer);
      GNUNET_free (socket);
      GNUNET_MESH_tunnel_destroy (tunnel); /* Destroy the tunnel */
    }
  else
    {
      make_state_transition (socket);
    }
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void 
tunnel_cleaner (void *cls,
                const struct GNUNET_MESH_Tunnel *tunnel,
                void *tunnel_ctx)
{
  struct GNUNET_STREAM_Socket *socket;

  socket = find_socket (tunnel);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Peer %s has terminated connection abruptly\n",
              GNUNET_i2s (socket->other_peer));

  socket->status = GNUNET_STREAM_SHUTDOWN;
  /* Clear Transmit handles */
  if (NULL != socket->transmit_handle)
    {
      GNUNET_MESH_notify_transmit_ready_cancel (socket->transmit_handle);
      socket->transmit_handle = NULL;
    }
   
  /* Clear existing message queue message */
  if (NULL != socket->message)
    {
      GNUNET_free (socket->message);
      socket->message = NULL;
    }
}


/**
 * Listens for stream connections for a specific application ports
 *
 * @param cfg the configuration to use
 * @param app_port the application port for which new streams will be accepted
 * @param listen_cb this function will be called when a peer tries to establish
 *            a stream with us
 * @param listen_cb_cls closure for listen_cb
 * @return listen socket, NULL for any error
 */
struct GNUNET_STREAM_ListenSocket *
GNUNET_STREAM_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      GNUNET_MESH_ApplicationType app_port,
                      GNUNET_STREAM_ListenCallback listen_cb,
                      void *listen_cb_cls)
{
  /* FIXME: Add variable args for passing configration options? */
  struct GNUNET_STREAM_ListenSocket *lsocket;

  lsocket = GNUNET_malloc (sizeof (struct GNUNET_STREAM_ListenSocket));
  lsocket->port = app_port;
  lsocket->listen_cb = listen_cb;
  lsocket->listen_cb_cls = listen_cb_cls;
  lsocket->mesh = GNUNET_MESH_connect (cfg,
                                       10, /* FIXME: QUEUE size as parameter? */
                                       lsocket, /* Closure */
                                       &new_tunnel_notify,
                                       &tunnel_cleaner,
                                       message_handlers,
                                       {app_port, NULL});
  return lsocket;
}


/**
 * Closes the listen socket
 *
 * @param socket the listen socket
 */
void
GNUNET_STREAM_listen_close (struct GNUNET_STREAM_ListenSocket *lsocket)
{
  /* Do house keeping */

  /* Close MESH connection */
  GNUNET_MESH_disconnect (lsocket->mesh);
  
  GNUNET_free (lsocket);
}

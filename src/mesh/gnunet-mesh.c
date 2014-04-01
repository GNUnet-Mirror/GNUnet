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
 * @file mesh/gnunet-mesh.c
 * @brief Print information about mesh tunnels and peers.
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "mesh.h"


/**
 * Option -m.
 */
static int monitor_connections;

/**
 * Option -P.
 */
static int request_peers;

/**
 * Option --peer
 */
static char *peer_id;

/**
 * Option -T.
 */
static int request_tunnels;

/**
 * Option --tunnel
 */
static char *tunnel_id;

/**
 * Option --connection
 */
static char *conn_id;

/**
 * Option --channel
 */
static char *channel_id;

/**
 * Port to listen on (-p).
 */
static uint32_t listen_port;

/**
 * Request echo service
 */
int echo;

/**
 * Time of last echo request.
 */
struct GNUNET_TIME_Absolute echo_time;

/**
 * Task for next echo request.
 */
GNUNET_SCHEDULER_TaskIdentifier echo_task;

/**
 * Peer to connect to.
 */
static char *target_id;

/**
 * Port to connect to
 */
static uint32_t target_port;

/**
 * Data pending in netcat mode.
 */
size_t data_size;


/**
 * Mesh handle.
 */
static struct GNUNET_MESH_Handle *mh;

/**
 * Channel handle.
 */
static struct GNUNET_MESH_Channel *ch;

/**
 * Shutdown task handle.
 */
GNUNET_SCHEDULER_TaskIdentifier sd;



static void
listen_stdio (void);



/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls Closure (unused).
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");
  if (NULL != ch)
  {
    GNUNET_MESH_channel_destroy (ch);
    ch = NULL;
  }
  if (NULL != mh)
  {
    GNUNET_MESH_disconnect (mh);
        mh = NULL;
  }
}


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * FIXME
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
size_t
data_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;
  size_t total_size;

  if (NULL == buf || 0 == size)
  {
    GNUNET_SCHEDULER_shutdown();
    return 0;
  }

  total_size = data_size + sizeof (struct GNUNET_MessageHeader);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending %u bytes\n", data_size);
  GNUNET_assert (size >= total_size);

  msg = buf;
  msg->size = htons (total_size);
  msg->type = htons (GNUNET_MESSAGE_TYPE_MESH_CLI);
  memcpy (&msg[1], cls, data_size);
  if (GNUNET_NO == echo)
  {
    listen_stdio ();
  }
  else
  {
    echo_time = GNUNET_TIME_absolute_get ();
  }

  return total_size;
}


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls Closure (unused).
 * @param tc scheduler context
 */
static void
read_stdio (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static char buf[60000];

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  data_size = read (0, buf, 60000);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "stdio read %u bytes\n", data_size);
  if (data_size < 1)
  {
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  GNUNET_MESH_notify_transmit_ready (ch, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     data_size
                                     + sizeof (struct GNUNET_MessageHeader),
                                     &data_ready, buf);
}


/**
 * Start listening to stdin
 */
static void
listen_stdio (void)
{
  struct GNUNET_NETWORK_FDSet *rs;

  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set_native (rs, 0);
  GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                               GNUNET_TIME_UNIT_FOREVER_REL,
                               rs, NULL,
                               &read_stdio, NULL);
  GNUNET_NETWORK_fdset_destroy (rs);
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_MESH_channel_destroy on the channel.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
channel_ended (void *cls,
               const struct GNUNET_MESH_Channel *channel,
               void *channel_ctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Channel ended!\n");
  GNUNET_break (channel == ch);
  ch = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in #GNUNET_MESH_connect.
 *
 * A call to #GNUNET_MESH_channel_destroy causes te channel to be ignored. In
 * this case the handler MUST return NULL.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port Port this channel is for.
 * @param options MeshOption flag field, with all active option bits set to 1.
 *
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
static void *
channel_incoming (void *cls,
                  struct GNUNET_MESH_Channel * channel,
                  const struct GNUNET_PeerIdentity * initiator,
                  uint32_t port, enum GNUNET_MESH_ChannelOption options)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Incoming channel %p on port %u\n",
              channel, port);
  if (NULL != ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "A channel already exists\n");
    return NULL;
  }
  if (0 == listen_port)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not listening to channels\n");
    return NULL;
  }
  ch = channel;
  if (GNUNET_NO == echo)
  {
    listen_stdio ();
    return NULL;
  }
  data_size = 0;
  return NULL;
}

/**
 * @brief Send an echo request to the remote peer.
 *
 * @param cls Closure (NULL).
 * @param tc Task context.
 */
static void
send_echo (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) || NULL == ch)
    return;

  GNUNET_MESH_notify_transmit_ready (ch, GNUNET_NO,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     sizeof (struct GNUNET_MessageHeader),
                                     &data_ready, NULL);
}



/**
 * Call MESH's monitor API, get info of one connection.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
create_channel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PeerIdentity pid;
  enum GNUNET_MESH_ChannelOption opt;

  GNUNET_assert (NULL == ch);

  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (target_id,
                                                  strlen (target_id),
                                                  &pid.public_key))
  {
    FPRINTF (stderr,
             _("Invalid target `%s'\n"),
             target_id);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to `%s'\n", target_id);
  opt = GNUNET_MESH_OPTION_DEFAULT | GNUNET_MESH_OPTION_RELIABLE;
  ch = GNUNET_MESH_channel_create (mh, NULL, &pid, target_port, opt);
  if (GNUNET_NO == echo)
    listen_stdio ();
  else
    GNUNET_SCHEDULER_add_now (send_echo, NULL);
}


/**
 * Function called whenever a message is received.
 *
 * Each time the function must call #GNUNET_MESH_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from #GNUNET_MESH_connect).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
data_callback (void *cls,
               struct GNUNET_MESH_Channel *channel,
               void **channel_ctx,
               const struct GNUNET_MessageHeader *message)
{
  uint16_t len;
  ssize_t done;
  uint16_t off;
  const char *buf;
  GNUNET_break (ch == channel);

  if (GNUNET_YES == echo)
  {
    if (0 != listen_port)
    {
      /* Just listening to echo incoming messages*/
      GNUNET_MESH_notify_transmit_ready (channel, GNUNET_NO,
                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                        sizeof (struct GNUNET_MessageHeader),
                                        &data_ready, NULL);
      return GNUNET_OK;
    }
    else
    {
      struct GNUNET_TIME_Relative latency;

      latency = GNUNET_TIME_absolute_get_duration (echo_time);
      echo_time = GNUNET_TIME_UNIT_FOREVER_ABS;
      FPRINTF (stdout, "time: %s\n",
               GNUNET_STRINGS_relative_time_to_string (latency, GNUNET_NO));
      echo_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                &send_echo, NULL);
    }
  }

  len = ntohs (message->size) - sizeof (*message);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got %u bytes\n", len);
  buf = (const char *) &message[1];
  off = 0;
  while (off < len)
  {
    done = write (1, &buf[off], len - off);
    if (done <= 0)
    {
      if (-1 == done)
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "write");
      return GNUNET_SYSERR;
    }
    off += done;
  }
  return GNUNET_OK;
}


/**
 * Method called to retrieve information about all peers in MESH, called
 * once per peer.
 *
 * After last peer has been reported, an additional call with NULL is done.
 *
 * @param cls Closure.
 * @param peer Peer, or NULL on "EOF".
 * @param tunnel Do we have a tunnel towards this peer?
 * @param n_paths Number of known paths towards this peer.
 * @param best_path How long is the best path?
 *                  (0 = unknown, 1 = ourselves, 2 = neighbor)
 */
static void
peers_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                int tunnel, unsigned int n_paths, unsigned int best_path)
{
  if (NULL == peer)
  {
    if (GNUNET_YES != monitor_connections)
    {
      GNUNET_SCHEDULER_shutdown();
    }
    return;
  }
  FPRINTF (stdout, "%s tunnel: %c, paths: %u\n",
           GNUNET_i2s_full (peer), tunnel ? 'Y' : 'N', n_paths);
}

/**
 * Method called to retrieve information about a specific peer
 * known to the service.
 *
 * @param cls Closure.
 * @param peer Peer ID.
 * @param tunnel Do we have a tunnel towards this peer? #GNUNET_YES/#GNUNET_NO
 * @param neighbor Is this a direct neighbor? #GNUNET_YES/#GNUNET_NO
 * @param n_paths Number of paths known towards peer.
 * @param paths Array of PEER_IDs representing all paths to reach the peer.
 *              Each path starts with the local peer.
 *              Each path ends with the destination peer (given in @c peer).
 */
void
peer_callback (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               int tunnel,
               int neighbor,
               unsigned int n_paths,
               struct GNUNET_PeerIdentity *paths)
{
}


/**
 * Method called to retrieve information about all tunnels in MESH.
 *
 * @param cls Closure.
 * @param peer Destination peer.
 * @param channels Number of channels.
 * @param connections Number of connections.
 * @param estate Encryption state.
 * @param cstate Connectivity state.
 */
void
tunnels_callback (void *cls,
                  const struct GNUNET_PeerIdentity *peer,
                  unsigned int channels,
                  unsigned int connections,
                  uint16_t estate,
                  uint16_t cstate)
{
  if (NULL == peer)
  {
    if (GNUNET_YES != monitor_connections)
    {
      GNUNET_SCHEDULER_shutdown();
    }
    return;
  }
  FPRINTF (stdout, "%s [ENC: %u, CON: %u] CHs: %u, CONNs: %u\n",
           GNUNET_i2s_full (peer), estate, cstate, channels, connections);
}


/**
 * Method called to retrieve information about a specific tunnel the mesh peer
 * has established, o`r is trying to establish.
 *
 * @param cls Closure.
 * @param peer Peer towards whom the tunnel is directed.
 * @param n_channels Number of channels.
 * @param n_connections Number of connections.
 * @param channels Channels.
 * @param connections Connections.
 * @param estate Encryption status.
 * @param cstate Connectivity status.
 */
void
tunnel_callback (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 unsigned int n_channels,
                 unsigned int n_connections,
                 uint32_t *channels,
                 struct GNUNET_MeshHash *connections,
                 unsigned int estate,
                 unsigned int cstate)
{
  unsigned int i;

  if (NULL != peer)
  {
    FPRINTF (stdout, "Tunnel %s\n", GNUNET_i2s_full (peer));
    FPRINTF (stdout, "- %u channels\n", n_channels);
    for (i = 0; i < n_channels; i++)
      FPRINTF (stdout, "   %u\n", channels[i]);
    FPRINTF (stdout, "- %u connections\n", n_connections);
    for (i = 0; i < n_connections; i++)
      FPRINTF (stdout, "   %s\n", GM_h2s (&connections[i]));
    FPRINTF (stdout, "- enc state: %u\n", estate);
    FPRINTF (stdout, "- con state: %u\n", cstate);
  }
  if (GNUNET_YES != monitor_connections)
  {
    GNUNET_SCHEDULER_shutdown();
  }
  return;

}


/**
 * Call MESH's meta API, get all peers known to a peer.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
get_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");
    return;
  }
  GNUNET_MESH_get_peers (mh, &peers_callback, NULL);
}


/**
 * Call MESH's monitor API, get info of one peer.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
show_peer (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PeerIdentity pid;

  if (GNUNET_OK !=
    GNUNET_CRYPTO_eddsa_public_key_from_string (peer_id,
                                                strlen (peer_id),
                                                &pid.public_key))
  {
    fprintf (stderr,
             _("Invalid peer ID `%s'\n"),
             peer_id);
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  GNUNET_MESH_get_peer (mh, &pid, peer_callback, NULL);
}

/**
 * Call MESH's meta API, get all tunnels known to a peer.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
get_tunnels (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");
    return;
  }
  GNUNET_MESH_get_tunnels (mh, &tunnels_callback, NULL);
}


/**
 * Call MESH's monitor API, get info of one tunnel.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
show_tunnel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PeerIdentity pid;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (tunnel_id,
                                                  strlen (tunnel_id),
                                                  &pid.public_key))
  {
    fprintf (stderr,
             _("Invalid tunnel owner `%s'\n"),
             tunnel_id);
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  GNUNET_MESH_get_tunnel (mh, &pid, tunnel_callback, NULL);
}


/**
 * Call MESH's monitor API, get info of one channel.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
show_channel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

}


/**
 * Call MESH's monitor API, get info of one connection.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext
 */
static void
show_connection (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_MESH_InboundChannelNotificationHandler *newch = NULL;
  GNUNET_MESH_ChannelEndHandler *endch = NULL;
  static const struct GNUNET_MESH_MessageHandler handlers[] = {
    {&data_callback, GNUNET_MESSAGE_TYPE_MESH_CLI, 0},
    {NULL, 0, 0} /* FIXME add option to monitor msg types */
  };
  static uint32_t *ports = NULL;
  /* FIXME add option to monitor apps */

  target_id = args[0];
  target_port = args[0] && args[1] ? atoi(args[1]) : 0;
  if ( (0 != (request_peers | request_tunnels)
        || 0 != monitor_connections
        || NULL != tunnel_id
        || NULL != conn_id
        || NULL != channel_id)
       && target_id != NULL)
  {
    FPRINTF (stderr,
             _("You must NOT give a TARGET"
               "when using 'request all' options\n"));
    return;
  }

  if (NULL != target_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating channel to %s\n",
                target_id);
    GNUNET_SCHEDULER_add_now (&create_channel, NULL);
    endch = &channel_ended;
  }
  else if (0 != listen_port)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Listen\n");
    newch = &channel_incoming;
    endch = &channel_ended;
    ports = GNUNET_malloc (sizeof (uint32_t) * 2);
    ports[0] = listen_port;
  }
  else if (NULL != peer_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Show peer\n");
    GNUNET_SCHEDULER_add_now (&show_peer, NULL);
  }
  else if (NULL != tunnel_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Show tunnel\n");
    GNUNET_SCHEDULER_add_now (&show_tunnel, NULL);
  }
  else if (NULL != channel_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Show channel\n");
    GNUNET_SCHEDULER_add_now (&show_channel, NULL);
  }
  else if (NULL != conn_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Show connection\n");
    GNUNET_SCHEDULER_add_now (&show_connection, NULL);
  }
  else if (GNUNET_YES == request_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Show all peers\n");
    GNUNET_SCHEDULER_add_now (&get_peers, NULL);
  }
  else if (GNUNET_YES == request_tunnels)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Show all tunnels\n");
    GNUNET_SCHEDULER_add_now (&get_tunnels, NULL);
  }
  else
  {
    FPRINTF (stderr, "No action requested\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to mesh\n");
  mh = GNUNET_MESH_connect (cfg,
                            NULL, /* cls */
                            newch, /* new channel */
                            endch, /* cleaner */
                            handlers,
                            ports);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Done\n");
  if (NULL == mh)
    GNUNET_SCHEDULER_add_now (shutdown_task, NULL);
  else
    sd = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                       shutdown_task, NULL);

}


/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  const char helpstr[] = "Create channels and retreive info about meshs status.";
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
//     {'a', "channel", "TUNNEL_ID:CHANNEL_ID",
//      gettext_noop ("provide information about a particular channel"),
//      GNUNET_YES, &GNUNET_GETOPT_set_string, &channel_id},
    {'C', "connection", "CONNECTION_ID",
     gettext_noop ("provide information about a particular connection"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &conn_id},
    {'e', "echo", NULL,
     gettext_noop ("activate echo mode"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &echo},
//     {'m', "monitor", NULL,
//      gettext_noop ("provide information about all tunnels (continuously) NOT IMPLEMENTED"), /* FIXME */
//      GNUNET_NO, &GNUNET_GETOPT_set_one, &monitor_connections},
    {'o', "open-port", NULL,
     gettext_noop ("port to listen to (default; 0)"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &listen_port},
    {'p', "peer", "PEER_ID",
    gettext_noop ("provide information about all peers"),
    GNUNET_NO, &GNUNET_GETOPT_set_string, &peer_id},
    {'P', "peers", NULL,
      gettext_noop ("provide information about all peers"),
      GNUNET_NO, &GNUNET_GETOPT_set_one, &request_peers},
    {'t', "tunnel", "TUNNEL_ID",
     gettext_noop ("provide information about a particular tunnel"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &tunnel_id},
    {'T', "tunnels", NULL,
     gettext_noop ("provide information about all tunnels"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &request_tunnels},

    GNUNET_GETOPT_OPTION_END
  };

  monitor_connections = GNUNET_NO;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-mesh (OPTIONS | TARGET PORT)",
                            gettext_noop (helpstr),
                            options, &run, NULL);

  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return 0;
  else
    return 1;
}

/* end of gnunet-mesh.c */

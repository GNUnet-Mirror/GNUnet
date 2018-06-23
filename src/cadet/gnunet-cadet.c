/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-cadet.c
 * @brief Print information about cadet tunnels and peers.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_cadet_service.h"
#include "cadet.h"


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
 * Port to listen on (-o).
 */
static char *listen_port;

/**
 * Request echo service
 */
static int echo;

/**
 * Request a debug dump
 */
static int dump;

/**
 * Time of last echo request.
 */
static struct GNUNET_TIME_Absolute echo_time;

/**
 * Task for next echo request.
 */
static struct GNUNET_SCHEDULER_Task *echo_task;

/**
 * Peer to connect to.
 */
static char *target_id;

/**
 * Port to connect to
 */
static char *target_port = "default";

/**
 * Cadet handle.
 */
static struct GNUNET_CADET_Handle *mh;

/**
 * Channel handle.
 */
static struct GNUNET_CADET_Channel *ch;

/**
 * HashCode of the given port string
 */
static struct GNUNET_HashCode porthash;

/**
 * Data structure for ongoing reception of incoming virtual circuits.
 */
struct GNUNET_CADET_Port *lp;

/**
 * Task for reading from stdin.
 */
static struct GNUNET_SCHEDULER_Task *rd_task;

/**
 * Task for main job.
 */
static struct GNUNET_SCHEDULER_Task *job;


/**
 * Wait for input on STDIO and send it out over the #ch.
 */
static void
listen_stdio (void);


/**
 * Convert encryption status to human readable string.
 *
 * @param status Encryption status.
 *
 * @return Human readable string.
 */
static const char *
enc_2s (uint16_t status)
{
  switch (status)
  {
    case 0:
      return "NULL ";
    case 1:
      return "KSENT";
    case 2:
      return "KRECV";
    case 3:
      return "READY";
    default:
      return "";
  }
}


/**
 * Convert connection status to human readable string.
 *
 * @param status Connection status.
 *
 * @return Human readable string.
 */
static const char *
conn_2s (uint16_t status)
{
  switch (status)
  {
    case 0:
      return "NEW  ";
    case 1:
      return "SRCH ";
    case 2:
      return "WAIT ";
    case 3:
      return "READY";
    case 4:
      return "SHUTD";
    default:
      return "";
  }
}



/**
 * Task to shut down this application.
 *
 * @param cls Closure (unused).
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shutdown\n");
  if (NULL != ch)
  {
    GNUNET_CADET_channel_destroy (ch);
    ch = NULL;
  }
  if (NULL != mh)
  {
    GNUNET_CADET_disconnect (mh);
    mh = NULL;
  }
  if (NULL != rd_task)
  {
    GNUNET_SCHEDULER_cancel (rd_task);
    rd_task = NULL;
  }
  if (NULL != echo_task)
  {
    GNUNET_SCHEDULER_cancel (echo_task);
    echo_task = NULL;
  }
  if (NULL != job)
  {
    GNUNET_SCHEDULER_cancel (job);
    job = NULL;
  }
}


/**
 * Task run in stdio mode, after some data is available at stdin.
 *
 * @param cls Closure (unused).
 */
static void
read_stdio (void *cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  char buf[60000];
  ssize_t data_size;

  rd_task = NULL;
  data_size = read (0,
                    buf,
                    60000);
  if (data_size < 1)
  {
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Read %u bytes from stdio\n",
              (unsigned int) data_size);
  env = GNUNET_MQ_msg_extra (msg,
                             data_size,
                             GNUNET_MESSAGE_TYPE_CADET_CLI);
  GNUNET_memcpy (&msg[1],
                 buf,
                 data_size);
  GNUNET_MQ_send (GNUNET_CADET_get_mq (ch),
                  env);
  if (GNUNET_NO == echo)
  {
    listen_stdio ();
  }
  else
  {
    echo_time = GNUNET_TIME_absolute_get ();
  }
}


/**
 * Wait for input on STDIO and send it out over the #ch.
 */
static void
listen_stdio ()
{
  struct GNUNET_NETWORK_FDSet *rs;

  /* FIXME: why use 'rs' here, seems overly complicated... */
  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set_native (rs,
                                   0); /* STDIN */
  rd_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         rs,
                                         NULL,
                                         &read_stdio,
                                         NULL);
  GNUNET_NETWORK_fdset_destroy (rs);
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * @param cls closure
 * @param channel connection to the other end (henceforth invalid)
 */
static void
channel_ended (void *cls,
               const struct GNUNET_CADET_Channel *channel)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Channel ended!\n");
  GNUNET_assert (channel == ch);
  ch = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in #GNUNET_CADET_connect.
 *
 * A call to #GNUNET_CADET_channel_destroy causes the channel to be ignored.
 * In this case the handler MUST return NULL.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @return initial channel context for the channel, we use @a channel
 */
static void *
channel_incoming (void *cls,
                  struct GNUNET_CADET_Channel *channel,
                  const struct GNUNET_PeerIdentity *initiator)
{
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
              "Incoming connection from %s\n",
              GNUNET_i2s_full (initiator));
  GNUNET_assert (NULL == ch);
  GNUNET_assert (NULL != lp);
  GNUNET_CADET_close_port (lp);
  lp = NULL;
  ch = channel;
  if (GNUNET_NO == echo)
    listen_stdio ();
  return channel;
}


/**
 * @brief Send an echo request to the remote peer.
 *
 * @param cls Closure (NULL).
 */
static void
send_echo (void *cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  echo_task = NULL;
  if (NULL == ch)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_CLI);
  GNUNET_MQ_send (GNUNET_CADET_get_mq (ch),
                  env);
}


/**
 * Call CADET's monitor API, request debug dump on the service.
 *
 * @param cls Closure (unused).
 */
static void
request_dump (void *cls)
{
  job = NULL;
  GNUNET_CADET_request_dump (mh);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Check data message sanity. Does nothing so far (all messages are OK).
 *
 * @param cls Closure (unused).
 * @param message The message to check.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
check_data (void *cls,
            const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK; /* all is well-formed */
}


/**
 * Function called whenever a message is received.
 *
 * Each time the function must call #GNUNET_CADET_receive_done on the channel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls NULL
 * @param message The actual message.
 */
static void
handle_data (void *cls,
             const struct GNUNET_MessageHeader *message)
{
  size_t payload_size = ntohs (message->size) - sizeof (*message);
  uint16_t len;
  ssize_t done;
  uint16_t off;
  const char *buf;

  GNUNET_CADET_receive_done (ch);
  if (GNUNET_YES == echo)
  {
    if (NULL != listen_port)
    {
      struct GNUNET_MQ_Envelope *env;
      struct GNUNET_MessageHeader *msg;

      env = GNUNET_MQ_msg_extra (msg,
                                 payload_size,
                                 GNUNET_MESSAGE_TYPE_CADET_CLI);
      GNUNET_memcpy (&msg[1],
                     &message[1],
                     payload_size);
      GNUNET_MQ_send (GNUNET_CADET_get_mq (ch),
                      env);
      return;
    }
    else
    {
      struct GNUNET_TIME_Relative latency;

      latency = GNUNET_TIME_absolute_get_duration (echo_time);
      echo_time = GNUNET_TIME_UNIT_FOREVER_ABS;
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "time: %s\n",
                  GNUNET_STRINGS_relative_time_to_string (latency,
                                                          GNUNET_NO));
      echo_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                &send_echo,
                                                NULL);
    }
  }

  len = ntohs (message->size) - sizeof (*message);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got %u bytes\n",
              len);
  buf = (const char *) &message[1];
  off = 0;
  while (off < len)
  {
    done = write (1,
                  &buf[off],
                  len - off);
    if (done <= 0)
    {
      if (-1 == done)
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "write");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    off += done;
  }
}


/**
 * Method called to retrieve information about all peers in CADET, called
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
peers_callback (void *cls,
		const struct GNUNET_PeerIdentity *peer,
                int tunnel,
		unsigned int n_paths,
		unsigned int best_path)
{
  if (NULL == peer)
  {
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  FPRINTF (stdout,
           "%s tunnel: %c, paths: %u\n",
           GNUNET_i2s_full (peer),
           tunnel ? 'Y' : 'N',
           n_paths);
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
static void
peer_callback (void *cls,
               const struct GNUNET_PeerIdentity *peer,
               int tunnel,
               int neighbor,
               unsigned int n_paths,
               const struct GNUNET_PeerIdentity *paths)
{
  unsigned int i;
  const struct GNUNET_PeerIdentity *p;

  FPRINTF (stdout,
           "%s [TUNNEL: %s, NEIGHBOR: %s, PATHS: %u]\n",
           GNUNET_i2s_full (peer),
           tunnel ? "Y" : "N",
           neighbor ? "Y" : "N",
           n_paths);
  p = paths;
  for (i = 0; i < n_paths && NULL != p;)
  {
    FPRINTF (stdout,
             "%s ",
             GNUNET_i2s (p));
    if (0 == memcmp (p,
                     peer,
                     sizeof (*p)))
    {
      FPRINTF (stdout, "\n");
      i++;
    }
    p++;
  }

  GNUNET_SCHEDULER_shutdown();
}


/**
 * Method called to retrieve information about all tunnels in CADET.
 *
 * @param cls Closure.
 * @param peer Destination peer.
 * @param channels Number of channels.
 * @param connections Number of connections.
 * @param estate Encryption state.
 * @param cstate Connectivity state.
 */
static void
tunnels_callback (void *cls,
                  const struct GNUNET_PeerIdentity *peer,
                  unsigned int channels,
                  unsigned int connections,
                  uint16_t estate,
                  uint16_t cstate)
{
  if (NULL == peer)
  {
    GNUNET_SCHEDULER_shutdown();
    return;
  }
  FPRINTF (stdout,
           "%s [ENC: %s, CON: %s] CHs: %u, CONNs: %u\n",
           GNUNET_i2s_full (peer),
           enc_2s (estate),
           conn_2s (cstate),
           channels,
           connections);
}


/**
 * Method called to retrieve information about a specific tunnel the cadet peer
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
static void
tunnel_callback (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 unsigned int n_channels,
                 unsigned int n_connections,
                 const struct GNUNET_CADET_ChannelTunnelNumber *channels,
                 const struct GNUNET_CADET_ConnectionTunnelIdentifier *connections,
                 unsigned int estate,
                 unsigned int cstate)
{
  unsigned int i;

  if (NULL != peer)
  {
    FPRINTF (stdout, "Tunnel %s\n", GNUNET_i2s_full (peer));
    FPRINTF (stdout, "\t%u channels\n", n_channels);
    for (i = 0; i < n_channels; i++)
      FPRINTF (stdout, "\t\t%X\n", ntohl (channels[i].cn));
    FPRINTF (stdout, "\t%u connections\n", n_connections);
    for (i = 0; i < n_connections; i++)
      FPRINTF (stdout, "\t\t%s\n", GNUNET_sh2s (&connections[i].connection_of_tunnel));
    FPRINTF (stdout, "\tencryption state: %s\n", enc_2s (estate));
    FPRINTF (stdout, "\tconnection state: %s\n", conn_2s (cstate));
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Call CADET's meta API, get all peers known to a peer.
 *
 * @param cls Closure (unused).
 */
static void
get_peers (void *cls)
{
  job = NULL;
  GNUNET_CADET_get_peers (mh, &peers_callback, NULL);
}


/**
 * Call CADET's monitor API, get info of one peer.
 *
 * @param cls Closure (unused).
 */
static void
show_peer (void *cls)
{
  struct GNUNET_PeerIdentity pid;

  job = NULL;
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
  GNUNET_CADET_get_peer (mh, &pid, peer_callback, NULL);
}


/**
 * Call CADET's meta API, get all tunnels known to a peer.
 *
 * @param cls Closure (unused).
 */
static void
get_tunnels (void *cls)
{
  job = NULL;
  GNUNET_CADET_get_tunnels (mh, &tunnels_callback, NULL);
}


/**
 * Call CADET's monitor API, get info of one tunnel.
 *
 * @param cls Closure (unused).
 */
static void
show_tunnel (void *cls)
{
  struct GNUNET_PeerIdentity pid;

  job = NULL;
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (tunnel_id,
                                                  strlen (tunnel_id),
                                                  &pid.public_key))
  {
    fprintf (stderr,
             _("Invalid tunnel owner `%s'\n"),
             tunnel_id);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CADET_get_tunnel (mh,
                           &pid,
                           &tunnel_callback,
                           NULL);
}


/**
 * Call CADET's monitor API, get info of one channel.
 *
 * @param cls Closure (unused).
 */
static void
show_channel (void *cls)
{
  job = NULL;
  GNUNET_break (0);
}


/**
 * Call CADET's monitor API, get info of one connection.
 *
 * @param cls Closure (unused).
 */
static void
show_connection (void *cls)
{
  job = NULL;
  GNUNET_break (0);
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_CADET_CLI,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  /* FIXME add option to monitor apps */

  target_id = args[0];
  if (target_id && args[1])
    target_port = args[1];

  if ( (0 != (request_peers | request_tunnels)
        || NULL != tunnel_id
        || NULL != conn_id
        || NULL != channel_id)
       && target_id != NULL)
  {
    FPRINTF (stderr,
             _("Extra arguments are not applicable "
               "in combination with this option.\n"));
    return;
  }

  if (GNUNET_YES == dump)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Requesting debug dump\n");
    job = GNUNET_SCHEDULER_add_now (&request_dump,
                                    NULL);
  }
  else if (NULL != peer_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Show peer\n");
    job = GNUNET_SCHEDULER_add_now (&show_peer,
                                    NULL);
  }
  else if (NULL != tunnel_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Show tunnel\n");
    job = GNUNET_SCHEDULER_add_now (&show_tunnel,
                                    NULL);
  }
  else if (NULL != channel_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Show channel\n");
    job = GNUNET_SCHEDULER_add_now (&show_channel,
                                    NULL);
  }
  else if (NULL != conn_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Show connection\n");
    job = GNUNET_SCHEDULER_add_now (&show_connection,
                                    NULL);
  }
  else if (GNUNET_YES == request_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Show all peers\n");
    job = GNUNET_SCHEDULER_add_now (&get_peers,
                                    NULL);
  }
  else if (GNUNET_YES == request_tunnels)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Show all tunnels\n");
    job = GNUNET_SCHEDULER_add_now (&get_tunnels,
                                    NULL);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to CADET service\n");
  mh = GNUNET_CADET_connect (cfg);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  if (NULL == mh)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL != listen_port)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Opening CADET listen port\n");
    GNUNET_CRYPTO_hash (listen_port,
                        strlen (listen_port),
                        &porthash);
    lp = GNUNET_CADET_open_port (mh,
                                 &porthash,
                                 &channel_incoming,
                                 NULL,
                                 NULL /* window changes */,
                                 &channel_ended,
                                 handlers);
  }
  if (NULL != target_id)
  {
    struct GNUNET_PeerIdentity pid;
    enum GNUNET_CADET_ChannelOption opt;

    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (target_id,
                                                    strlen (target_id),
                                                    &pid.public_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  _("Invalid target `%s'\n"),
                  target_id);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connecting to `%s:%s'\n",
                target_id,
                target_port);
    opt = GNUNET_CADET_OPTION_DEFAULT | GNUNET_CADET_OPTION_RELIABLE;
    GNUNET_CRYPTO_hash (target_port,
                        strlen(target_port),
                        &porthash);
    ch = GNUNET_CADET_channel_create (mh,
                                      NULL,
                                      &pid,
                                      &porthash,
                                      opt,
                                      NULL /* window changes */,
                                      &channel_ended,
                                      handlers);
    if (GNUNET_YES == echo)
    {
      echo_task = GNUNET_SCHEDULER_add_now (&send_echo,
                                            NULL);
    }
    else
    {
      listen_stdio ();
    }
  }

  if ( (NULL == lp) &&
       (NULL == job) &&
       (NULL == ch) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _("No action requested\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  int res;
  const char helpstr[] = "Create tunnels and retrieve info about CADET's status.";
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    /* I would use the terminology 'circuit' here...  --lynX */
    GNUNET_GETOPT_option_string ('C',
                                 "connection",
                                 "CONNECTION_ID",
                                 gettext_noop ("Provide information about a particular connection"),
                                 &conn_id),

    GNUNET_GETOPT_option_flag ('e',
                                  "echo",
                                  gettext_noop ("Activate echo mode"),
                                  &echo), 

    GNUNET_GETOPT_option_flag ('d',
                                  "dump",
                                  gettext_noop ("Dump debug information to STDERR"),
                                  &dump),

    GNUNET_GETOPT_option_string ('o',
                                 "open-port",
                                 "SHARED_SECRET",
                                 gettext_noop ("Listen for connections using a shared secret among sender and recipient"),
                                 &listen_port),


    GNUNET_GETOPT_option_string ('p',
                                 "peer",
                                 "PEER_ID",
                                 gettext_noop ("Provide information about a patricular peer"),
                                 &peer_id),


    GNUNET_GETOPT_option_flag ('P',
                                  "peers",
                                  gettext_noop ("Provide information about all peers"),
                                  &request_peers),

    GNUNET_GETOPT_option_string ('t',
                                 "tunnel",
                                 "TUNNEL_ID",
                                 gettext_noop ("Provide information about a particular tunnel"),
                                 &tunnel_id),


    GNUNET_GETOPT_option_flag ('T',
                                  "tunnels",
                                  gettext_noop ("Provide information about all tunnels"),
                                  &request_tunnels),

    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv,
                            "gnunet-cadet (OPTIONS | PEER_ID SHARED_SECRET)",
                            gettext_noop (helpstr),
                            options, &run, NULL);

  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return 0;
  return 1;
}

/* end of gnunet-cadet.c */

/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2012, 2014 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file core/gnunet-core.c
 * @brief Print information about other peers known to CORE.
 * @author Nathan Evans
 */
#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"


/**
 * Option -e.
 */
static int echo;

/**
 * Option -m.
 */
static int monitor_connections;

/**
 * Option -r.
 */
static int measure_rtt;

/**
 * Argument of the -p option
 */
static char *peer;

/**
 * Handle to the CORE monitor.
 */
static struct GNUNET_CORE_MonitorHandle *mh;

/**
 * Handle to the CORE service.
 */
static struct GNUNET_CORE_Handle *service_handle;

/**
 * Identity of the peer we transmit to
 */
static struct GNUNET_PeerIdentity peer_id;

/**
 * the number of RTT measurements to be done
 */
static unsigned int ping_limit;

/**
 * the ping timeout given as command line argument
 */
static unsigned int ping_timeout_seconds;

/**
 * the time span we are waiting for a ping response before sending the next ping
 */
static struct GNUNET_TIME_Relative ping_timeout;

/**
 * echo reply timeout task
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * are we waiting for an echo reply?
 */
static int waiting_for_pong;

/**
 * number of echo_replies we sent
 */
static unsigned int ping_count;

/**
 * Time of the last echo request
 */
static struct GNUNET_TIME_Absolute echo_time;


/**
 * TODO
 */
static void
send_ping (void *cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Handle *mq = cls;

  if (GNUNET_YES == waiting_for_pong)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "ping %d timed out.\n",
                ping_count);
  }

  if (ping_limit != 0 && ping_count == ping_limit)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  echo_time = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_AbsoluteNBO payload = GNUNET_TIME_absolute_hton (echo_time);
  env = GNUNET_MQ_msg_extra (msg,
                             sizeof (payload),
                             GNUNET_MESSAGE_TYPE_DUMMY); // Message type? Dummy?
  GNUNET_memcpy (&msg[1], 
                 &payload,
                 sizeof (payload));
  GNUNET_MQ_send (mq,
                  env);
  ping_count++;
  waiting_for_pong = GNUNET_YES;

  if (ping_timeout.rel_value_us != 0)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task =
      GNUNET_SCHEDULER_add_delayed (ping_timeout, send_ping, NULL);
  }

}


/**
 * Function called for each received message.
 *
 * @param cls closure
 * @param message the message
 * @return #GNUNET_OK
 */
static int
check_dummy (void *cls,
	     const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK; /* all messages are fine */
}


/**
 * Function called for each received message.
 *
 * @param cls closure
 * @param message the message
 */
static void
handle_dummy (void *cls,
	      const struct GNUNET_MessageHeader *message)
{
  size_t payload_size = ntohs (message->size) - sizeof (*message);

  struct GNUNET_MQ_Handle *mq = cls;

  if (GNUNET_YES == echo)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_MessageHeader *msg;

    env = GNUNET_MQ_msg_extra (msg,
                               payload_size,
                               GNUNET_MESSAGE_TYPE_DUMMY);
    GNUNET_memcpy (&msg[1],
                   &message[1],
                   payload_size);
    GNUNET_MQ_send (mq,
                    env);
    return;
  }

  if (GNUNET_YES == measure_rtt)
  {
    struct GNUNET_TIME_AbsoluteNBO *payload_nbo;
    struct GNUNET_TIME_Absolute payload;
    struct GNUNET_TIME_Relative rtt;
    size_t expected_size = sizeof (*message) + sizeof (struct GNUNET_TIME_AbsoluteNBO);

    if (! waiting_for_pong)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "received unexpected echo response, dropping.\n");
      return;
    }

    if (ntohs (message->size) != expected_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "received invalid ping response, dropping.\n");
      return;
    }

    payload_nbo = (struct GNUNET_TIME_AbsoluteNBO *) &message[1];
    payload = GNUNET_TIME_absolute_ntoh (*payload_nbo);

    if (payload.abs_value_us != echo_time.abs_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "received echo response after timeout, dropping.\n");
      return;
    }

    waiting_for_pong = GNUNET_NO;
    rtt = GNUNET_TIME_absolute_get_duration (payload);
    FPRINTF (stdout,
             "%d,%" PRId64 "\n",
             ping_count,
             rtt.rel_value_us);
    send_ping (mq);
    return;
  }
}


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  if (NULL != mh)
  {
    GNUNET_CORE_monitor_stop (mh);
    mh = NULL;
  }

  if (NULL != service_handle)
  {
    GNUNET_CORE_disconnect (service_handle);
    service_handle = NULL;
  }
}


/**
 * Function called to notify core users that another
 * peer changed its state with us.
 *
 * @param cls closure
 * @param peer the peer that changed state
 * @param state new state of the peer
 * @param timeout timeout for the new state
 */
static void
monitor_cb (void *cls,
            const struct GNUNET_PeerIdentity *peer,
            enum GNUNET_CORE_KxState state,
            struct GNUNET_TIME_Absolute timeout)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  const char *now_str;
  const char *state_str;

  //if ( ( (NULL == peer) ||
  //       (GNUNET_CORE_KX_ITERATION_FINISHED == state) ) &&
  //     (GNUNET_NO == monitor_connections) )
  //{
  //  GNUNET_SCHEDULER_shutdown ();
  //  return;
  //}

  switch (state)
  {
  case GNUNET_CORE_KX_STATE_DOWN:
    /* should never happen, as we immediately send the key */
    state_str = _("fresh connection");
    break;
  case GNUNET_CORE_KX_STATE_KEY_SENT:
    state_str = _("key sent");
    break;
  case GNUNET_CORE_KX_STATE_KEY_RECEIVED:
    state_str = _("key received");
    break;
  case GNUNET_CORE_KX_STATE_UP:
    state_str = _("connection established");
    break;
  case GNUNET_CORE_KX_STATE_REKEY_SENT:
    state_str = _("rekeying");
    break;
  case GNUNET_CORE_KX_PEER_DISCONNECT:
    state_str = _("disconnected");
    break;
  case GNUNET_CORE_KX_ITERATION_FINISHED:
    return;
  case GNUNET_CORE_KX_CORE_DISCONNECT:
    FPRINTF (stderr,
             "%s\n",
             _("Connection to CORE service lost (reconnecting)"));
    return;
  default:
    state_str = _("unknown state");
    break;
  }
  now_str = GNUNET_STRINGS_absolute_time_to_string (now);
  FPRINTF (stdout,
           _("%24s: %-30s %4s (timeout in %6s)\n"),
           now_str,
           state_str,
           GNUNET_i2s (peer),
           GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (timeout),
                                                   GNUNET_YES));
}


/**
 * Function called when a connection to a peer is lost.
 *
 * @param cls closure
 * @param peer the disconnected peer
 */
static void
peer_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity *peer, void *peer_cls)
{

}


/**
 * Function called when a connection to a peer is established.
 *
 * @param cls closure
 * @param peer the connected peer
 */
static void *
peer_connect_cb (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle* mq)
{
  if ( (GNUNET_YES == measure_rtt) &&
       (0 == memcmp (&peer_id,
                   peer,
                   sizeof (struct GNUNET_PeerIdentity))))
  {
    send_ping (mq); 
  }

  return mq;
}


/**
 * Function called after GNUNET_CORE_connect has succeeded (or failed for good). 
 *
 * @param cls closure
 * @param my_identity our peer id (or NULL if not connected)
 */
static void
service_startup_cb (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "could not connect to CORE service");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if ( (NULL != peer) &&
       (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_public_key_from_string (peer,
                                                    strlen (peer),
                                                    &peer_id.public_key)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "given peer id is invalid");
    return;
  }
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
  if (NULL != args[0])
  {
    FPRINTF (stderr,
             _("Invalid command line argument `%s'\n"),
             args[0]);
    return;
  }

  if (GNUNET_YES == monitor_connections)
  {
    mh = GNUNET_CORE_monitor_start (cfg,
                                    &monitor_cb,
                                    NULL);
    if (NULL == mh)
    {
      FPRINTF (stderr,
               "%s",
               _("Failed to connect to CORE service!\n"));
      return;
    }
  }

  if (GNUNET_YES == measure_rtt || GNUNET_YES == echo)
  {
    struct GNUNET_MQ_MessageHandler handlers[] = {
      GNUNET_MQ_hd_var_size (dummy,
                             GNUNET_MESSAGE_TYPE_DUMMY,
                             struct GNUNET_MessageHeader,
                             NULL),
      GNUNET_MQ_handler_end ()
    };

    service_handle = GNUNET_CORE_connect (cfg,
                                          NULL,
                                          service_startup_cb,
                                          peer_connect_cb,
                                          peer_disconnect_cb,
                                          handlers);
    if (NULL == service_handle)
    {
      FPRINTF (stderr,
               "%s",
               _("Failed to connect to CORE service!\n"));
      return;
    }
  }

  if (GNUNET_YES == measure_rtt)
  {
    ping_timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                                  ping_timeout_seconds);
    waiting_for_pong = GNUNET_NO;
  }

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * The main function to obtain peer information from CORE.
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
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('e',
                               "echo",
                               gettext_noop ("activate echo mode"),
                               &echo),

    GNUNET_GETOPT_option_flag ('m',
                                  "monitor",
                                  gettext_noop ("provide information about all current connections (continuously)"),
                                  &monitor_connections),

    GNUNET_GETOPT_option_uint ('n',
                                "count",
                                "COUNT",
                                gettext_noop ("number of RTT measurements"),
                                &ping_limit),

    GNUNET_GETOPT_option_flag ('r',
                               "measure-rtt",
                               gettext_noop ("measure round-trip time by sending packets to an echo-mode enabled peer"),
                               &measure_rtt),

    GNUNET_GETOPT_option_string ('p',
                                 "peer",
                                 "PEER",
                                 gettext_noop ("peer identity"),
                                 &peer),

    GNUNET_GETOPT_option_uint ('w',
                                "timeout",
                                "SECONDS",
                                gettext_noop ("timeout for each RTT measurement"),
                                &ping_timeout_seconds),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-core",
                            gettext_noop
                            ("Print information about connected peers."),
                            options, &run, NULL);

  GNUNET_free ((void *) argv);
  if (GNUNET_OK == res)
    return 0;
  return 1;
}

/* end of gnunet-core.c */

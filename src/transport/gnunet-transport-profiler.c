/*
 This file is part of GNUnet.
 (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * @file src/transport/gnunet-transport.c
 * @brief Tool to help configure, measure and control the transport subsystem.
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_nat_lib.h"


/**
 * Timeout for a connections
 */
#define CONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Benchmarking block size in bye
 */
#define DEFAULT_MESSAGE_SIZE 1024

/**
 * Benchmarking message count
 */
#define DEFAULT_MESSAGE_COUNT 1024

/**
 * Option -s.
 */
static int benchmark_send;

/**
 * Option -b.
 */
static int benchmark_receive;

/**
 * Option -n.
 */
static unsigned int benchmark_count;

/**
 * Option -m.
 */
static unsigned int benchmark_size;

/**
 * Which peer should we connect to?
 */
static char *cpid;

/**
 * Handle to transport service.
 */
static struct GNUNET_TRANSPORT_Handle *handle;

/**
 * Configuration handle
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Try_connect handle
 */
struct GNUNET_TRANSPORT_TryConnectHandle *tc_handle;



/**
 * Global return value (0 success).
 */
static int ret;
/**
 * Number of bytes of traffic we received so far.
 */
static unsigned long long traffic_received;

/**
 * Number of bytes of traffic we sent so far.
 */
static unsigned long long traffic_sent;

/**
 * Starting time of transmitting/receiving data.
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Handle for current transmission request.
 */
static struct GNUNET_TRANSPORT_TransmitHandle *th;

struct GNUNET_TRANSPORT_Blacklist *bl_handle;

/**
 * Identity of the peer we transmit to / connect to.
 * (equivalent to 'cpid' string).
 */
static struct GNUNET_PeerIdentity pid;

/**
 * Task scheduled for cleanup / termination of the process.
 */
static GNUNET_SCHEDULER_TaskIdentifier end;

/**
 * Task for operation timeout
 */
static GNUNET_SCHEDULER_TaskIdentifier op_timeout;

/**
 * Selected level of verbosity.
 */
static int verbosity;

/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative duration;

  end = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != op_timeout)
  {
    GNUNET_SCHEDULER_cancel (op_timeout);
    op_timeout = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != tc_handle)
  {
    GNUNET_TRANSPORT_try_connect_cancel (tc_handle);
    tc_handle = NULL;
  }
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (NULL != handle)
  {
    GNUNET_TRANSPORT_disconnect (handle);
    handle = NULL;
  }
  if (NULL != bl_handle )
  {
    GNUNET_TRANSPORT_blacklist_cancel (bl_handle);
    bl_handle = NULL;
  }
#if 0
  if (benchmark_send)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    FPRINTF (stdout,
             _("Transmitted %llu bytes/s (%llu bytes in %s)\n"),
             1000LL * 1000LL * traffic_sent / (1 + duration.rel_value_us),
             traffic_sent,
             GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_YES));
  }
  if (benchmark_receive)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    FPRINTF (stdout,
             _("Received %llu bytes/s (%llu bytes in %s)\n"),
             1000LL * 1000LL * traffic_received / (1 + duration.rel_value_us),
             traffic_received,
             GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_YES));
  }
#endif
}


static void
operation_timeout (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  op_timeout = GNUNET_SCHEDULER_NO_TASK;
  if ((benchmark_send) || (benchmark_receive))
  {
    FPRINTF (stdout,
             _("Failed to connect to `%s'\n"),
             GNUNET_i2s_full (&pid));
    if (GNUNET_SCHEDULER_NO_TASK != end)
      GNUNET_SCHEDULER_cancel (end);
    end = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    ret = 1;
    return;
  }
}


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  @a buf will be
 * NULL and @a size zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_data (void *cls,
               size_t size,
               void *buf)
{
  static  msgs_sent = 0;
  struct GNUNET_MessageHeader *m = buf;


  if ((NULL == buf) || (0 == size))
  {
    th = NULL;
    return 0;
  }

  msgs_sent ++;

  GNUNET_assert(size >= sizeof(struct GNUNET_MessageHeader));
  GNUNET_assert(size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  m->size = ntohs (size);
  m->type = ntohs (GNUNET_MESSAGE_TYPE_DUMMY);
  memset (&m[1], 52, size - sizeof(struct GNUNET_MessageHeader));
  traffic_sent += size;

  if (msgs_sent <benchmark_count)
  {
  th = GNUNET_TRANSPORT_notify_transmit_ready (handle, &pid,
                                               benchmark_size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &transmit_data, NULL);
  }
  else
  {
    if (verbosity > 0)
      FPRINTF (stdout, _("DONE!\n"));
    return size;
  }
  if (verbosity > 0)
    FPRINTF (stdout, _("Transmitting %u bytes to %s\n"), (unsigned int) size,
        GNUNET_i2s (&pid));
  return size;
}

static void
start_benchmark ()
{
  ret = 0;
  if (benchmark_send)
  {
    if (GNUNET_SCHEDULER_NO_TASK != op_timeout)
    {
      GNUNET_SCHEDULER_cancel (op_timeout);
      op_timeout = GNUNET_SCHEDULER_NO_TASK;
    }
    if (verbosity > 0)
      FPRINTF (stdout,
          _("Successfully connected to `%s', starting to send %u messages in %u byte blocks\n"),
          GNUNET_i2s (&pid), benchmark_count, benchmark_size);
    start_time = GNUNET_TIME_absolute_get ();
    if (NULL == th)
      th = GNUNET_TRANSPORT_notify_transmit_ready (handle, &pid, benchmark_size,
          GNUNET_TIME_UNIT_FOREVER_REL, &transmit_data, NULL );
    else
      GNUNET_break(0);
    return;
  }
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 */
static void
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer)
{
  if (0 != memcmp (&pid, peer, sizeof(struct GNUNET_PeerIdentity)))
  {
    FPRINTF (stdout,
        _("Connected to different peer `%s'\n"), GNUNET_i2s (&pid));
    return;
  }

  if (verbosity > 0)
    FPRINTF (stdout,
        _("Successfully connected to `%s'\n"),
        GNUNET_i2s (&pid));

  if (NULL != tc_handle)
  {
    GNUNET_TRANSPORT_try_connect_cancel (tc_handle);
    tc_handle = NULL;
  }

  start_benchmark ();
}


/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  if (0 != memcmp (&pid, peer, sizeof(struct GNUNET_PeerIdentity)))
    return;
  if (benchmark_send)
  {
    FPRINTF (stdout, _("Disconnected from peer `%s' while benchmarking\n"),
        GNUNET_i2s (&pid));
    if (GNUNET_SCHEDULER_NO_TASK != end)
      GNUNET_SCHEDULER_cancel (end);
    return;
  }
}

/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 */
static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  if (benchmark_receive)
  {
    if (GNUNET_MESSAGE_TYPE_DUMMY != ntohs (message->type))
      return;
    if (verbosity > 0)
      FPRINTF (stdout,
               _("Received %u bytes from %s\n"),
               (unsigned int) ntohs (message->size),
               GNUNET_i2s (peer));

    if (traffic_received == 0)
      start_time = GNUNET_TIME_absolute_get ();
    traffic_received += ntohs (message->size);
    return;
  }
}



static void
try_connect_cb (void *cls,
                const int result)
{
  static int retries = 0;

  if (GNUNET_OK == result)
  {
    tc_handle = NULL;
    return;
  }

  retries++;
  if (retries < 10)
  {
    if (verbosity > 0)
      FPRINTF (stdout, _("Retrying to connect to `%s'\n"), GNUNET_i2s (&pid));

    tc_handle = GNUNET_TRANSPORT_try_connect (handle, &pid, try_connect_cb,
        NULL);
  }
  else
  {
    FPRINTF (stderr,
             "%s",
             _("Failed to send connect request to transport service\n"));
    if (GNUNET_SCHEDULER_NO_TASK != end)
      GNUNET_SCHEDULER_cancel (end);
    ret = 1;
    end = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }
}

static int
blacklist_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (0 != memcmp (&pid, peer, sizeof(struct GNUNET_PeerIdentity)))
  {
    if (verbosity > 0)
      FPRINTF (stdout,
          _("Denying connection to `%s'\n"),
          GNUNET_i2s (&peer));
    return GNUNET_SYSERR;
  }

  if (verbosity > 0)
    FPRINTF (stdout,
        _("Permitting connection to `%s'\n"),
        GNUNET_i2s (&pid));
  return GNUNET_OK;
}



/**
 * Function called with the result of the check if the 'transport'
 * service is running.
 *
 * @param cls closure with our configuration
 * @param result #GNUNET_YES if transport is running
 */
static void
testservice_task (void *cls, int result)
{
  ret = 1;
#if 0
  if (GNUNET_YES != result)
  {
    FPRINTF (stderr, _("Service `%s' is not running\n"), "transport");
    return;
  }
#endif

  if (NULL == cpid)
  {
    FPRINTF (stderr, _("No peer identity given\n"));
    return;
  }
  if ((GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string (cpid, strlen (cpid),
              &pid.public_key)))
  {
    FPRINTF (stderr, _("Failed to parse peer identity `%s'\n"), cpid);
    return;
  }


  if (1 == benchmark_send)
  {
    FPRINTF (stderr,
        _("Trying to send %u messages with size %u to peer `%s'\n"),
          benchmark_count, benchmark_size, GNUNET_i2s (&pid));
  }
  else if (1 == benchmark_receive)
  {
    FPRINTF (stderr,
        _("Trying to receive messages from peer `%s'\n"),
        GNUNET_i2s (&pid));
  }
  else
  {
    FPRINTF (stderr, _("No operation given\n"));
    return;
  }

  handle = GNUNET_TRANSPORT_connect (cfg, NULL, NULL, &notify_receive,
      &notify_connect, &notify_disconnect);

  if (NULL == handle)
  {
    FPRINTF (stderr, "%s", _("Failed to connect to transport service\n"));
    ret = 1;
    return;
  }

  bl_handle = GNUNET_TRANSPORT_blacklist (cfg, blacklist_cb, NULL);
  tc_handle = GNUNET_TRANSPORT_try_connect(handle, &pid, try_connect_cb, NULL);

  end = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                      &shutdown_task,
                                      NULL);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param mycfg configuration
 */
static void
run (void *cls,
     char * const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *mycfg)
{
  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;
  GNUNET_CLIENT_service_test ("transport", cfg, GNUNET_TIME_UNIT_SECONDS,
      &testservice_task, (void *) cfg);
}

int
main (int argc, char * const *argv)
{
  int res;
  benchmark_count = DEFAULT_MESSAGE_COUNT;
  benchmark_size = DEFAULT_MESSAGE_SIZE;

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {

    { 's', "send", NULL,
      gettext_noop ("send data to peer"),
      0, &GNUNET_GETOPT_set_one, &benchmark_send},
    { 'r', "receive", NULL, gettext_noop
      ("receive data from peer"), 0,
      &GNUNET_GETOPT_set_one, &benchmark_receive},
    { 'n', "number", NULL, gettext_noop
      ("number of messages to send"), 1,
      &GNUNET_GETOPT_set_uint, &benchmark_count},
    { 'm', "messagesize", NULL, gettext_noop
      ("message size to use"), 1,
      &GNUNET_GETOPT_set_uint, &benchmark_size},
    { 'p', "peer", "PEER",
      gettext_noop ("peer identity"), 1, &GNUNET_GETOPT_set_string,
      &cpid },
    GNUNET_GETOPT_OPTION_VERBOSE (&verbosity),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv,
                            "gnunet-transport",
                            gettext_noop ("Direct access to transport service."),
                            options,
                            &run, NULL);
  GNUNET_free((void *) argv);
  if (GNUNET_OK == res)
    return ret;
  return 1;
}

/* end of gnunet-transport.c */

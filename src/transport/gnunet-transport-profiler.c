/*
 This file is part of GNUnet.
 Copyright (C) 2011-2016 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file src/transport/gnunet-transport-profiler.c
 * @brief Tool to help benchmark the transport subsystem.
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 * This utility can be used to benchmark a transport mechanism for
 * GNUnet.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"


struct Iteration
{
  struct Iteration *next;
  struct Iteration *prev;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute end;

  struct GNUNET_TIME_Relative dur;

  /* Transmission rate for this iteration in KB/s */
  float rate;

  unsigned int msgs_sent;
};


/**
 * Timeout for a connections
 */
#define CONNECT_TIMEOUT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Benchmarking block size in bye
 */
#define DEFAULT_MESSAGE_SIZE 1024

/**
 * Benchmarking message count
 */
#define DEFAULT_MESSAGE_COUNT 1024

/**
 * Benchmarking iteration count
 */
#define DEFAULT_ITERATION_COUNT 1

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
 * Option -i.
 */
static unsigned int benchmark_iterations;

/**
 * Option -m.
 */
static unsigned int benchmark_size;

/**
 * Benchmark running
 */
static unsigned int benchmark_running;

/**
 * Which peer should we connect to?
 */
static char *cpid;

/**
 * Handle to transport service.
 */
static struct GNUNET_TRANSPORT_CoreHandle *handle;

/**
 * Handle to ATS service.
 */
static struct GNUNET_ATS_ConnectivityHandle *ats;

/**
 * Configuration handle
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Try_connect handle
 */
static struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;

static struct Iteration *ihead;

static struct Iteration *itail;

/**
 * Global return value (0 success).
 */
static int ret;

/**
 * Handle for transmissions.
 */
static struct GNUNET_MQ_Handle *mq;

static struct GNUNET_TRANSPORT_Blacklist *bl_handle;

/**
 * Identity of the peer we transmit to / connect to.
 * (equivalent to 'cpid' string).
 */
static struct GNUNET_PeerIdentity pid;

/**
 * Selected level of verbosity.
 */
static unsigned int verbosity;


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  struct Iteration *icur;
  struct Iteration *inext;

  unsigned int iterations;

  unsigned long long avg_duration;
  float avg_rate;
  float stddev_rate;
  float stddev_duration;

  if (NULL != ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (ats_sh);
    ats_sh = NULL;
  }
  if (NULL != bl_handle)
  {
    GNUNET_TRANSPORT_blacklist_cancel (bl_handle);
    bl_handle = NULL;
  }
  if (NULL != ats)
  {
    GNUNET_ATS_connectivity_done (ats);
    ats = NULL;
  }
  if (NULL != handle)
  {
    GNUNET_TRANSPORT_core_disconnect (handle);
    handle = NULL;
  }

  if (verbosity > 0)
    FPRINTF (stdout, "\n");

  /* Output format:
   * All time values in ms
   * Rate in KB/s
   * #messages;#messagesize;#avg_dur;#avg_rate;#duration_i0;#duration_i0;... */

  if (benchmark_send)
  {
    /* First iteration to calculcate avg and stddev */
    iterations = 0;
    avg_duration = 0;
    avg_rate = 0.0;

    inext = ihead;
    while (NULL != (icur = inext))
    {
      inext = icur->next;
      icur->rate = ((benchmark_count * benchmark_size) / 1024) /
                   ((float) icur->dur.rel_value_us / (1000 * 1000));
      if (verbosity > 0)
        FPRINTF (stdout,
                 _ ("%llu B in %llu ms == %.2f KB/s!\n"),
                 ((long long unsigned int) benchmark_count * benchmark_size),
                 ((long long unsigned int) icur->dur.rel_value_us / 1000),
                 (float) icur->rate);

      avg_duration += icur->dur.rel_value_us / (1000);
      avg_rate += icur->rate;
      iterations++;
    }
    if (0 == iterations)
      iterations = 1; /* avoid division by zero */
    /* Calculate average rate */
    avg_rate /= iterations;
    /* Calculate average duration */
    avg_duration /= iterations;

    stddev_rate = 0;
    stddev_duration = 0;
    inext = ihead;
    while (NULL != (icur = inext))
    {
      inext = icur->next;
      stddev_rate += ((icur->rate - avg_rate) * (icur->rate - avg_rate));
      stddev_duration += (((icur->dur.rel_value_us / 1000) - avg_duration) *
                          ((icur->dur.rel_value_us / 1000) - avg_duration));
    }
    /* Calculate standard deviation rate */
    stddev_rate = stddev_rate / iterations;
    stddev_rate = sqrtf (stddev_rate);

    /* Calculate standard deviation duration */
    stddev_duration = stddev_duration / iterations;
    stddev_duration = sqrtf (stddev_duration);

    /* Output */
    FPRINTF (stdout,
             "%u;%u;%llu;%llu;%.2f;%.2f",
             benchmark_count,
             benchmark_size,
             avg_duration,
             (unsigned long long) stddev_duration,
             avg_rate,
             stddev_rate);

    inext = ihead;
    while (NULL != (icur = inext))
    {
      inext = icur->next;
      GNUNET_CONTAINER_DLL_remove (ihead, itail, icur);

      FPRINTF (stdout,
               ";%llu;%.2f",
               (long long unsigned int) (icur->dur.rel_value_us / 1000),
               icur->rate);

      GNUNET_free (icur);
    }
  }
#if 0
  if (benchmark_receive)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    FPRINTF (stdout,
             "Received %llu bytes/s (%llu bytes in %s)\n",
             1000LL * 1000LL * traffic_received / (1 + duration.rel_value_us),
             traffic_received,
             GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_YES));
  }
#endif
  FPRINTF (stdout, "\n");
}


static void
iteration_done ();


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
static void
send_msg (void *cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *m;

  if (NULL == mq)
    return;
  env = GNUNET_MQ_msg_extra (m, benchmark_size, GNUNET_MESSAGE_TYPE_DUMMY);
  memset (&m[1], 52, benchmark_size - sizeof (struct GNUNET_MessageHeader));

  if (itail->msgs_sent < benchmark_count)
  {
    GNUNET_MQ_notify_sent (env, &send_msg, NULL);
  }
  else
  {
    iteration_done ();
  }
  GNUNET_MQ_send (mq, env);
  if ((verbosity > 0) && (0 == itail->msgs_sent % 10))
    FPRINTF (stdout, ".");
}


static void
iteration_start ()
{
  struct Iteration *icur;

  ret = 0;
  if (! benchmark_send)
    return;
  benchmark_running = GNUNET_YES;
  icur = GNUNET_new (struct Iteration);
  GNUNET_CONTAINER_DLL_insert_tail (ihead, itail, icur);
  icur->start = GNUNET_TIME_absolute_get ();
  if (verbosity > 0)
    FPRINTF (
      stdout,
      "\nStarting benchmark, starting to send %u messages in %u byte blocks\n",
      benchmark_count,
      benchmark_size);
  send_msg (NULL);
}


static void
iteration_done ()
{
  static int it_count = 0;

  it_count++;
  itail->dur = GNUNET_TIME_absolute_get_duration (itail->start);
  if (it_count == benchmark_iterations)
  {
    benchmark_running = GNUNET_NO;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  iteration_start ();
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param m message queue for transmissions
 * @return NULL
 */
static void *
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_MQ_Handle *m)
{
  if (0 != memcmp (&pid, peer, sizeof (struct GNUNET_PeerIdentity)))
  {
    FPRINTF (stdout, "Connected to different peer `%s'\n", GNUNET_i2s (&pid));
    return NULL;
  }

  if (verbosity > 0)
    FPRINTF (stdout, "Successfully connected to `%s'\n", GNUNET_i2s (&pid));
  mq = m;
  iteration_start ();
  return NULL;
}


/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 * @param internal_cls NULL
 */
static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
                   void *internal_cls)
{
  if (0 != memcmp (&pid, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  mq = NULL;
  if (GNUNET_YES == benchmark_running)
  {
    FPRINTF (stdout,
             "Disconnected from peer `%s' while benchmarking\n",
             GNUNET_i2s (&pid));
    return;
  }
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param message the message
 * @return #GNUNET_OK
 */
static int
check_dummy (void *cls, const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK; /* all messages are fine */
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param message the message
 */
static void
handle_dummy (void *cls, const struct GNUNET_MessageHeader *message)
{
  if (! benchmark_receive)
    return;
  if (verbosity > 0)
    FPRINTF (stdout,
             "Received %u bytes\n",
             (unsigned int) ntohs (message->size));
}


static int
blacklist_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  if (0 != memcmp (&pid, peer, sizeof (struct GNUNET_PeerIdentity)))
  {
    if (verbosity > 0)
      FPRINTF (stdout, "Denying connection to `%s'\n", GNUNET_i2s (peer));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *mycfg)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
    {GNUNET_MQ_hd_var_size (dummy,
                            GNUNET_MESSAGE_TYPE_DUMMY,
                            struct GNUNET_MessageHeader,
                            NULL),
     GNUNET_MQ_handler_end ()};

  cfg = (struct GNUNET_CONFIGURATION_Handle *) mycfg;

  ret = 1;
  if (GNUNET_MAX_MESSAGE_SIZE <= benchmark_size)
  {
    FPRINTF (stderr, "Message size too big!\n");
    return;
  }

  if (NULL == cpid)
  {
    FPRINTF (stderr, "No peer identity given\n");
    return;
  }
  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string (cpid,
                                                               strlen (cpid),
                                                               &pid.public_key))
  {
    FPRINTF (stderr, "Failed to parse peer identity `%s'\n", cpid);
    return;
  }
  if (1 == benchmark_send)
  {
    if (verbosity > 0)
      FPRINTF (stderr,
               "Trying to send %u messages with size %u to peer `%s'\n",
               benchmark_count,
               benchmark_size,
               GNUNET_i2s (&pid));
  }
  else if (1 == benchmark_receive)
  {
    FPRINTF (stderr,
             "Trying to receive messages from peer `%s'\n",
             GNUNET_i2s (&pid));
  }
  else
  {
    FPRINTF (stderr, "No operation given\n");
    return;
  }

  ats = GNUNET_ATS_connectivity_init (cfg);
  if (NULL == ats)
  {
    FPRINTF (stderr, "Failed to connect to ATS service\n");
    ret = 1;
    return;
  }

  handle = GNUNET_TRANSPORT_core_connect (cfg,
                                          NULL,
                                          handlers,
                                          NULL,
                                          &notify_connect,
                                          &notify_disconnect,
                                          NULL);
  if (NULL == handle)
  {
    FPRINTF (stderr, "Failed to connect to transport service\n");
    GNUNET_ATS_connectivity_done (ats);
    ats = NULL;
    ret = 1;
    return;
  }

  bl_handle = GNUNET_TRANSPORT_blacklist (cfg, &blacklist_cb, NULL);
  ats_sh = GNUNET_ATS_connectivity_suggest (ats, &pid, 1);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


int
main (int argc, char *const *argv)
{
  int res;
  benchmark_count = DEFAULT_MESSAGE_COUNT;
  benchmark_size = DEFAULT_MESSAGE_SIZE;
  benchmark_iterations = DEFAULT_ITERATION_COUNT;
  benchmark_running = GNUNET_NO;

  struct GNUNET_GETOPT_CommandLineOption options[] = {

    GNUNET_GETOPT_option_flag ('s',
                               "send",
                               gettext_noop ("send data to peer"),
                               &benchmark_send),
    GNUNET_GETOPT_option_flag ('r',
                               "receive",
                               gettext_noop ("receive data from peer"),
                               &benchmark_receive),
    GNUNET_GETOPT_option_uint ('i',
                               "iterations",
                               NULL,
                               gettext_noop ("iterations"),
                               &benchmark_iterations),
    GNUNET_GETOPT_option_uint ('n',
                               "number",
                               NULL,
                               gettext_noop ("number of messages to send"),
                               &benchmark_count),
    GNUNET_GETOPT_option_uint ('m',
                               "messagesize",
                               NULL,
                               gettext_noop ("message size to use"),
                               &benchmark_size),
    GNUNET_GETOPT_option_string ('p',
                                 "peer",
                                 "PEER",
                                 gettext_noop ("peer identity"),
                                 &cpid),
    GNUNET_GETOPT_option_verbose (&verbosity),
    GNUNET_GETOPT_OPTION_END};

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res =
    GNUNET_PROGRAM_run (argc,
                        argv,
                        "gnunet-transport",
                        gettext_noop ("Direct access to transport service."),
                        options,
                        &run,
                        NULL);
  GNUNET_free ((void *) argv);
  if (GNUNET_OK == res)
    return ret;
  return 1;
}

/* end of gnunet-transport-profiler.c */

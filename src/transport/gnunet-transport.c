/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */

#include "platform.h"
#include "gnunet_program_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"

/**
 * Which peer should we connect to?
 */
static char *cpid;

/**
 * Handle to transport service.
 */
static struct GNUNET_TRANSPORT_Handle *handle;

/**
 * Option -s.
 */
static int benchmark_send;

/**
 * Option -b.
 */
static int benchmark_receive;

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
 * Selected level of verbosity.
 */
static int verbosity;



/**
 * Shutdown, print statistics.
 */
static void
do_disconnect (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative duration;

  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  GNUNET_TRANSPORT_disconnect (handle);
  if (benchmark_receive)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    fprintf (stderr,
	     _("Received %llu bytes/s (%llu bytes in %llu ms)\n"),
	     1000 * traffic_received / (1+duration.rel_value),
	     traffic_received,
	     (unsigned long long) duration.rel_value);
  }
  if (benchmark_send)
  {
    duration = GNUNET_TIME_absolute_get_duration (start_time);
    fprintf (stderr,
	     _("Transmitted %llu bytes/s (%llu bytes in %llu ms)\n"),
	     1000 * traffic_sent / (1+duration.rel_value),
	     traffic_sent,
	     (unsigned long long) duration.rel_value);
  }
}


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_data (void *cls, size_t size,
	       void *buf)
{
  struct GNUNET_MessageHeader *m = buf;

  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  GNUNET_assert (size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  m->size = ntohs (size);
  m->type = ntohs (GNUNET_MESSAGE_TYPE_DUMMY);
  memset (&m[1], 52, size - sizeof (struct GNUNET_MessageHeader));
  traffic_sent += size;
  th = GNUNET_TRANSPORT_notify_transmit_ready (handle,
					       &pid,
					       32 * 1024,
					       0,
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       &transmit_data, NULL);
  if (verbosity > 0)
    fprintf (stderr,
	     _("Transmitting %u bytes to %s\n"),
	     (unsigned int) size,
	     GNUNET_i2s (&pid));
  return size;
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
notify_connect (void *cls,
		const struct GNUNET_PeerIdentity
		* peer,
		const struct
		GNUNET_ATS_Information
		* ats, uint32_t ats_count)
{
  if (verbosity > 0)
    fprintf (stderr,
	     _("Connected to %s\n"),
	     GNUNET_i2s (peer));
  if (0 != memcmp (&pid,
		   peer,
		   sizeof (struct GNUNET_PeerIdentity)))
    return;
  ret = 0;
  if (benchmark_send) 
  {
    start_time = GNUNET_TIME_absolute_get ();
    th = GNUNET_TRANSPORT_notify_transmit_ready (handle,
						 peer,
						 32 * 1024,
						 0,
						 GNUNET_TIME_UNIT_FOREVER_REL,
						 &transmit_data, NULL);
  }
  else
  {
    /* all done, terminate instantly */
    GNUNET_SCHEDULER_cancel (end);
    end = GNUNET_SCHEDULER_add_now (&do_disconnect,
				    NULL);    
  }  
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
		   const struct
		   GNUNET_PeerIdentity * peer)
{
  if (verbosity > 0)
    fprintf (stderr,
	     _("Disconnected from %s\n"),
	     GNUNET_i2s (peer));
  if ( (0 == memcmp (&pid,
		     peer,
		     sizeof (struct GNUNET_PeerIdentity))) &&
       (NULL != th) )
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
    GNUNET_SCHEDULER_cancel (end);
    end = GNUNET_SCHEDULER_add_now (&do_disconnect,
				    NULL);    
  }
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 * @param ats performance data
 * @param ats_count number of entries in ats 
 */
static void
notify_receive (void *cls,
		const struct
		GNUNET_PeerIdentity * peer,
		const struct
		GNUNET_MessageHeader *
		message,
		const struct
		GNUNET_ATS_Information
		* ats, uint32_t ats_count)
{
  if (! benchmark_receive)
    return;
  if (verbosity > 0)
    fprintf (stderr,
	     _("Received %u bytes from %s\n"),
	     (unsigned int) ntohs (message->size),
	     GNUNET_i2s (peer));
  if (traffic_received == 0)
    start_time = GNUNET_TIME_absolute_get ();
  traffic_received += ntohs (message->size);
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
  if (benchmark_send && (NULL == cpid))
  {
    fprintf (stderr, _("Option `%s' makes no sense without option `%s'.\n"),
	     "-s", "-C");
    return;
  }
  if (NULL != cpid)
  {
    ret = 1;
    if (GNUNET_OK !=
	GNUNET_CRYPTO_hash_from_string (cpid, &pid.hashPubKey))
    {
      fprintf (stderr,
	       _("Failed to parse peer identity `%s'\n"),
	       cpid);
      return;
    }
    handle = GNUNET_TRANSPORT_connect (cfg, NULL, NULL,
				       &notify_receive, 
				       &notify_connect,
				       &notify_disconnect);
    GNUNET_TRANSPORT_try_connect (handle, &pid);
    end = GNUNET_SCHEDULER_add_delayed (benchmark_send
					? GNUNET_TIME_UNIT_FOREVER_REL
					: GNUNET_TIME_UNIT_SECONDS,
					&do_disconnect,
					NULL);    
  } else if (benchmark_receive)
  {
    handle = GNUNET_TRANSPORT_connect (cfg, NULL, NULL,
				       &notify_receive, 
				       &notify_connect,
				       &notify_disconnect);
    GNUNET_TRANSPORT_try_connect (handle, &pid);
    end = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
					&do_disconnect,
					NULL); 
  }
}


int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'b', "benchmark", NULL,
     gettext_noop ("measure how fast we are receiving data (until CTRL-C)"),
     0, &GNUNET_GETOPT_set_one, &benchmark_receive},
    {'C', "connect", "PEER",
     gettext_noop ("try to connect to the given peer"),
     1, &GNUNET_GETOPT_set_string, &cpid},
    {'s', "send", NULL,
     gettext_noop ("send data for benchmarking to the other peer (until CTRL-C)"),
     0, &GNUNET_GETOPT_set_one, &benchmark_send},  
    GNUNET_GETOPT_OPTION_VERBOSE(&verbosity),
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-transport",
                              gettext_noop ("Direct access to transport service."),
                              options, &run, NULL)) ? ret : 1;
}


/* end of gnunet-transport.c */

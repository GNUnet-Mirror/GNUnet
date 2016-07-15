/*
     This file is part of GNUnet.x
     Copyright (C) 2009, 2010, 2016 GNUnet e.V.

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
 * @file transport/test_transport_api_timeout.c
 * @brief test case for transport plugin implementations complying timeout
 * settings
 *
 *
 * This test case serves ensures that no peer disconnect events occurs
 * while plugins are idle
 */

#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)

#define MTYPE 12345

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TIME_Relative time_running;

static struct GNUNET_SCHEDULER_Task *timer_task;

static int shutdown_flag;

static unsigned int disconnects;


static void
custom_shutdown (void *cls)
{
  if (NULL != timer_task)
  {
    GNUNET_SCHEDULER_cancel (timer_task);
    timer_task = NULL;
  }
  if (0 == disconnects)
  {
    ccc->global_ret = GNUNET_OK;
  }
  else
  {
    ccc->global_ret =- GNUNET_SYSERR;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Fail! Had %u disconnects while waiting %s\n",
                disconnects,
		GNUNET_STRINGS_relative_time_to_string (WAIT,
							GNUNET_YES));
  }
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %d from peer %s!\n",
              ntohs (message->type),
	      GNUNET_i2s (sender));
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (shutdown_flag != GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "FAIL! Peer `%s' disconnected during waiting period!\n",
                GNUNET_i2s (other));
    disconnects++;
  }
}


static void
timer (void *cls)
{
  static unsigned int percentage;

  timer_task = NULL;
  percentage += 10;
  time_running = GNUNET_TIME_relative_add (time_running,
					   GNUNET_TIME_relative_divide (WAIT,
									10));

  if (time_running.rel_value_us ==
      GNUNET_TIME_relative_max (time_running, WAIT).rel_value_us)
  {
    FPRINTF (stderr, "%s",  "100%%\n");
    shutdown_flag = GNUNET_YES;
    GNUNET_SCHEDULER_shutdown ();
  }
  else
  {
    FPRINTF (stderr,
	     "%u%%..",
	     percentage);
    timer_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (WAIT, 10),
                                      &timer,
				      NULL);
  }
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &timer,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };

  ccc = &my_ccc;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}

/* end of test_transport_api_timeout.c*/

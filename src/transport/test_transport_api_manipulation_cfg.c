/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2016 GNUnet e.V.

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
 * @file transport/test_transport_api_manipulation_cfg.c
 * @brief base test case for transport traffic manipulation implementation
 * based on cfg
 *
 * Peer 1 has inbound and outbound delay of 100ms
 * Peer 2 has no inbound and outbound delay
 *
 * We send a request from P1 to P2 and expect delay of >= TEST_DELAY us
 * Then we send response from P2 to P1 and expect delay of >= TEST_DELAY us
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)


#define TEST_MESSAGE_SIZE 2600

#define TEST_RESPONSE_MESSAGE_TYPE 

/**
 * Test delay, in microseconds.
 */
#define TEST_DELAY 100 * 1000LL


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TIME_Absolute start_request;

static struct GNUNET_TIME_Absolute start_response;


static void
sendtask_response_task (void *cls)
{
  int ret;
  
  start_response = GNUNET_TIME_absolute_get();
  ret = GNUNET_TRANSPORT_TESTING_send (ccc->p[1],
				       ccc->p[0],
				       GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE2,
				       TEST_MESSAGE_SIZE,
				       1,
				       NULL,
				       NULL);
  if (GNUNET_NO == ret)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (GNUNET_SYSERR != ret);
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  struct GNUNET_TIME_Relative duration;

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%s') received message of type %d and size %u size from peer %s)!\n",
                receiver->no,
                ps,
                ntohs (message->header.type),
                ntohs (message->header.size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }

  switch (ntohs (message->header.type)) {
  case GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE:
    duration = GNUNET_TIME_absolute_get_difference (start_request,
						    GNUNET_TIME_absolute_get());
    if (duration.rel_value_us >= TEST_DELAY)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Request message was delayed for %s\n",
                  GNUNET_STRINGS_relative_time_to_string (duration,
                                                          GNUNET_YES));
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Request message was delayed for unexpected duration %s\n",
                  GNUNET_STRINGS_relative_time_to_string (duration,
                                                          GNUNET_YES));
      ccc->global_ret = GNUNET_SYSERR;
      GNUNET_SCHEDULER_shutdown ();
    }
    /* Send response */
    GNUNET_SCHEDULER_add_now (&sendtask_response_task,
			      NULL);
    return;
  case GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE2:
    duration = GNUNET_TIME_absolute_get_difference(start_response,
                                                   GNUNET_TIME_absolute_get());
    if (duration.rel_value_us >= TEST_DELAY)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Response message was delayed for %s\n",
                  GNUNET_STRINGS_relative_time_to_string (duration,
                                                          GNUNET_YES));
      ccc->global_ret = GNUNET_OK;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Response message was delayed for unexpected duration %s\n",
                  GNUNET_STRINGS_relative_time_to_string (duration,
                                                          GNUNET_YES));
      ccc->global_ret = GNUNET_SYSERR;
    }
    GNUNET_SCHEDULER_shutdown ();
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = 1
  };
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &GNUNET_TRANSPORT_TESTING_large_send,
    .connect_continuation_cls = &sc,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
    .timeout = TIMEOUT
  };

  ccc = &my_ccc;
  sc.ccc = ccc;
  start_request = GNUNET_TIME_absolute_get ();
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}


/* end of test_transport_api_manipulation_cfg.c */

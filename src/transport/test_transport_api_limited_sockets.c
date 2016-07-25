/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 GNUnet e.V.

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
 * @file transport/test_transport_api_limited_sockets.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp, udp, and udp-nat
 * transport test cases.  Based on the executable being run
 * the correct test case will be performed.  Conservation of
 * C code apparently.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define MAX_FILES 50


#if HAVE_SETRLIMIT

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;


static void
notify_receive (void *cls, 
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %d from peer %s!\n",
              ntohs (message->header.type),
	      GNUNET_i2s (sender));
  if ( (GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE ==
	ntohs (message->header.type)) &&
       (sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage) ==
	ntohs (message->header.size)) )
  {
    ccc->global_ret = GNUNET_OK;
  }
  else
  {
    GNUNET_break (0);
  }
  GNUNET_SCHEDULER_shutdown ();
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = 1
  };
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &GNUNET_TRANSPORT_TESTING_simple_send,
    .connect_continuation_cls = &sc,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
    .timeout = TIMEOUT,
    .global_ret = GNUNET_SYSERR
  };
  struct rlimit r_file_old;
  struct rlimit r_file_new;
  int res;

  sc.ccc = &my_ccc;
  res = getrlimit (RLIMIT_NOFILE,
		   &r_file_old);
  r_file_new.rlim_cur = MAX_FILES;
  r_file_new.rlim_max = r_file_old.rlim_max;
  res = setrlimit (RLIMIT_NOFILE,
		   &r_file_new);
  if (0 != res)
  {
    fprintf (stderr,
	     "Setting limit failed: %s\n",
	     strerror (errno));
    return 77;
  }

  ccc = &my_ccc;
  ccc->global_ret = GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}

#else
/* cannot setrlimit */


int
main (int argc, char *argv[])
{
  fprintf (stderr,
	   "Cannot run test on this system\n");
  return 77;
}

#endif

/* end of test_transport_api_limited_sockets.c */

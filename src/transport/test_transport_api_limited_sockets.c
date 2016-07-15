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

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define MTYPE 12345

#define MAX_FILES 50


#if HAVE_SETRLIMIT

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;


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
  if ((MTYPE == ntohs (message->type)) &&
      (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size)))
  {
    ccc->global_ret = GNUNET_OK;
  }
  else
  {
    GNUNET_break (0);
  }
  GNUNET_SCHEDULER_shutdown ();
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  struct GNUNET_MessageHeader *hdr;

  th = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting message with %u bytes to peer %s\n",
              (unsigned int) sizeof (struct GNUNET_MessageHeader),
              GNUNET_i2s (&p->id));
  GNUNET_assert (size >= 256);
  if (buf != NULL)
  {
    hdr = buf;
    hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
    hdr->type = htons (MTYPE);
  }
  return sizeof (struct GNUNET_MessageHeader);
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


static void
custom_shutdown (void *cls)
{
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


static void
sendtask (void *cls)
{
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[0]->th,
					       &ccc->p[1]->id,
					       256,
					       TIMEOUT,
                                               &notify_ready,
					       ccc->p[0]);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };
  struct rlimit r_file_old;
  struct rlimit r_file_new;
  int res;
  
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
  fprintf (stderr, "Cannot run test on this system\n");
  return 0;
}

#endif

/* end of test_transport_api_limited_sockets.c */

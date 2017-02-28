/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2009, 2010, 2017 GNUnet e.V.

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
 * @file peerinfo/perf_peerinfo_api.c
 * @brief testcase for peerinfo_api.c, hopefully hammer the peerinfo service,
 * this performance test adds up to 5000 peers with one address each and checks
 * over how many peers it can iterate before receiving a timeout after 5 seconds
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_peerinfo_service.h"
#include "peerinfo.h"
#include <gauger.h>

#define NUM_REQUESTS 5000

static struct GNUNET_PEERINFO_IteratorContext *ic[NUM_REQUESTS];

static struct GNUNET_PEERINFO_Handle *h;

static unsigned int numpeers;

static struct GNUNET_PeerIdentity pid;

static struct GNUNET_SCHEDULER_Task *tt;


static void
do_shutdown (void *cls)
{
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
  for (unsigned int i = 0; i < NUM_REQUESTS; i++)
    if (NULL != ic[i])
      GNUNET_PEERINFO_iterate_cancel (ic[i]);
  GNUNET_PEERINFO_disconnect (h);
  h = NULL;
}


static void
do_timeout (void *cls)
{
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


static int
check_it (void *cls,
          const struct GNUNET_HELLO_Address *address,
          struct GNUNET_TIME_Absolute expiration)
{
  return GNUNET_OK;
}


static ssize_t
address_generator (void *cls, size_t max, void *buf)
{
  size_t *agc = cls;
  ssize_t ret;
  char *caddress;
  struct GNUNET_HELLO_Address address;

  if (*agc == 0)
    return GNUNET_SYSERR; /* Done */

  GNUNET_asprintf (&caddress, "Address%d", *agc);
  address.peer = pid;
  address.address_length = strlen (caddress) + 1;
  address.address = caddress;
  address.transport_name = "peerinfotest";
  ret =
      GNUNET_HELLO_add_address (&address,
                                GNUNET_TIME_relative_to_absolute
                                (GNUNET_TIME_UNIT_HOURS), buf, max);
  GNUNET_free (caddress);
  *agc = 0;
  return ret;
}


static void
add_peer (size_t i)
{
  struct GNUNET_HELLO_Message *h2;

  memset (&pid, i, sizeof (pid));
  h2 = GNUNET_HELLO_create (&pid.public_key,
                            &address_generator,
                            &i,
                            GNUNET_NO);
  GNUNET_PEERINFO_add_peer (h, h2, NULL, NULL);
  GNUNET_free (h2);
}


static void
process (void *cls,
         const struct GNUNET_PeerIdentity *peer,
         const struct GNUNET_HELLO_Message *hello,
         const char *err_msg)
{
  struct GNUNET_PEERINFO_IteratorContext **icp = cls;

  if (NULL == peer)
  {
    *icp = NULL;
    return;
  }
  numpeers++;
  if (0 && (NULL != hello) )
    GNUNET_HELLO_iterate_addresses (hello,
                                    GNUNET_NO,
                                    &check_it,
                                    NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  h = GNUNET_PEERINFO_connect (cfg);
  GNUNET_assert (h != NULL);
  for (unsigned int i = 0; i < NUM_REQUESTS; i++)
  {
    add_peer (i);
    ic[i] = GNUNET_PEERINFO_iterate (h,
                                     GNUNET_YES,
                                     NULL,
                                     &process,
                                     &ic[i]);
  }
  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                                                    5),
                                     &do_timeout,
                                     NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
}


int
main (int argc,
      char *argv[])
{
  if (0 != GNUNET_TESTING_service_run ("perf-gnunet-peerinfo",
				       "peerinfo",
				       "test_peerinfo_api_data.conf",
				       &run, NULL))
    return 1;
  FPRINTF (stderr,
           "Received %u/%u calls before timeout\n",
           numpeers,
	   NUM_REQUESTS * NUM_REQUESTS / 2);
  GAUGER ("PEERINFO",
          "Peerinfo lookups",
          numpeers / 5,
          "peers/s");
  return 0;
}

/* end of perf_peerinfo_api.c */

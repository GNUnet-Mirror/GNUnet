/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_api_scheduling_destroy_address.c
 * @brief test destroying addresses in automatic transport selection scheduling API
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib-new.h"
#include "ats.h"
#include "test_ats_api_common.h"

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier wait_task;

#define WAIT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Scheduling handle
 */
static struct GNUNET_ATS_SchedulingHandle *sched_ats;

/**
 * Return value
 */
static int ret;

/**
 * Test address
 */
static struct Test_Address test_addr;

/**
 * Test peer
 */
static struct PeerContext p;

/**
 * HELLO address
 */
struct GNUNET_HELLO_Address hello_address;


static void
create_test_address (struct Test_Address *dest, char * plugin, void *session, void *addr, size_t addrlen)
{

  dest->plugin = GNUNET_strdup (plugin);
  dest->session = session;
  dest->addr = GNUNET_malloc (addrlen);
  memcpy (dest->addr, addr, addrlen);
  dest->addr_len = addrlen;
}

static void
free_test_address (struct Test_Address *dest)
{
  GNUNET_free (dest->plugin);
  GNUNET_free (dest->addr);
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  if (sched_ats != NULL)
    GNUNET_ATS_scheduling_done (sched_ats);
  free_test_address (&test_addr);
  ret = GNUNET_SYSERR;
}


static void
end ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down\n");
  wait_task = GNUNET_SCHEDULER_NO_TASK;
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  free_test_address (&test_addr);
  GNUNET_ATS_scheduling_done (sched_ats);
  sched_ats = NULL;
}

static void
address_suggest_cb (void *cls, const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{
  static int stage = 0;
  int res = 0;

  if (0 ==stage)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage 0: Received suggestion for peer `%s'\n",
                GNUNET_i2s(&address->peer));

    if (0 != memcmp (&address->peer, &p.id, sizeof (struct GNUNET_PeerIdentity)))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid peer id'\n");
        res = 1;
    }
    else if (0 != strcmp (address->transport_name, test_addr.plugin))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid plugin'\n");
        res = 1;
    }
    else if (address->address_length != test_addr.addr_len)
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address length'\n");
        res = 1;
    }
    else if (0 != memcmp (address->address, test_addr.plugin, address->address_length))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address'\n");
        res = 1;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for correct address `%s'\n",
                  GNUNET_i2s (&address->peer));
      res = 0;
    }
    GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
    if (1 == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Callback for invalid address `%s'\n",
                  GNUNET_i2s (&address->peer));
      GNUNET_SCHEDULER_add_now (&end, NULL);
      ret = 1;
    }
    stage ++;
    ret = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying address for `%s'\n",
                GNUNET_i2s (&address->peer));
    /* Destroying address */
    GNUNET_ATS_address_destroyed (sched_ats, &hello_address, test_addr.session);
    /* Request address */
    GNUNET_ATS_suggest_address (sched_ats, &p.id);
    wait_task = GNUNET_SCHEDULER_add_delayed (WAIT_TIMEOUT, &end, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage 1: Unexpected address suggestion\n");
  ret = 1;

}


static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* Connect to ATS scheduling */
  sched_ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    ret = 1;
    end ();
    return;
  }

  /* Set up peer */
  if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string(PEERID, &p.id.hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
      ret = GNUNET_SYSERR;
      end ();
      return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s_full(&p.id));

  create_test_address (&test_addr, "test", NULL, "test", strlen ("test") + 1);

  /* Adding address without session */
  hello_address.peer = p.id;
  hello_address.transport_name = test_addr.plugin;
  hello_address.address = test_addr.addr;
  hello_address.address_length = test_addr.addr_len;
  GNUNET_ATS_address_add (sched_ats, &hello_address, test_addr.session, NULL, 0);

  /* Request address */
  GNUNET_ATS_suggest_address (sched_ats, &p.id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_scheduling_add_address",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_scheduling_destroy_address.c */

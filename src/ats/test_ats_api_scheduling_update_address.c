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
 * @file ats/test_ats_api_scheduling_update_address.c
 * @brief test updating an address: add address, get and compare it, update it
 *        get it again and compre
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib-new.h"
#include "ats.h"
#include "test_ats_api_common.h"

static GNUNET_SCHEDULER_TaskIdentifier die_task;

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
 * HELLO test address
 */

struct GNUNET_HELLO_Address test_hello_address;

/**
 * Test session
 */
static void *test_session;

/**
 * Test ats info
 */
struct GNUNET_ATS_Information test_ats_info[2];

/**
 * Test ats count
 */
uint32_t test_ats_count;


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
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_ATS_scheduling_done (sched_ats);
  sched_ats = NULL;
  free_test_address (&test_addr);
}


static int
compare_addresses (const struct GNUNET_HELLO_Address *address1, void *session1,
                   const struct GNUNET_HELLO_Address *address2, void *session2)
{
  if (0 != memcmp (&address1->peer, &address2->peer, sizeof (struct GNUNET_PeerIdentity)))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid peer id'\n");
      return GNUNET_SYSERR;
  }
  if (0 != strcmp (address1->transport_name, address2->transport_name))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid plugin'\n");
      return GNUNET_SYSERR;
  }
  if (address1->address_length != address2->address_length)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address length'\n");
      return GNUNET_SYSERR;

  }
  else if (0 != memcmp (address1->address, address2->address, address2->address_length))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid address'\n");
      return GNUNET_SYSERR;
  }
  if (session1 != session2)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Suggestion with invalid session1 %p vs session2 %p'\n",
                  session1, session2);
      return GNUNET_SYSERR;

  }
  return GNUNET_OK;
}

static int
compare_ats (const struct GNUNET_ATS_Information *ats_is, uint32_t ats_count_is,
             const struct GNUNET_ATS_Information *ats_should, uint32_t ats_count_should)
{
  unsigned int c_o;
  unsigned int c_i;
  char *prop[] = GNUNET_ATS_PropertyStrings;
  uint32_t type1;
  uint32_t type2;
  uint32_t val1;
  uint32_t val2;
  int res = GNUNET_OK;

  for (c_o = 0; c_o < ats_count_is; c_o++)
  {
    for (c_i = 0; c_i < ats_count_should; c_i++)
    {
        type1 = ntohl(ats_is[c_o].type);
        type2 = ntohl(ats_should[c_i].type);
        if (type1 == type2)
        {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS type `%s'\n",
                        prop[type1]);
            val1 = ntohl(ats_is[c_o].value);
            val2 = ntohl(ats_should[c_i].value);
            if (val1 != val2)
            {
                GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ATS value `%s' not equal: %u != %u\n",
                            prop[type1],
                            val1, val2);
                res = GNUNET_SYSERR;
            }
            else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS value `%s' equal: %u == %u\n",
                          prop[type1],
                          val1, val2);
            }
        }
    }
  }
  return res;
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
  if (0 == stage)
  {
    GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
    if (GNUNET_OK == compare_addresses(address, session, &test_hello_address, test_session))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage 0: Callback for correct address `%s'\n",
                  GNUNET_i2s (&address->peer));
      ret = 0;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage 0: Callback with incorrect address `%s'\n",
                    GNUNET_i2s (&address->peer));
      ret = 1;
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }

    if (GNUNET_OK != compare_ats(atsi, ats_count, test_ats_info, test_ats_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage 0: Callback with incorrect ats info \n");
      ret = 1;
      GNUNET_SCHEDULER_add_now (&end, NULL);
      return;
    }

    /* Update address */

    /* Request address */
    GNUNET_ATS_suggest_address (sched_ats, &p.id);
    stage ++;
  }
  else if (1 == stage)
  {
      GNUNET_ATS_suggest_address_cancel (sched_ats, &p.id);
      if (GNUNET_OK == compare_addresses(address, session, &test_hello_address, test_session))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stage 1: Callback with correct address `%s'\n",
                    GNUNET_i2s (&address->peer));
        ret = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Stage 1: Callback with incorrect address `%s'\n",
                    GNUNET_i2s (&address->peer));
        ret = 1;
      }

      GNUNET_SCHEDULER_add_now (&end, NULL);
  }
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

  GNUNET_assert (0 == strcmp (PEERID, GNUNET_i2s_full (&p.id)));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s_full(&p.id));

  /* Prepare ATS Information */
  test_ats_info[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  test_ats_info[0].value = htonl(GNUNET_ATS_NET_WAN);
  test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  test_ats_info[1].value = htonl(1);
  test_ats_count = 2;

  /* Adding address without session */
  test_session = &test_addr;
  create_test_address (&test_addr, "test", &test_addr, "test", strlen ("test") + 1);
  test_hello_address.peer = p.id;
  test_hello_address.transport_name = test_addr.plugin;
  test_hello_address.address = test_addr.addr;
  test_hello_address.address_length = test_addr.addr_len;
  GNUNET_ATS_address_add (sched_ats, &test_hello_address, test_session, test_ats_info, test_ats_count);

  /* Request address */
  GNUNET_ATS_suggest_address (sched_ats, &p.id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_scheduling_update_address",
                                    "test_ats_api.conf",
                                    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_scheduling_update_address.c */

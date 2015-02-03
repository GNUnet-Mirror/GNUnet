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
 * @file ats/test_ats_api_bandwidth_consumption.c
 * @brief test automatic transport selection scheduling API
 * @author Christian Grothoff
 * @author Matthias Wachs

 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "ats.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct GNUNET_SCHEDULER_Task * die_task;

static struct GNUNET_SCHEDULER_Task * consume_task;

static struct GNUNET_ATS_SchedulingHandle *ats;

static struct GNUNET_ATS_PerformanceHandle *atp;

/**
 * Connectivity handle
 */
static struct GNUNET_ATS_ConnectivityHandle *connect_ats;

static struct GNUNET_ATS_ReservationContext *sh;

static struct PeerContext *p;

static uint32_t bw_in;

static uint32_t bw_out;

static int ret;

struct Address
{
  char *plugin;

  size_t plugin_len;

  void *addr;

  size_t addr_len;

  struct GNUNET_ATS_Information *ats;

  int ats_count;

  void *session;
};

struct PeerContext
{
  struct GNUNET_PeerIdentity id;

  struct Address *addr;
};


static void
end ()
{
  if (NULL != connect_ats)
  {
    GNUNET_ATS_connectivity_done (connect_ats);
    connect_ats = NULL;
  }
  if (die_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }
  if (consume_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (consume_task);
    consume_task = NULL;
  }
  if (sh != NULL)
  {
    GNUNET_ATS_reserve_bandwidth_cancel (sh);
    sh = NULL;
  }
  if (ats != NULL)
  {
    GNUNET_ATS_scheduling_done (ats);
    ats = NULL;
  }
  if (atp != NULL)
  {
    GNUNET_ATS_performance_done (atp);
    atp = NULL;
  }
  GNUNET_free (p->addr);
  GNUNET_free (p);
  p = NULL;
  ret = 0;
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;
  end ();
  ret = GNUNET_SYSERR;
}


static void
performance_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                const char *plugin_name, const void *plugin_addr,
                size_t plugin_addr_len,
                struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{

}


static void
reservation_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                int32_t amount, struct GNUNET_TIME_Relative res_delay)
{
  sh = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS reserved bandwidth of %i to peer `%s' in %llu ms\n", amount,
              GNUNET_i2s (peer), res_delay.rel_value);
}


static void
consume_bandwidth (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  consume_task = NULL;
  int32_t to_reserve = 500;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to reserver bandwidth of %i to peer `%s' in %llu ms\n",
              to_reserve, GNUNET_i2s (&p->id));

  sh = GNUNET_ATS_reserve_bandwidth (atp, &p->id, to_reserve, &reservation_cb,
                                     NULL);
}


static void
address_suggest_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const char *plugin_name, const void *plugin_addr,
                    size_t plugin_addr_len, struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *ats,
                    uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS suggested address for peer `%s'\n",
              GNUNET_i2s (peer));

  bw_in = ntohl (bandwidth_in.value__);
  bw_out = ntohl (bandwidth_out.value__);

  consume_task = GNUNET_SCHEDULER_add_now (&consume_bandwidth, NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct Address *addr;

  ret = GNUNET_SYSERR;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  connect_ats = GNUNET_ATS_connectivity_init (mycfg);

  ats = GNUNET_ATS_scheduling_init (cfg, &address_suggest_cb, NULL);
  if (ats == NULL)
  {
    ret = GNUNET_SYSERR;
    end ();
    return;
  }
  p = GNUNET_new (struct PeerContext);
  addr = GNUNET_new (struct Address);

  atp = GNUNET_ATS_performance_init (cfg, NULL, NULL);
  if (atp == NULL)
  {
    ret = GNUNET_SYSERR;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to init ATS performance\n");
    end_badly (NULL, NULL);
    GNUNET_free (p);
    GNUNET_free (addr);
    return;
  }

  /* set up peer */
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                    &p->id.hashPubKey);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s (&p->id));
  p->addr = addr;
  addr->plugin = "test";
  addr->session = NULL;
  addr->addr = NULL;
  addr->addr_len = 0;

  GNUNET_ATS_address_update (ats, &p->id, addr->plugin, addr->addr,
                             addr->addr_len, addr->session, NULL, 0);

  GNUNET_ATS_connectivity_suggest (connect_ats, &p->id);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test_ats_api_bandwidth_consumption",
				    "test_ats_api.conf",
				    &run, NULL))
    return 1;
  return ret;
}

/* end of file test_ats_api_bandwidth_consumption.c */

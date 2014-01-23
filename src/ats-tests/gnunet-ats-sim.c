/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats-test/gnunet-ats-sim.c
 * @brief ats traffic simulator: this tool uses the ats-test library to setup a
 * topology and generate traffic between these peers. The traffic description
 * is loaded from a experiment description file
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "ats-testing.h"

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct BenchmarkPeer *masters_p;
static struct BenchmarkPeer *slaves_p;

struct Experiment *e;


static void
evaluate ()
{
  int c_m;
  int c_s;
  unsigned int duration;
  struct BenchmarkPeer *mp;
  struct BenchmarkPartner *p;

  unsigned int kb_sent_sec;
  double kb_sent_percent;
  unsigned int kb_recv_sec;
  double kb_recv_percent;
  unsigned int rtt;

  duration = (TEST_TIMEOUT.rel_value_us / (1000 * 1000));
  for (c_m = 0; c_m < e->num_masters; c_m++)
  {
    mp = &masters_p[c_m];
    fprintf (stderr,
        _("Master [%u]: sent: %u KiB in %u sec. = %u KiB/s, received: %u KiB in %u sec. = %u KiB/s\n"),
        mp->no, mp->total_bytes_sent / 1024, duration,
        (mp->total_bytes_sent / 1024) / duration,
        mp->total_bytes_received / 1024, duration,
        (mp->total_bytes_received / 1024) / duration);

    for (c_s = 0; c_s < e->num_slaves; c_s++)
    {
      p = &mp->partners[c_s];

      kb_sent_sec = 0;
      kb_recv_sec = 0;
      kb_sent_percent = 0.0;
      kb_recv_percent = 0.0;
      rtt = 0;

      if (duration > 0)
      {
          kb_sent_sec = (p->bytes_sent / 1024) / duration;
          kb_recv_sec = (p->bytes_received / 1024) / duration;
      }

      if (mp->total_bytes_sent > 0)
          kb_sent_percent = ((double) p->bytes_sent * 100) / mp->total_bytes_sent;
      if (mp->total_bytes_received > 0)
          kb_recv_percent = ((double) p->bytes_received * 100) / mp->total_bytes_received;
      if (1000 * p->messages_sent > 0)
          rtt = p->total_app_rtt / (1000 * p->messages_sent);
      fprintf (stderr,
          "%c Master [%u] -> Slave [%u]: sent %u KiB/s (%.2f %%), received %u KiB/s (%.2f %%)\n",
          (mp->pref_partner == p->dest) ? '*' : ' ',
          mp->no, p->dest->no,
          kb_sent_sec, kb_sent_percent,
                  kb_recv_sec, kb_recv_percent);
      fprintf (stderr,
          "%c Master [%u] -> Slave [%u]: Average application layer RTT: %u ms\n",
          (mp->pref_partner == p->dest) ? '*' : ' ',
          mp->no, p->dest->no, rtt);
    }
  }
}

static void
do_shutdown ()
{
  /* Shutdown a topology with */
  evaluate ();
  GNUNET_ATS_TEST_shutdown_topology ();
}

static void
transport_recv_cb (void *cls,
                   const struct GNUNET_PeerIdentity * peer,
                   const struct GNUNET_MessageHeader * message)
{

}

static void
ats_performance_info_cb (void *cls, const struct GNUNET_HELLO_Address *address,
    int address_active, struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{

}

static void topology_setup_done (void *cls,
    struct BenchmarkPeer *masters,
    struct BenchmarkPeer *slaves)
{
  int c_m;
  int c_s;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Topology setup complete!\n");

  masters_p = masters;
  slaves_p = slaves;

  for (c_m = 0; c_m < e->num_masters; c_m++)
  {
      for (c_s = 0; c_s < e->num_slaves; c_s++)
      {
        /* Generate maximum traffic to all peers */
        fprintf (stderr, "c_m %u c_s %u\n", c_m, c_s);
        GNUNET_ATS_TEST_generate_traffic_start (&masters[c_m],
            &masters[c_m].partners[c_s],
            10000,
            GNUNET_TIME_UNIT_FOREVER_REL);
      }
  }
  GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &do_shutdown, NULL);
}


int
main (int argc, char *argv[])
{
  if (argc < 2)
  {
    fprintf (stderr, "No experiment given...\n");
    return 1;
  }

  fprintf (stderr, "Loading experiment `%s' \n", argv[1]);
  e = GNUNET_ATS_TEST_experimentation_start (argv[1]);
  if (NULL == e)
  {
    fprintf (stderr, "Invalid experiment\n");
    return 1;
  }

  fprintf (stderr, "%llu %llu\n", e->num_masters, e->num_slaves);

  /* Setup a topology with */
  GNUNET_ATS_TEST_create_topology ("gnunet-ats-sim", e->cfg_file,
      e->num_slaves,
      e->num_masters,
      GNUNET_NO,
      &topology_setup_done,
      NULL,
      &transport_recv_cb,
      &ats_performance_info_cb);
  return 0;
}
/* end of file gnunet-ats-sim.c */

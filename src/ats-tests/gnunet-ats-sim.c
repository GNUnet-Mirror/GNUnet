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
 * @file ats/perf_ats.c
 * @brief ats benchmark: start peers and modify preferences, monitor change over time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "ats-testing.h"

#define DEFAULT_NUM_SLAVES 5
#define DEFAULT_NUM_MASTERS 1

#define TEST_MESSAGE_TYPE_PING 12345
#define TEST_MESSAGE_TYPE_PONG 12346

static int c_masters;

static int c_slaves;

static int
core_handle_pong (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  return 0;
}

static int
core_handle_ping (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  return 0;
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Topology setup complete!\n");
  GNUNET_ATS_TEST_shutdown_topology ();
}

int
main (int argc, char *argv[])
{
  static struct GNUNET_CORE_MessageHandler handlers[] = {
      {&core_handle_ping, TEST_MESSAGE_TYPE_PING, 0 },
      {&core_handle_pong, TEST_MESSAGE_TYPE_PONG, 0 },
      { NULL, 0, 0 } };

  c_slaves = DEFAULT_NUM_SLAVES;
  c_masters = DEFAULT_NUM_MASTERS;

  GNUNET_ATS_TEST_create_topology ("gnunet-ats-sim", "perf_ats_proportional_none.conf",
      c_slaves,
      c_masters,
      GNUNET_YES,
      &topology_setup_done,
      NULL,
      handlers,
      &transport_recv_cb,
      &ats_performance_info_cb);
  return 0;
}
/* end of file perf_ats_topogy.c */

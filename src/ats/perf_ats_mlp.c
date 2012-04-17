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
 * @file ats/perf_ats_mlp
 * @brief performance test for the MLP solver
 * @author Christian Grothoff
 * @author Matthias Wachs

 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-ats_addresses_mlp.h"

#define VERBOSE GNUNET_YES
#define VERBOSE_ARM GNUNET_NO

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX

#define DEF_PEERS 10
#define DEF_ADDRESSES_PER_PEER 5

static unsigned int peers;
static unsigned int addresses;

struct PeerContext *p;
struct ATS_Address *a;

static int ret;

struct GNUNET_STATISTICS_Handle * stats;

struct GNUNET_CONTAINER_MultiHashMap * amap;

struct GAS_MLP_Handle *mlp;

struct GNUNET_STATISTICS_Handle * stats;

struct GNUNET_OS_Process *stats_proc;

GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

struct PeerContext
{
  struct GNUNET_PeerIdentity id;

  struct Address *addr;
};

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

void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int ca;
  for (ca=0; ca < (peers * addresses); ca++)
  {
    GNUNET_free (a[ca].plugin);
    GNUNET_free (a[ca].ats);
  }
  GNUNET_CONTAINER_multihashmap_destroy(amap);
  GNUNET_free (a);
  GNUNET_free (p);
  GNUNET_STATISTICS_destroy(stats,GNUNET_NO);

  if (NULL != stats_proc)
  {
    if (0 != GNUNET_OS_process_kill (stats_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    if (GNUNET_OS_process_wait (stats_proc) != GNUNET_OK)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    GNUNET_OS_process_close (stats_proc);
    stats_proc = NULL;
  }
  ret = 0;
}

int stat_it (void *cls, const char *subsystem,
                                           const char *name, uint64_t value,
                                           int is_persistent)
{
  static int calls;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s : %llu\n", name, value);
  calls ++;

  if (2 == calls)
  {
    if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
      GNUNET_SCHEDULER_cancel(shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now(&do_shutdown, NULL);
  }
  return GNUNET_OK;
}

static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "GLPK not installed!");
  ret = 1;
  return;
#endif
  unsigned int c = 0;
  unsigned int c2 = 0;
  unsigned int ca = 0;

  stats_proc = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-statistics",
        "gnunet-service-statistics", NULL);

  if (NULL == stats_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to start statistics service \n");
    ret = 1;
    return;
  }

  shutdown_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_HOURS, &do_shutdown, NULL);

  if (peers == 0)
    peers = DEF_PEERS;
  if (addresses == 0)
    addresses = DEF_ADDRESSES_PER_PEER;

  p = GNUNET_malloc (peers * sizeof (struct ATS_Peer));
  a = GNUNET_malloc (peers * addresses * sizeof (struct ATS_Address));

  stats = GNUNET_STATISTICS_create("ats", cfg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up %u peers with %u addresses per peer\n", peers, addresses);

  amap = GNUNET_CONTAINER_multihashmap_create(addresses * peers);

  mlp = GAS_mlp_init (cfg, stats, MLP_MAX_EXEC_DURATION, MLP_MAX_ITERATIONS);
  mlp->auto_solve = GNUNET_NO;
  for (c=0; c < peers; c++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up peer %u\n", c);
    GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &p[c].id.hashPubKey);

    for (c2=0; c2 < addresses; c2++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up address %u for peer %u\n", c2, c);
      /* Setting required information */
      a[ca].mlp_information = NULL;
      a[ca].prev = NULL;
      a[ca].next = NULL;

      /* Setting address */
      a[ca].peer = p[c].id;
      a[ca].plugin = strdup("test");
      a[ca].atsp_network_type = GNUNET_ATS_NET_LOOPBACK;

      a[ca].ats = GNUNET_malloc (2 * sizeof (struct GNUNET_ATS_Information));
      a[ca].ats[0].type = GNUNET_ATS_QUALITY_NET_DELAY;
      a[ca].ats[0].value = 20;
      a[ca].ats[1].type = GNUNET_ATS_QUALITY_NET_DISTANCE;
      a[ca].ats[1].value = 2;
      a[ca].ats_count = 2;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up address %u\n", ca);
      GNUNET_CONTAINER_multihashmap_put (amap, &a[ca].peer.hashPubKey, &a[ca], GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      GAS_mlp_address_update(mlp, amap, &a[ca]);
      ca++;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Problem contains %u peers and %u adresses\n", mlp->c_p, mlp->addr_in_problem);

  GNUNET_assert (peers == mlp->c_p);
  GNUNET_assert (peers * addresses == mlp->addr_in_problem);

  /* Solving the problem */
  if (GNUNET_OK == GAS_mlp_solve_problem(mlp))
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Problem solved successfully \n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Problem solved failed \n");



  GAS_mlp_done (mlp);

  GNUNET_STATISTICS_get (stats, "ats", "# LP execution time (ms)", GNUNET_TIME_UNIT_MINUTES, NULL, &stat_it, NULL);
  GNUNET_STATISTICS_get (stats, "ats", "# MLP execution time (ms)", GNUNET_TIME_UNIT_MINUTES, NULL, &stat_it, NULL);
  return;
}


int
main (int argc, char *argv[])
{

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "addresses", NULL,
     gettext_noop ("addresses per peer"), 1,
     &GNUNET_GETOPT_set_uint, &addresses},
    {'p', "peers", NULL,
     gettext_noop ("peers"), 1,
     &GNUNET_GETOPT_set_uint, &peers},
    GNUNET_GETOPT_OPTION_END
  };


  GNUNET_PROGRAM_run (argc, argv,
                      "perf_ats_mlp", "nohelp", options,
                      &check, NULL);


  return ret;
}

/* end of file perf_ats_mlp.c */

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

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX

#define DEF_PEERS 10
#define DEF_ADDRESSES_PER_PEER 5
#define DEF_ATS_VALUES 2
#define DEF_ATS_MAX_DELAY 30
#define DEF_ATS_MAX_DISTANCE 3

static unsigned int peers;
static unsigned int addresses;
static unsigned int numeric;
static unsigned int update_percentage;

static int start;
static int end;

struct ATS_Peer *p;
struct ATS_Address *a;

static int ret;

static struct GNUNET_CONTAINER_MultiHashMap * amap;

static struct GAS_MLP_Handle *mlp;




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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown\n");

  if (NULL != mlp)
  {
    GAS_mlp_done (mlp);
    mlp = NULL;
  }

  if (NULL != a)
  {
    for (ca=0; ca < (peers * addresses); ca++)
    {
      GNUNET_free (a[ca].plugin);
      GNUNET_free (a[ca].ats);
    }
  }

  if (NULL != amap)
    GNUNET_CONTAINER_multihashmap_destroy(amap);
  GNUNET_free_non_null (a);
  GNUNET_free_non_null (p);

}

static void
update_addresses (struct ATS_Address * a, unsigned int addrs, unsigned int percentage)
{
  if (percentage == 0)
    return;

  unsigned int ua = (addrs) * ((float) percentage / 100);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Updating %u of %u addresses per peer\n", ua, addrs);

  unsigned int updated[addrs];
  unsigned int u_types[DEF_ATS_VALUES];
  unsigned int updates = 0;
  unsigned int u_type = 0;
  unsigned int u_val = 0;
  unsigned int cur = 0;

  u_types[0] = 0;
  u_types[1] = 0;

  for (cur = 0; cur < addrs; cur ++)
  {
    updated[cur] = 0;
  }
  cur = 0;

  while (updates < ua)
  {
    cur = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, addrs);
    if (0 == updated[cur])
    {
      u_type = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, DEF_ATS_VALUES);
      switch (u_type) {
        case 0:
            do
            {
            u_val = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, DEF_ATS_MAX_DELAY);
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating DELAY from %u to %u\n",a[cur].ats[u_type].value, u_val);
            }
            while (a[cur].ats[u_type].value == u_val);
          break;
        case 1:
          do
          {
            u_val = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, DEF_ATS_MAX_DISTANCE);
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating DISTANCE from %u to %u\n",a[cur].ats[u_type].value, u_val);
          }
          while (a[cur].ats[u_type].value == u_val);
          break;
        default:
          GNUNET_break (0);
          break;
      }
      u_types[u_type]++;

      a[cur].ats[u_type].value = u_val;
      updated[cur] = 1;
      GAS_mlp_address_update(mlp, amap, &a[cur]);
      updates++;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Updated %u delay and %u distance values\n", u_types[0], u_types[1]);

}


static void
check (void *cls, char *const *args, const char *cfgfile,
       const  struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned int c = 0;
  unsigned int c2 = 0;
  unsigned int ca = 0;
  int update = GNUNET_NO;
  int range = GNUNET_NO;
  int res;

#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "GLPK not installed!");
  ret = 1;
  return;
#endif

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up %u peers with %u addresses per peer\n", peers, addresses);

  mlp = GAS_mlp_init (cfg, NULL, MLP_MAX_EXEC_DURATION, MLP_MAX_ITERATIONS);
  if (NULL == mlp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to init MLP\n");
    ret = 1;
    if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
      GNUNET_SCHEDULER_cancel(shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }

  if (peers == 0)
    peers = DEF_PEERS;
  if (addresses == 0)
    addresses = DEF_ADDRESSES_PER_PEER;

  p = GNUNET_malloc (peers * sizeof (struct ATS_Peer));
  a = GNUNET_malloc (peers * addresses * sizeof (struct ATS_Address));

  amap = GNUNET_CONTAINER_multihashmap_create(addresses * peers);

  mlp->auto_solve = GNUNET_NO;
  if (start == 0)
      start = 0;
  if (end == 0)
      end = -1;
  if ((start != -1) && (end != -1))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Solving problem starting from %u to %u\n", start , end);
    range = GNUNET_YES;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Solving problem for %u peers\n", peers);

  if ((update_percentage >= 0) && (update_percentage <= 100))
  {
    update = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Benchmarking with existing presolution and %u%% updated addresses\n", update_percentage);
  }
  else if ((update_percentage > 100) && (update_percentage != UINT_MAX))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Invalid percentage: %u\n", update_percentage);
    ret = 1;
    return;
  }

  for (c=0; c < peers; c++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up peer %u\n", c);
    GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_NONCE, &p[c].id.hashPubKey);

    for (c2=0; c2 < addresses; c2++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up address %u for peer %u\n", c2, c);
      /* Setting required information */
      a[ca].mlp_information = NULL;
      a[ca].prev = NULL;
      a[ca].next = NULL;

      /* Setting address */
      a[ca].peer = p[c].id;
      a[ca].plugin = GNUNET_strdup("test");
      a[ca].atsp_network_type = GNUNET_ATS_NET_LOOPBACK;

      a[ca].ats = GNUNET_malloc (DEF_ATS_VALUES * sizeof (struct GNUNET_ATS_Information));
      a[ca].ats[0].type = GNUNET_ATS_QUALITY_NET_DELAY;
      a[ca].ats[0].value = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, DEF_ATS_MAX_DELAY);
      a[ca].ats[1].type = GNUNET_ATS_QUALITY_NET_DISTANCE;
      a[ca].ats[1].value = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, DEF_ATS_MAX_DISTANCE);
      a[ca].ats_count = 2;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting up address %u\n", ca);
      GNUNET_CONTAINER_multihashmap_put (amap, &a[ca].peer.hashPubKey, &a[ca], GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      GAS_mlp_address_update(mlp, amap, &a[ca]);
      ca++;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Problem contains %u peers and %u adresses\n", mlp->c_p, mlp->addr_in_problem);

    if (((GNUNET_YES == range) && (((start >= 0) && ((c+1) >= start)) && (c <= end))) || ((c+1) == peers))
    {
      GNUNET_assert ((c+1) == mlp->c_p);
      GNUNET_assert ((c+1) * addresses == mlp->addr_in_problem);

      /* Solving the problem */
      struct GAS_MLP_SolutionContext ctx;

      res = GAS_mlp_solve_problem(mlp, &ctx);

      if (GNUNET_NO == update)
      {
        if (GNUNET_OK == res)
        {
          GNUNET_assert (GNUNET_OK == ctx.lp_result);
          GNUNET_assert (GNUNET_OK == ctx.mlp_result);
          if (GNUNET_YES == numeric)
            printf ("%u;%u;%llu;%llu\n",mlp->c_p, mlp->addr_in_problem, (unsigned long long) ctx.lp_duration.rel_value, (unsigned long long) ctx.mlp_duration.rel_value);
          else
            GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Problem solved for %u peers with %u address successfully (LP: %llu ms / MLP: %llu ms)\n",
                mlp->c_p, mlp->addr_in_problem, ctx.lp_duration.rel_value, ctx.mlp_duration.rel_value);
        }
        else
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Solving problem with %u peers and %u addresses failed\n", c, c2);
      }
      else
      {
        struct GAS_MLP_SolutionContext uctx;
        /* Update addresses */
        update_addresses (a, (c+1) * c2, update_percentage);

        /* Solve again */
        res = GAS_mlp_solve_problem(mlp, &uctx);

        if (GNUNET_OK == res)
        {
          GNUNET_assert (GNUNET_OK == uctx.lp_result);
          GNUNET_assert (GNUNET_OK == uctx.mlp_result);
          if (GNUNET_YES == numeric)
            printf ("%u;%u;%llu;%llu;%llu;%llu\n",mlp->c_p, mlp->addr_in_problem,
                (unsigned long long) ctx.lp_duration.rel_value, (unsigned long long) ctx.mlp_duration.rel_value,
                (unsigned long long) uctx.lp_duration.rel_value, (unsigned long long) uctx.mlp_duration.rel_value);
          else
            GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Updated problem solved for %u peers with %u address successfully (Initial: LP/MLP: %llu/%llu ms, Update: %llu/%llu ms)\n",
                mlp->c_p, mlp->addr_in_problem,
                (unsigned long long) ctx.lp_duration.rel_value, (unsigned long long) ctx.mlp_duration.rel_value,
                (unsigned long long) uctx.lp_duration.rel_value, (unsigned long long) uctx.mlp_duration.rel_value);
        }
        else
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Solving updated problem with %u peers and %u addresses failed\n", c, c2);
      }
    }
  }

  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel(shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);

}


int
main (int argc, char *argv[])
{
  /* Init invalid */
  update_percentage = UINT_MAX;
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "addresses", NULL,
     gettext_noop ("addresses per peer"), 1,
     &GNUNET_GETOPT_set_uint, &addresses},
    {'p', "peers", NULL,
     gettext_noop ("peers"), 1,
     &GNUNET_GETOPT_set_uint, &peers},
     {'n', "numeric", NULL,
      gettext_noop ("numeric output only"), 0,
      &GNUNET_GETOPT_set_one, &numeric},
    {'e', "end", NULL,
     gettext_noop ("end solving problem"), 1,
     &GNUNET_GETOPT_set_uint, &end},
   {'s', "start", NULL,
    gettext_noop ("start solving problem"), 1,
    &GNUNET_GETOPT_set_uint, &start},
    {'u', "update", NULL,
     gettext_noop ("benchmark with existing solution (address updates)"), 1,
     &GNUNET_GETOPT_set_uint, &update_percentage},
    GNUNET_GETOPT_OPTION_END
  };


  GNUNET_PROGRAM_run (argc, argv,
                      "perf_ats_mlp", "nohelp", options,
                      &check, NULL);


  return ret;
}

/* end of file perf_ats_mlp.c */

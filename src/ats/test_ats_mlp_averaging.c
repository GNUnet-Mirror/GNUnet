/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_mlp.c
 * @brief test for the MLP solver
 * @author Christian Grothoff
 * @author Matthias Wachs

 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_addresses_mlp.h"

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX


static int ret;

struct GNUNET_STATISTICS_Handle *stats;

struct GNUNET_CONTAINER_MultiPeerMap *addresses;

struct GAS_MLP_Handle *mlp;


static void
create_address (struct ATS_Address *addr, char * plugin, int ats_count, struct GNUNET_ATS_Information *ats)
{
  addr->solver_information = NULL;
  addr->next = NULL;
  addr->prev = NULL;
  addr->plugin = GNUNET_strdup (plugin);
  addr->ats_count = ats_count;
  addr->ats = ats;
}

static void
set_ats (struct GNUNET_ATS_Information *ats, uint32_t type, uint32_t value)
{
  ats->type = type;
  ats->value = value;
}

static unsigned int
load_quotas (const struct GNUNET_CONFIGURATION_Handle *cfg, unsigned long long *out_dest, unsigned long long *in_dest, int dest_length)
{
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  char * entry_in = NULL;
  char * entry_out = NULL;
  char * quota_out_str;
  char * quota_in_str;
  int c;

  for (c = 0; (c < GNUNET_ATS_NetworkTypeCount) && (c < dest_length); c++)
  {
    in_dest[c] = 0;
    out_dest[c] = 0;
    switch (quotas[c]) {
      case GNUNET_ATS_NET_UNSPECIFIED:
        entry_out = "UNSPECIFIED_QUOTA_OUT";
        entry_in = "UNSPECIFIED_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_LOOPBACK:
        entry_out = "LOOPBACK_QUOTA_OUT";
        entry_in = "LOOPBACK_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_LAN:
        entry_out = "LAN_QUOTA_OUT";
        entry_in = "LAN_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_WAN:
        entry_out = "WAN_QUOTA_OUT";
        entry_in = "WAN_QUOTA_IN";
        break;
      case GNUNET_ATS_NET_WLAN:
        entry_out = "WLAN_QUOTA_OUT";
        entry_in = "WLAN_QUOTA_IN";
        break;
      default:
        break;
    }

    if ((entry_in == NULL) || (entry_out == NULL))
      continue;

    /* quota out */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      if (0 == strcmp(quota_out_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &out_dest[c])))
        out_dest[c] = UINT32_MAX;

      GNUNET_free (quota_out_str);
      quota_out_str = NULL;
    }
    else if (GNUNET_ATS_NET_UNSPECIFIED == quotas[c])
      out_dest[c] = UINT32_MAX;
    else
      out_dest[c] = UINT32_MAX;

    /* quota in */
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      if (0 == strcmp(quota_in_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &in_dest[c])))
        in_dest[c] = UINT32_MAX;

      GNUNET_free (quota_in_str);
      quota_in_str = NULL;
    }
    else if (GNUNET_ATS_NET_UNSPECIFIED == quotas[c])
    {
      in_dest[c] = UINT32_MAX;
    }
    else
    {
        in_dest[c] = UINT32_MAX;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loaded quota: %s %u, %s %u\n", entry_in, in_dest[c], entry_out, out_dest[c]);

  }
  return GNUNET_ATS_NetworkTypeCount;
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
  struct ATS_Address addr[10];
  struct ATS_Address *res[10];
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  unsigned long long  quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long  quotas_out[GNUNET_ATS_NetworkTypeCount];
  int quota_count;
  // struct MLP_information *mlpi;
  struct GAS_MLP_SolutionContext ctx;

  stats = GNUNET_STATISTICS_create("ats", cfg);

  addresses = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);

  quota_count = load_quotas(cfg, quotas_in, quotas_out, GNUNET_ATS_NetworkTypeCount);
  mlp = GAS_mlp_init (cfg, NULL, quotas, quotas_in, quotas_out, quota_count);
  mlp->auto_solve = GNUNET_NO;

  struct GNUNET_PeerIdentity p[10];

  /* Creating peer 1 */
  GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &p[0].hashPubKey);

  /* Creating peer 1 address 1 */
  addr[0].peer.hashPubKey = p[0].hashPubKey;
  struct GNUNET_ATS_Information a1_ats[3];
  set_ats (&a1_ats[0], GNUNET_ATS_QUALITY_NET_DISTANCE, 1);
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 0);
  set_ats (&a1_ats[2], GNUNET_ATS_ARRAY_TERMINATOR, 0);
  create_address (&addr[0], "dummy", 3, &a1_ats[0]);
  addr[0].atsp_network_type = GNUNET_ATS_NET_LAN;

  GNUNET_CONTAINER_multipeermap_put(addresses, &addr[0].peer, &addr[0], GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  /* Add peer 1 address 1 */
  GAS_mlp_address_update (mlp, addresses, &addr[0]);
  // mlpi = addr[0].mlp_information;

  GNUNET_assert (mlp != NULL);
  GNUNET_assert (mlp->addresses_in_problem == 1);

  /* Update an peer 1 address 1  */
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 20);
  GAS_mlp_address_update (mlp, addresses, &addr[0]);
  GNUNET_assert (mlp->addresses_in_problem == 1);


  /* Update an peer 1 address 1  */
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 10);
  GAS_mlp_address_update (mlp, addresses, &addr[0]);
  GNUNET_assert (mlp->addresses_in_problem == 1);

  /* Update an peer 1 address 1  */
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 10);
  GAS_mlp_address_update (mlp, addresses, &addr[0]);
  GNUNET_assert (mlp->addresses_in_problem == 1);

  /* Update an peer 1 address 1  */
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 30);
  GAS_mlp_address_update (mlp, addresses, &addr[0]);
  GNUNET_assert (mlp->addresses_in_problem == 1);


  GNUNET_assert (GNUNET_OK == GAS_mlp_solve_problem(mlp, &ctx));
  GNUNET_assert (GNUNET_OK == ctx.lp_result);
  GNUNET_assert (GNUNET_OK == ctx.mlp_result);

  res[0] = GAS_mlp_get_preferred_address(mlp, addresses, &p[0]);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Preferred address `%s' outbound bandwidth: %u Bps\n",
              res[0]->plugin,
              (unsigned int) ntohl (res[0]->assigned_bw_out.value__));

  /* Delete an address */
  GNUNET_CONTAINER_multipeermap_remove (addresses, &addr[0].peer, &addr[0]);
  GAS_mlp_address_delete (mlp, addresses, &addr[0]);

  GNUNET_assert (mlp->addresses_in_problem == 0);

  GAS_mlp_done (mlp);

  GNUNET_free (addr[0].plugin);
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
  GNUNET_STATISTICS_destroy(stats, GNUNET_NO);

  ret = 0;
}


int
main (int argc, char *argv[])
{

  static char *const argv2[] = { "test_ats_mlp",
    "-c",
    "test_ats_api.conf",
    "-L", "WARNING",
    NULL
  };

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_ats_mlp_averaging", "nohelp", options,
                      &check, NULL);


  return ret;
}

/* end of file test_ats_mlp_averaging.c */

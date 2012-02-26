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

#define VERBOSE GNUNET_YES
#define VERBOSE_ARM GNUNET_NO

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX


static int ret;

struct GNUNET_STATISTICS_Handle * stats;

struct GNUNET_CONTAINER_MultiHashMap * addresses;

struct GAS_MLP_Handle *mlp;


static void
create_address (struct ATS_Address *addr, char * plugin, int ats_count, struct GNUNET_ATS_Information *ats)
{
  addr->mlp_information = NULL;
  addr->next = NULL;
  addr->prev = NULL;
  addr->plugin = strdup (plugin);
  addr->ats_count = ats_count;
  addr->ats = ats;
}

static void
set_ats (struct GNUNET_ATS_Information *ats, uint32_t type, uint32_t value)
{
  ats->type = type;
  ats->value = value;
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
  struct ATS_PreferedAddress *res[10];

  stats = GNUNET_STATISTICS_create("ats", cfg);

  addresses = GNUNET_CONTAINER_multihashmap_create (10);

  mlp = GAS_mlp_init (cfg, NULL, MLP_MAX_EXEC_DURATION, MLP_MAX_ITERATIONS);
  mlp->auto_solve = GNUNET_NO;

  struct GNUNET_PeerIdentity p[10];

  /* Creating peer 1 */
  GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &p[0].hashPubKey);
  /* Creating peer 2 */
  GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &p[1].hashPubKey);

  /* Creating peer 1 address 1 */
  addr[0].peer.hashPubKey = p[0].hashPubKey;
  struct GNUNET_ATS_Information a1_ats[3];
  set_ats (&a1_ats[0], GNUNET_ATS_QUALITY_NET_DISTANCE, 1);
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 1);
  set_ats (&a1_ats[2], GNUNET_ATS_ARRAY_TERMINATOR, 0);
  create_address (&addr[0], "dummy", 3, &a1_ats[0]);
  addr[0].atsp_network_type = GNUNET_ATS_NET_WAN;

  /* Creating peer 1  address 2 */
  addr[1].peer.hashPubKey = p[0].hashPubKey;
  struct GNUNET_ATS_Information a2_ats[3];
  set_ats (&a2_ats[1], GNUNET_ATS_QUALITY_NET_DISTANCE, 1);
  set_ats (&a2_ats[0], GNUNET_ATS_QUALITY_NET_DELAY, 1);
  set_ats (&a2_ats[2], GNUNET_ATS_ARRAY_TERMINATOR, 0);
  create_address (&addr[1], "dummy2", 3, &a2_ats[0]);
  addr[1].atsp_network_type = GNUNET_ATS_NET_LAN;

  /* Creating peer 2  address 1 */
  addr[2].peer.hashPubKey = p[1].hashPubKey;
  struct GNUNET_ATS_Information a3_ats[3];
  set_ats (&a3_ats[1], GNUNET_ATS_QUALITY_NET_DISTANCE, 1);
  set_ats (&a3_ats[0], GNUNET_ATS_QUALITY_NET_DELAY, 1);
  set_ats (&a3_ats[2], GNUNET_ATS_ARRAY_TERMINATOR, 0);
  create_address (&addr[2], "dummy3", 3, &a3_ats[0]);
  addr[2].atsp_network_type = GNUNET_ATS_NET_LAN;

  GNUNET_CONTAINER_multihashmap_put(addresses, &addr[0].peer.hashPubKey, &addr[0], GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  /* Add peer 1 address 1 */
  GAS_mlp_address_update (mlp, addresses, &addr[0]);

  GNUNET_assert (mlp != NULL);
  GNUNET_assert (mlp->addr_in_problem == 1);

  /* Update an peer 1 address 1  */
  set_ats (&a1_ats[1], GNUNET_ATS_QUALITY_NET_DELAY, 1);
  GAS_mlp_address_update (mlp, addresses, &addr[0]);
  GNUNET_assert (mlp->addr_in_problem == 1);

  /* Add peer 1 address 2 */
  GNUNET_CONTAINER_multihashmap_put(addresses, &addr[0].peer.hashPubKey, &addr[1], GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GAS_mlp_address_update (mlp, addresses, &addr[1]);
  GNUNET_assert (mlp->addr_in_problem == 2);

  /* Add peer 2 address 1 */
  GNUNET_CONTAINER_multihashmap_put(addresses, &addr[2].peer.hashPubKey, &addr[2], GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GAS_mlp_address_update (mlp, addresses, &addr[2]);
  GNUNET_assert (mlp->addr_in_problem == 3);

  GNUNET_assert (GNUNET_OK == GAS_mlp_solve_problem(mlp));

  res[0] = GAS_mlp_get_preferred_address(mlp, addresses, &p[0]);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Preferred address `%s' outbound bandwidth: %u Bps\n",res[0]->address->plugin, res[0]->bandwidth_out);
  res[1] = GAS_mlp_get_preferred_address(mlp, addresses, &p[1]);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Preferred address `%s' outbound bandwidth: %u Bps\n",res[1]->address->plugin, res[1]->bandwidth_out);

  /* Delete an address */
  GNUNET_CONTAINER_multihashmap_remove (addresses, &addr[0].peer.hashPubKey, &addr[0]);
  GAS_mlp_address_delete (mlp, addresses, &addr[0]);
  GNUNET_CONTAINER_multihashmap_remove (addresses, &addr[1].peer.hashPubKey, &addr[1]);
  GAS_mlp_address_delete (mlp, addresses, &addr[1]);
  GNUNET_CONTAINER_multihashmap_remove (addresses, &addr[2].peer.hashPubKey, &addr[2]);
  GAS_mlp_address_delete (mlp, addresses, &addr[2]);

  GNUNET_assert (mlp->addr_in_problem == 0);

  GAS_mlp_done (mlp);

  GNUNET_free (addr[0].plugin);
  GNUNET_free (addr[1].plugin);
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
  GNUNET_STATISTICS_destroy(stats, GNUNET_NO);

  ret = 0;
  return;
}


int
main (int argc, char *argv[])
{

  static char *const argv2[] = { "test_ats_mlp",
    "-c",
    "test_ats_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#else
    "-L", "WARNING",
#endif
    NULL
  };

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_ats_mlp", "nohelp", options,
                      &check, NULL);


  return ret;
}

/* end of file test_ats_api_bandwidth_consumption.c */

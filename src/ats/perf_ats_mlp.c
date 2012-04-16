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
#include "gnunet-service-ats_addresses_mlp.h"

#define VERBOSE GNUNET_YES
#define VERBOSE_ARM GNUNET_NO

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX

#define DEF_PEERS 10
#define DEF_ADDRESSES_PER_PEER 5

static unsigned int peers;
static unsigned int addresses;

static int ret;

struct GNUNET_STATISTICS_Handle * stats;

struct GNUNET_CONTAINER_MultiHashMap * amap;

struct GAS_MLP_Handle *mlp;

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
  //char * pid;

  if (peers == 0)
    peers = DEF_PEERS;
  if (addresses == 0)
    addresses = DEF_ADDRESSES_PER_PEER;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Setting up %u peers with %u addresses per peer\n", peers, addresses);

  struct PeerContext p[peers];
  struct ATS_Address a[addresses * peers];

  amap = GNUNET_CONTAINER_multihashmap_create(addresses * peers);

  mlp = GAS_mlp_init (cfg, NULL, MLP_MAX_EXEC_DURATION, MLP_MAX_ITERATIONS);
  mlp->auto_solve = GNUNET_NO;
  for (c=0; c < peers; c++)
  {
    GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &p[c].id.hashPubKey);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "peer %s\n", GNUNET_h2s_full(&p[c].id.hashPubKey));

    for (c2=0; c2 < addresses; c2++)
    {
      a[ca].peer = p[c].id;
      a[ca].plugin = strdup("test");
      a[ca].addr = GNUNET_HELLO_address_allocate(&a[ca].peer, a[ca].plugin, NULL, 0);
      a[ca].addr_len = GNUNET_HELLO_address_get_size(a[ca].addr);
      a[ca].ats = NULL;
      ca++;
      GAS_mlp_address_update(mlp, amap, &a[c2]);
    }
  }

  GAS_mlp_solve_problem(mlp);


  GAS_mlp_done (mlp);

  for (c2=0; c2 < (peers * addresses); c2++)
  {
    GNUNET_free (a[c2].plugin);
    GNUNET_free (a[c2].addr);
//      GAS_mlp_address_update(mlp, amap, &a[c2]);
  }

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
    {'a', "addresses", NULL,
     gettext_noop ("addresses per peer"), 1,
     &GNUNET_GETOPT_set_uint, &addresses},
    {'p', "peers", NULL,
     gettext_noop ("peers"), 1,
     &GNUNET_GETOPT_set_uint, &peers},
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "test_ats_mlp", "nohelp", options,
                      &check, NULL);


  return ret;
}

/* end of file test_ats_api_bandwidth_consumption.c */

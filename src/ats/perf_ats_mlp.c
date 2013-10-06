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
#include "gnunet_ats_service.h"
#include "gnunet-service-ats-solver_mlp.h"
#include "gnunet-service-ats_normalization.h"
#include "test_ats_api_common.h"

#define PEERS_START 100
#define PEERS_END 	100

#define ADDRESSES 10

int count_p;
int count_a;


struct PerfPeer
{
	struct GNUNET_PeerIdentity id;

	struct ATS_Address *head;
	struct ATS_Address *tail;
};

static int ret;
static int opt_numeric;
static int opt_dump;
static int opt_update_percent;
static int opt_update_quantity;

static int N_peers_start;
static int N_peers_end;
static int N_address;

/**
 * Statistics handle
 */
struct GNUNET_STATISTICS_Handle * stats;

/**
 * MLP solver handle
 */
struct GAS_MLP_Handle *mlp;

/**
 * Hashmap containing addresses
 */
struct GNUNET_CONTAINER_MultiHashMap * addresses;

#define ATS_COUNT 2
struct GNUNET_ATS_Information ats[2];

struct PerfPeer *peers;

static void
end_now (int res)
{
  if (NULL != stats)
  {
  	  GNUNET_STATISTICS_destroy(stats, GNUNET_NO);
  	  stats = NULL;
  }
  /*
  if (NULL != addresses)
  {
  		GNUNET_CONTAINER_multihashmap_iterate (addresses, &addr_it, NULL);
  		GNUNET_CONTAINER_multihashmap_destroy (addresses);
  		addresses = NULL ;
  }*/
  if (NULL != peers)
	{
		GNUNET_free (peers);
	}
  if (NULL != mlp)
  {
  		GAS_mlp_done (mlp);
  		mlp = NULL;
  }
  GAS_normalization_stop();
	ret = res;
}


static void
bandwidth_changed_cb (void *cls, struct ATS_Address *address)
{

}

static void
normalized_property_changed_cb (void *cls,
								  						 struct ATS_Address *peer,
								  						 uint32_t type,
								  						 double prop_rel)
{
	 /* TODO */
}

const double *
get_property_cb (void *cls, const struct ATS_Address *address)
{
	return GAS_normalization_get_properties ((struct ATS_Address *) address);
}


static const double *
get_preferences_cb (void *cls, const struct GNUNET_PeerIdentity *id)
{
	return GAS_normalization_get_preferences (id);
}


static void
perf_create_peer (int cp)
{
	GNUNET_CRYPTO_hash_create_random(GNUNET_CRYPTO_QUALITY_WEAK, &peers[cp].id.hashPubKey);
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating peer #%u: %s \n", cp, GNUNET_i2s (&peers[cp].id));
}

static struct ATS_Address *
perf_create_address (int cp, int ca)
{
	struct ATS_Address *a;
	a = create_address (&peers[cp].id, "Test 1", "test 1", strlen ("test 1") + 1, 0);
	GNUNET_CONTAINER_DLL_insert (peers[cp].head, peers[cp].tail, a);
	GNUNET_CONTAINER_multihashmap_put (addresses, &peers[cp].id.hashPubKey, a, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
	return a;
}

static void
address_initial_update (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
	GAS_mlp_address_property_changed (mlp, address,
			GNUNET_ATS_QUALITY_NET_DELAY, 100,
			(double)(100 + GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 100)) / 100);

	GAS_mlp_address_property_changed (mlp, address,
			GNUNET_ATS_QUALITY_NET_DISTANCE, 10,
			(double)(100 + GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 100)) / 100);
}


static void
update_single_addresses (struct ATS_Address *cur)
{
	int r_type;
	int r_val;

	r_type = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 2);
	switch (r_type) {
		case 0:
			r_val = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 100);
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating peer `%s' address %p type %s val %u\n",
					GNUNET_i2s (&cur->peer), cur,
					"GNUNET_ATS_QUALITY_NET_DELAY", r_val);
			GAS_mlp_address_property_changed (mlp, cur, GNUNET_ATS_QUALITY_NET_DELAY, r_val,
					(double)(100 + r_val / 100));
			break;
		case 1:
			r_val = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 10);

			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating peer `%s' address %p type %s val %u\n",
					GNUNET_i2s (&cur->peer), cur,
					"GNUNET_ATS_QUALITY_NET_DISTANCE", r_val);
			GAS_mlp_address_property_changed (mlp, cur, GNUNET_ATS_QUALITY_NET_DISTANCE, r_val,
					(double)(100 + r_val) / 100);
			break;
		default:
			break;
	}
	GAS_mlp_address_inuse_changed(mlp, cur, GNUNET_YES);

}

static void
update_addresses (unsigned int cp, unsigned int ca, unsigned int up_q)
{
	struct ATS_Address *cur;
	int c_peer;
	int c_select;
	int c_addr;
	int r;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating addresses %u addresses per peer \n", up_q);
	unsigned int m [ca];

	for (c_peer = 0; c_peer < cp; c_peer++)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating peer `%s'\n", GNUNET_i2s (&peers[c_peer].id));
			for (c_select = 0; c_select < ca; c_select++)
				m[c_select] = 0;
			c_select = 0;
			while (c_select < opt_update_quantity)
			{
					r = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, ca);
					if (0 == m[r])
					{
						m[r] = 1;
						c_select++;
					}
			}

			c_addr = 0;
			for (cur = peers[c_peer].head; NULL != cur; cur = cur->next)
			{
					if (1 == m[c_addr])
							update_single_addresses (cur);
					c_addr ++;
			}
	}
}


static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  unsigned long long  quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long  quotas_out[GNUNET_ATS_NetworkTypeCount];
	int cp;
	int ca;
	struct ATS_Address * cur_addr;

	int full_lp_res;
	int full_mip_res;
	int full_lp_presolv;
	int full_mip_presolv;
	struct GNUNET_TIME_Relative full_build_dur;
	struct GNUNET_TIME_Relative full_lp_dur;
	struct GNUNET_TIME_Relative full_mip_dur;

	int update_lp_res;
	int update_mip_res;
	int update_lp_presolv;
	int update_mip_presolv;
	struct GNUNET_TIME_Relative update_build_dur;
	struct GNUNET_TIME_Relative update_lp_dur;
	struct GNUNET_TIME_Relative update_mip_dur;

  stats = GNUNET_STATISTICS_create("ats", cfg);
  if (NULL == stats)
  {
  	GNUNET_break (0);
    end_now (1);
    return;
  }
  GAS_normalization_start (NULL, NULL, &normalized_property_changed_cb, NULL);
  /* Load quotas */
  if (GNUNET_ATS_NetworkTypeCount != load_quotas (cfg, quotas_out, quotas_in,
  			GNUNET_ATS_NetworkTypeCount))
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }

  GNUNET_assert (N_peers_end >= N_peers_start);
  GNUNET_assert (N_address >= 0);

  fprintf (stderr, "Solving problem for %u..%u peers with %u addresses\n",
  		N_peers_start, N_peers_end, N_address);

  count_p = N_peers_end;
  count_a = N_address;
  peers = GNUNET_malloc ((count_p) * sizeof (struct PerfPeer));
  /* Setup address hashmap */
  addresses = GNUNET_CONTAINER_multihashmap_create (N_address, GNUNET_NO);

  /* Init MLP solver */
  mlp  = GAS_mlp_init (cfg, stats, addresses,
  		quotas, quotas_out, quotas_in,
  		GNUNET_ATS_NetworkTypeCount, &bandwidth_changed_cb, NULL,
  		&get_preferences_cb, NULL,
  		&get_property_cb, NULL);
  if (NULL == mlp)
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }
  mlp->mlp_auto_solve = GNUNET_NO;
  mlp->write_mip_mps = opt_dump;
  mlp->write_mip_sol = opt_dump;

	for (cp = 0; cp < count_p; cp++)
			perf_create_peer (cp);

	if (GNUNET_YES == opt_numeric)
		fprintf (stderr, "#peers;#addresses per peer;LP/MIP state;presolv;exec build in ms;exec LP in ms; exec MIP in ms;#cols;#rows;#nonzero elements\n");

	for (cp = 0; cp < count_p; cp++)
	{
			for (ca = 0; ca < count_a; ca++)
			{
					cur_addr = perf_create_address(cp, ca);
					/* add address */
					GAS_mlp_address_add (mlp, cur_addr, GNUNET_ATS_NET_UNSPECIFIED);
					address_initial_update (mlp, addresses, cur_addr);
					GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding address for peer %u address %u: \n", cp, ca);
			}
			GAS_mlp_get_preferred_address( mlp, &peers[cp].id);
			/* solve */
			if (cp + 1 >= N_peers_start)
			{

				update_mip_dur = GNUNET_TIME_UNIT_FOREVER_REL;
				update_lp_dur = GNUNET_TIME_UNIT_FOREVER_REL;
				update_build_dur = GNUNET_TIME_UNIT_FOREVER_REL;
				update_mip_presolv = GNUNET_SYSERR;
				update_lp_presolv = GNUNET_SYSERR;
				update_mip_res = GNUNET_SYSERR;
				update_lp_res = GNUNET_SYSERR;
				/* Solve the full problem */
				GAS_mlp_solve_problem (mlp);
				full_lp_res = mlp->ps.lp_res;
				full_mip_res = mlp->ps.mip_res;
				full_lp_presolv = mlp->ps.lp_presolv;
				full_mip_presolv = mlp->ps.mip_presolv;
				full_build_dur = mlp->ps.build_dur;
				full_lp_dur = mlp->ps.lp_dur;
				full_mip_dur = mlp->ps.mip_dur;

				/* Update and solve the problem */
				if ((0 < opt_update_quantity) || (0 < opt_update_percent))
				{
					GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating problem with %u peers and %u addresses\n", cp + 1, ca);
					update_addresses (cp + 1, ca, opt_update_quantity);
					GAS_mlp_solve_problem (mlp);
					GAS_mlp_solve_problem (mlp);
					update_lp_res = mlp->ps.lp_res;
					update_mip_res = mlp->ps.mip_res;
					update_lp_presolv = mlp->ps.lp_presolv;
					update_mip_presolv = mlp->ps.mip_presolv;
					update_build_dur = mlp->ps.build_dur;
					update_lp_dur = mlp->ps.lp_dur;
					update_mip_dur = mlp->ps.mip_dur;

				}
				if (GNUNET_NO == opt_numeric)
				{
				fprintf (stderr,
					 "Rebuild: %03u peers each %02u addresses; rebuild: LP/MIP state [%3s/%3s] presolv [%3s/%3s], (build/LP/MIP in us) %04llu / %04llu / %04llu\n",
					 cp + 1, ca,
					 (GNUNET_OK == full_lp_res) ? "OK" : "FAIL",
					 (GNUNET_OK == full_mip_res) ? "OK" : "FAIL",
					 (GLP_YES == full_lp_presolv) ? "YES" : "NO",
					 (GNUNET_OK == full_mip_presolv) ? "YES" : "NO",
					 (unsigned long long) full_build_dur.rel_value_us,
					 (unsigned long long) full_lp_dur.rel_value_us,
					 (unsigned long long) full_mip_dur.rel_value_us);
				if ((0 < opt_update_quantity) || (0 < opt_update_percent))
				  fprintf (stderr,
					   "Update: %03u peers each %02u addresses; rebuild: LP/MIP state [%3s/%3s] presolv [%3s/%3s], (build/LP/MIP in us) %04llu / %04llu / %04llu\n",
					   cp + 1, ca,
					   (GNUNET_OK == update_lp_res) ? "OK" : "FAIL",
					   (GNUNET_OK == update_mip_res) ? "OK" : "FAIL",
					   (GLP_YES == update_lp_presolv) ? "YES" : "NO",
					   (GNUNET_OK == update_mip_presolv) ? "YES" : "NO",
					   (unsigned long long) update_build_dur.rel_value_us,
					   (unsigned long long) update_lp_dur.rel_value_us,
					   (unsigned long long) update_mip_dur.rel_value_us);
				}
				else
				{
				  fprintf (stderr,
					   "Rebuild;%u;%u;%s;%s;%s;%s;%04llu;%04llu;%04llu\n",
					   cp + 1, ca,
					   (GNUNET_OK == full_lp_res) ? "OK" : "FAIL",
					   (GNUNET_OK == full_mip_res) ? "OK" : "FAIL",
					   (GLP_YES == full_lp_presolv) ? "YES" : "NO",
					   (GNUNET_OK == full_mip_presolv) ? "YES" : "NO",
					   (unsigned long long) full_build_dur.rel_value_us,
					   (unsigned long long) full_lp_dur.rel_value_us,
					   (unsigned long long) full_mip_dur.rel_value_us);
				  if ((0 < opt_update_quantity) || (0 < opt_update_percent))
				    fprintf (stderr,
					     "Update;%u;%u;%s;%s;%s;%s;%04llu;%04llu;%04llu\n",
					     cp + 1, ca,
					     (GNUNET_OK == update_lp_res) ? "OK" : "FAIL",
					     (GNUNET_OK == update_mip_res) ? "OK" : "FAIL",
					     (GLP_YES == update_lp_presolv) ? "YES" : "NO",
					     (GNUNET_OK == update_mip_presolv) ? "YES" : "NO",
					     (unsigned long long) update_build_dur.rel_value_us,
					     (unsigned long long) update_lp_dur.rel_value_us,
					     (unsigned long long) update_mip_dur.rel_value_us);
				}
			}
	}


	struct ATS_Address *cur;
	struct ATS_Address *next;
	for (cp = 0; cp < count_p; cp++)
	{
			for (cur = peers[cp].head; cur != NULL; cur = next)
			{
					GAS_mlp_address_delete (mlp, cur, GNUNET_NO);
					next = cur->next;
					GNUNET_CONTAINER_DLL_remove (peers[cp].head, peers[cp].tail, cur);
					GNUNET_free (cur);
			}

	}
	GNUNET_free (peers);

}


int
main (int argc, char *argv[])
{

  static char *const argv2[] = { "perf_ats_mlp",
    "-c",
    "test_ats_mlp.conf",
    "-L", "WARNING",
    NULL
  };

  opt_dump = GNUNET_NO;
  opt_update_quantity = 0;
  opt_update_percent = 0;

  N_peers_start = 0;
  N_peers_end = 0;
  N_address = 0;
  int c;
  for (c = 0; c < argc; c++)
  {
  		if ((0 == strcmp (argv[c], "-z")) && (c < (argc - 1)))
  		{
  				if (0 != atoi(argv[c+1]))
  				{
  						N_peers_start = atoi(argv[c+1]);
  				}
  		}
  		if ((0 == strcmp (argv[c], "-x")) && (c < (argc - 1)))
  		{
  				if (0 != atoi(argv[c+1]))
  				{
  						N_peers_end = atoi(argv[c+1]);
  				}
  		}
  		if ((0 == strcmp (argv[c], "-c")) && (c < (argc - 1)))
  		{
  				if (0 != atoi(argv[c+1]))
  				{
  						N_address = atoi(argv[c+1]);
  				}
  		}
  		if ((0 == strcmp (argv[c], "-n")))
  		{
  				opt_numeric = GNUNET_YES;
  		}
  		if ((0 == strcmp (argv[c], "-d")))
  		{
  				opt_dump = GNUNET_YES;
  		}
  		if ((0 == strcmp (argv[c], "-p")) && (c < (argc - 1)))
  		{
  				if (0 != atoi(argv[c+1]))
  				{
  	  				/* Update a fix "p"ercentage of addresses */
  						opt_update_percent = atoi(argv[c+1]);
  						if ((0 <= opt_update_percent) && (100 <= opt_update_percent))
  						{
  							fprintf (stderr, _("Percentage has to be: 0 <= p <= 100 "));
  							exit (1);
  						}
  				}
  		}
  		if ((0 == strcmp (argv[c], "-q")) && (c < (argc - 1)))
  		{
  				if (0 != atoi(argv[c+1]))
  				{
  	  				/* Update a fix "q"uantity of addresses */
  						opt_update_quantity = atoi(argv[c+1]);
  						if (0 >= opt_update_quantity)
  						{
  							fprintf (stderr, _("Quantity has to be:  p => 0 "));
  							exit (1);
  						}
  				}
  		}
  }

  if ((0 == N_peers_start) && (0 == N_peers_end))
  {
  		N_peers_start = PEERS_START;
  		N_peers_end = PEERS_END;
  }
  if (0 == N_address)
  		N_address = ADDRESSES;

  if (opt_update_quantity > N_address)
  {
  		fprintf (stderr, _("Trying to update more addresses than we have per peer! (%u vs %u)"), opt_update_quantity, N_address);
  		exit (1);
  }

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };


  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "perf_ats_mlp", "nohelp", options,
                      &check, NULL);


  return ret;
}

/* end of file perf_ats_mlp.c */

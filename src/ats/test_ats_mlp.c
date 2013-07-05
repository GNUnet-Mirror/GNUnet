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
 * @brief basic test for the MLP solver
 * @author Christian Grothoff
 * @author Matthias Wachs

 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats-solver_mlp.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet_ats_service.h"
#include "test_ats_api_common.h"

/**
 * Return value
 */
static int ret;

/**
 * MLP solver handle
 */
struct GAS_MLP_Handle *mlp;


/**
 * Statistics handle
 */
struct GNUNET_STATISTICS_Handle * stats;

/**
 * Hashmap containing addresses
 */
struct GNUNET_CONTAINER_MultiHashMap * addresses;

/**
 * Peer
 */
struct GNUNET_PeerIdentity p[2];

/**
 * ATS Address
 */
struct ATS_Address *address[3];

/**
 * Timeout task
 */
GNUNET_SCHEDULER_TaskIdentifier timeout_task;


int addr_it (void *cls,
             const struct GNUNET_HashCode * key,
             void *value)
{
	struct ATS_Address *address = (struct ATS_Address *) value;
	GAS_mlp_address_delete (mlp, address, GNUNET_NO);
	GNUNET_CONTAINER_multihashmap_remove (addresses, key, value);
  GNUNET_free (address);
	return GNUNET_OK;
}


static void
end_now (int res)
{
	if (GNUNET_SCHEDULER_NO_TASK != timeout_task)
	{
			GNUNET_SCHEDULER_cancel (timeout_task);
			timeout_task = GNUNET_SCHEDULER_NO_TASK;
	}
  if (NULL != stats)
  {
  	  GNUNET_STATISTICS_destroy(stats, GNUNET_NO);
  	  stats = NULL;
  }
  if (NULL != addresses)
  {
  		GNUNET_CONTAINER_multihashmap_iterate (addresses, &addr_it, NULL);
  		GNUNET_CONTAINER_multihashmap_destroy (addresses);
  		addresses = NULL ;
  }
  if (NULL != mlp)
  {
  		GAS_mlp_done (mlp);
  		mlp = NULL;
  }
  GAS_normalization_stop ();
	ret = res;
}

static void
end_correctly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Test ending with success\n"));
	end_now (0);
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	GNUNET_break (0);
	timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Test ending with timeout\n"));
	end_now (1);
}


const double *
get_preferences_cb (void *cls, const struct GNUNET_PeerIdentity *id)
{
	return GAS_normalization_get_preferences (id);
}

const double *
get_property_cb (void *cls, const struct ATS_Address *address)
{
	return GAS_normalization_get_properties ((struct ATS_Address *) address);
}

static void
normalized_property_changed_cb (void *cls,
								  						 struct ATS_Address *peer,
								  						 uint32_t type,
								  						 double prop_rel)
{
	 /* TODO */
}


static void
bandwidth_changed_cb (void *cls, struct ATS_Address *address)
{
	static int cb_p0 = GNUNET_NO;
	static int cb_p1 = GNUNET_NO;

	unsigned long long in = ntohl(address->assigned_bw_in.value__);
	unsigned long long out = ntohl(address->assigned_bw_out.value__);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MLP suggests for peer `%s' address `%s':`%s' in %llu out %llu \n",
  		GNUNET_i2s(&address->peer),
  		address->plugin,
  		address->addr,
  		in, out);

  if ((in > 0) && (out > 0) &&
  		(0 == memcmp(&p[0], &address->peer, sizeof (address->peer))))
  	cb_p0 ++;

  if ((in > 0) && (out > 0) &&
  		(0 == memcmp(&p[1], &address->peer, sizeof (address->peer))))
  	cb_p1 ++;

  if ((1 == cb_p0) && (1 == cb_p1))
  		GNUNET_SCHEDULER_add_now (&end_correctly, NULL);
  else if ((1 < cb_p0) || (1 < cb_p1))
  {
  		GNUNET_break (0);
  		GNUNET_SCHEDULER_add_now (&end_badly, NULL);
  }
}


static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  unsigned long long  quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long  quotas_out[GNUNET_ATS_NetworkTypeCount];

#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "GLPK not installed!");
  ret = 1;
  return;
#endif

  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  stats = GNUNET_STATISTICS_create("ats", cfg);
  if (NULL == stats)
  {
  	GNUNET_break (0);
    end_now (1);
    return;
  }

  /* Load quotas */
  if (GNUNET_ATS_NetworkTypeCount != load_quotas (cfg, quotas_out, quotas_in,
  			GNUNET_ATS_NetworkTypeCount))
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }
  GAS_normalization_start (NULL, NULL, &normalized_property_changed_cb, NULL);
  /* Setup address hashmap */
  addresses = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);

  /* Init MLP solver */
  mlp  = GAS_mlp_init (cfg, stats, addresses,
  		quotas, quotas_out, quotas_in,
  		GNUNET_ATS_NetworkTypeCount,
  		&bandwidth_changed_cb, NULL,
  		&get_preferences_cb, NULL,
  		&get_property_cb, NULL);
  if (NULL == mlp)
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }
  mlp->mlp_auto_solve = GNUNET_NO;

  /* Create peer 0 */
  if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string(PEERID0, &p[0].hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
      end_now (1);
      return;
  }

  /* Create peer 1 */
  if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string(PEERID1, &p[1].hashPubKey))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not setup peer!\n");
      end_now (1);
      return;
  }

  /* Create address 0 */
  address[0] = create_address (&p[0], "test_plugin0", "test_addr0", strlen("test_addr0")+1, 0);
  if (NULL == address[0])
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }
  GNUNET_CONTAINER_multihashmap_put (addresses, &p[0].hashPubKey, address[0],
  		GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  /* Adding address 0 */
  GAS_mlp_address_add (mlp, address[0], GNUNET_ATS_NET_UNSPECIFIED);

  /* Create address 1 */
  address[1] = create_address (&p[0], "test_plugin1", "test_addr1", strlen("test_addr1")+1, 0);
  if (NULL == address[1])
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }
  GNUNET_CONTAINER_multihashmap_put (addresses, &p[0].hashPubKey, address[1],
  		GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  /* Adding address 1*/
  GAS_mlp_address_add (mlp, address[1], GNUNET_ATS_NET_UNSPECIFIED);


  /* Create address 3 */
  address[2] = create_address (&p[1], "test_plugin2", "test_addr2", strlen("test_addr2")+1, 0);
  if (NULL == address[2])
  {
    	GNUNET_break (0);
      end_now (1);
      return;
  }
  GNUNET_CONTAINER_multihashmap_put (addresses, &p[1].hashPubKey, address[2],
  		GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  /* Adding address 3*/
  GAS_mlp_address_add (mlp, address[2], GNUNET_ATS_NET_UNSPECIFIED);


  /* Updating address 0*/
  GAS_mlp_address_change_network(mlp, address[0], GNUNET_ATS_NET_UNSPECIFIED, GNUNET_ATS_NET_WAN);

  /* Retrieving preferred address for peer and wait for callback */
  GAS_mlp_get_preferred_address (mlp, &p[0]);
  GAS_mlp_get_preferred_address (mlp, &p[1]);

  mlp->write_mip_mps = GNUNET_NO;
  mlp->write_mip_sol = GNUNET_NO;

  GAS_mlp_solve_problem (mlp);
}


int
main (int argc, char *argv[])
{

  static char *const argv2[] = { "test_ats_mlp",
    "-c",
    "test_ats_mlp.conf",
    "-L", "WARNING",
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

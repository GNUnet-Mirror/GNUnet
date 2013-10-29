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
 * @file ats/perf_ats_solver.c
 * @brief generic performance test for ATS solvers
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_normalization.h"
#include "gnunet_ats_service.h"
#include "gnunet_ats_plugin.h"
#include "test_ats_api_common.h"

#define DEFAULT_PEERS_START     100
#define DEFAULT_PEERS_END       100
#define DEFAULT_ADDRESSES       10
#define DEFAULT_ATS_COUNT       2

/**
 * Handle for ATS address component
 */
struct PerfHandle
{
  struct PerfPeer *peers;

  /**
   * #peers to start benchmarking with
   */
  int N_peers_start;

  /**
   * #peers to end benchmarking with
   */
  int N_peers_end;

  /**
   * #addresses to benchmarking with
   */
  int N_address;

  int opt_numeric;
  int opt_dump;
  int opt_update_percent;
  int opt_update_quantity;

  char *ats_string;

  /**
   *
   */
  struct GNUNET_STATISTICS_Handle *stat;

  /**
   * A multihashmap to store all addresses
   */
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;


  /**
   * Configured ATS solver
   */
  int ats_mode;

  /**
   *  Solver handle
   */
  void *solver;

  /**
   * Address suggestion requests DLL head
   */
  struct GAS_Addresses_Suggestion_Requests *r_head;

  /**
   * Address suggestion requests DLL tail
   */
  struct GAS_Addresses_Suggestion_Requests *r_tail;

  /* Solver functions */
  struct GNUNET_ATS_PluginEnvironment env;

  char *plugin;
};

struct PerfPeer
{
  struct GNUNET_PeerIdentity id;

  struct ATS_Address *head;
  struct ATS_Address *tail;
};

static struct PerfHandle ph;


int count_p;
int count_a;

/**
 * Return value
 */
static int ret;


/**
 * ATS information
 */
//static struct GNUNET_ATS_Information ats[2];


static void
end_now (int res)
{
  if (NULL != ph.stat)
  {
    GNUNET_STATISTICS_destroy (ph.stat, GNUNET_NO);
    ph.stat = NULL;
  }
  /*
   if (NULL != addresses)
   {
   GNUNET_CONTAINER_multihashmap_iterate (addresses, &addr_it, NULL);
   GNUNET_CONTAINER_multihashmap_destroy (addresses);
   addresses = NULL ;
   }*/
  if (NULL != ph.peers)
  {
    GNUNET_free(ph.peers);
  }

  GAS_normalization_stop ();
  ret = res;
}


static void
perf_create_peer (int cp)
{
  /*
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
      &ph.peers[cp].id.);*/
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Creating peer #%u: %s \n", cp,
      GNUNET_i2s (&ph.peers[cp].id));
}



static void
update_single_addresses (struct ATS_Address *cur)
{
  int r_type;
  int r_val;

  r_type = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 2);
  switch (r_type)
  {
  case 0:
    r_val = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Updating peer `%s' address %p type %s val %u\n",
        GNUNET_i2s (&cur->peer), cur, "GNUNET_ATS_QUALITY_NET_DELAY", r_val);
    ph.env.sf.s_address_update_property (ph.solver, cur,
        GNUNET_ATS_QUALITY_NET_DELAY,
        r_val, (double) (100 + r_val / 100));
    break;
  case 1:
    r_val = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 10);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Updating peer `%s' address %p type %s val %u\n",
        GNUNET_i2s (&cur->peer), cur, "GNUNET_ATS_QUALITY_NET_DISTANCE", r_val);
    ph.env.sf.s_address_update_property (ph.solver, cur,
        GNUNET_ATS_QUALITY_NET_DISTANCE,
        r_val, (double) (100 + r_val) / 100);
    break;
  default:
    break;
  }
  ph.env.sf.s_address_update_inuse (ph.solver, cur, GNUNET_YES);
}



static void
bandwidth_changed_cb (void *cls, struct ATS_Address *address)
{
  return;
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
normalized_property_changed_cb (void *cls, struct ATS_Address *peer,
    uint32_t type, double prop_rel)
{
  /* TODO */
}

static void
address_initial_update (void *solver,
    struct GNUNET_CONTAINER_MultiPeerMap * addresses,
    struct ATS_Address *address)
{
  ph.env.sf.s_address_update_property (solver, address, GNUNET_ATS_QUALITY_NET_DELAY,
      100,
      (double) (100 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100))
          / 100);

  ph.env.sf.s_address_update_property (solver, address,
      GNUNET_ATS_QUALITY_NET_DISTANCE, 10,
      (double) (100 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100))
          / 100);
}

static void
update_addresses (unsigned int cp, unsigned int ca, unsigned int up_q)
{
  struct ATS_Address *cur;
  int c_peer;
  int c_select;
  int c_addr;
  int r;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Updating addresses %u addresses per peer \n", up_q);
  unsigned int m[ca];

  for (c_peer = 0; c_peer < cp; c_peer++)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Updating peer `%s'\n",
        GNUNET_i2s (&ph.peers[c_peer].id));
    for (c_select = 0; c_select < ca; c_select++)
      m[c_select] = 0;
    c_select = 0;
    while (c_select < ph.opt_update_quantity)
    {
      r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, ca);
      if (0 == m[r])
      {
        m[r] = 1;
        c_select++;
      }
    }

    c_addr = 0;
    for (cur = ph.peers[c_peer].head; NULL != cur; cur = cur->next)
    {
      if (1 == m[c_addr])
        update_single_addresses (cur);
      c_addr++;
    }
  }
}


static struct ATS_Address *
perf_create_address (int cp, int ca)
{
  struct ATS_Address *a;
  a = create_address (&ph.peers[cp].id, "Test 1", "test 1", strlen ("test 1") + 1,
      0);
  GNUNET_CONTAINER_DLL_insert(ph.peers[cp].head, ph.peers[cp].tail, a);
  GNUNET_CONTAINER_multipeermap_put (ph.addresses, &ph.peers[cp].id, a,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return a;
}

static void
check ()
{
  struct ATS_Address *cur;
  struct ATS_Address *next;
  int cp;
  int ca;
  int count_p = ph.N_peers_end;
  int count_a = ph.N_address;
  struct ATS_Address * cur_addr;
  ph.peers = GNUNET_malloc ((count_p) * sizeof (struct PerfPeer));

  for (cp = 0; cp < count_p; cp++)
    perf_create_peer (cp);

  for (cp = 0; cp < count_p; cp++)
  {
    for (ca = 0; ca < count_a; ca++)
    {
      cur_addr = perf_create_address (cp, ca);
      /* add address */
      ph.env.sf.s_add (ph.solver, cur_addr, GNUNET_ATS_NET_LAN);
      address_initial_update (ph.solver, ph.addresses, cur_addr);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Adding address for peer %u address %u\n", cp, ca);
    }
    //ph.env.sf.s_get (ph.solver, &ph.peers[cp].id);
    if (cp + 1 >= ph.N_peers_start)
    {
      /* Solve */
      if ((0 < ph.opt_update_quantity) || (0 < ph.opt_update_percent))
      {
        /* Update */
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
            "Updating problem with %u peers and %u addresses\n", cp + 1, ca);
        //ph.env.sf.s_bulk_start (ph.solver);
        //update_addresses (cp + 1, ca, ph.opt_update_quantity);
        //ph.env.sf.s_bulk_stop (ph.solver);
      }
    }
  }
  for (cp = 0; cp < count_p; cp++)
  {
    for (cur = ph.peers[cp].head; cur != NULL ; cur = next)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Deleting addresses for peer %u\n", cp);
      ph.env.sf.s_del (ph.solver, cur, GNUNET_NO);
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove(ph.peers[cp].head, ph.peers[cp].tail, cur);
      GNUNET_free(cur);
    }

  }
  GNUNET_free(ph.peers);
}


static void
run (void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log_setup ("perf-ats", "WARNING", NULL);
  char *sep;
  char *src_filename = GNUNET_strdup (__FILE__);
  char *test_filename = cls;
  char *solver;
  char *plugin;
  unsigned long long quotas_in[GNUNET_ATS_NetworkTypeCount];
  unsigned long long quotas_out[GNUNET_ATS_NetworkTypeCount];
  int c;

  /* Extract test name */
  if (NULL == (sep  = (strstr (src_filename,".c"))))
  {
    GNUNET_break (0);
    ret = 1;
    return;
  }
  sep[0] = '\0';

  if (NULL != (sep = strstr (test_filename, ".exe")))
    sep[0] = '\0';

  if (NULL == (solver = strstr (test_filename, src_filename)))
  {
    GNUNET_break (0);
    ret = 1;
    return ;
  }
  solver += strlen (src_filename) +1;

  if (0 == strcmp(solver, "proportional"))
  {
    ph.ats_mode = MODE_PROPORTIONAL;
    ph.ats_string = "proportional";
  }
  else if (0 == strcmp(solver, "mlp"))
  {
    ph.ats_mode = MODE_MLP;
    ph.ats_string = "mlp";
  }
  else if ((0 == strcmp(solver, "ril")))
  {
    ph.ats_mode = MODE_RIL;
    ph.ats_string = "ril";
  }
  else
  {
    GNUNET_free (src_filename);
    GNUNET_break (0);
    ret = 1;
    return ;
  }
  GNUNET_free (src_filename);

  /* Calculcate peers */
  if ((0 == ph.N_peers_start) && (0 == ph.N_peers_end))
  {
    ph.N_peers_start = DEFAULT_PEERS_START;
    ph.N_peers_end = DEFAULT_PEERS_END;
  }
  if (0 == ph.N_address)
    ph.N_address = DEFAULT_ADDRESSES;

  if (ph.opt_update_quantity > ph.N_address)
  {
    fprintf (stderr,
        _("Trying to update more addresses than we have per peer! (%u vs %u)"),
        ph.opt_update_quantity, ph.N_address);
    exit (1);
  }

  if (ph.N_peers_start != ph.N_peers_end)
    fprintf (stderr, "Benchmarking solver `%s' with %u to %u peers and %u addresses\n",
        ph.ats_string, ph.N_peers_start, ph.N_peers_end, ph.N_address);
  else
    fprintf (stderr, "Benchmarking solver `%s' with %u peers and %u addresses\n",
        ph.ats_string, ph.N_peers_end, ph.N_address);

  /* Load quotas */
  if (GNUNET_ATS_NetworkTypeCount != load_quotas (cfg,
      quotas_in, quotas_in, GNUNET_ATS_NetworkTypeCount))
  {
    GNUNET_break(0);
    end_now (1);
    return;
  }

  /* Load solver */
  ph.env.cfg = cfg;
  ph.stat = GNUNET_STATISTICS_create ("ats", cfg);
  ph.env.stats = ph.stat;
  ph.addresses = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  ph.env.addresses = ph.addresses;
  ph.env.bandwidth_changed_cb = bandwidth_changed_cb;
  ph.env.get_preferences = &get_preferences_cb;
  ph.env.get_property = &get_property_cb;
  ph.env.network_count = GNUNET_ATS_NetworkTypeCount;
  int networks[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    ph.env.networks[c] = networks[c];
    ph.env.out_quota[c] = quotas_out[c];
    ph.env.in_quota[c] = quotas_in[c];
  }
  GAS_normalization_start (NULL, NULL, &normalized_property_changed_cb, NULL );


  GNUNET_asprintf (&plugin, "libgnunet_plugin_ats_%s", ph.ats_string);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initializing solver `%s '`%s'\n"), ph.ats_string, plugin);
  if  (NULL == (ph.solver = GNUNET_PLUGIN_load (plugin, &ph.env)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Failed to initialize solver `%s'!\n"), plugin);
    ret = 1;
    return;
  }

  /* Do work */
  check ();

  /* Unload solver*/
  GNUNET_PLUGIN_unload (plugin, ph.solver);
  GNUNET_free (plugin);
  ph.solver = NULL;
}

int
main (int argc, char *argv[])
{
  /* extract command line arguments */
  ph.opt_dump = GNUNET_NO;
  ph.opt_update_quantity = 0;
  ph.opt_update_percent = 0;
  ph.N_peers_start = 0;
  ph.N_peers_end = 0;
  ph.N_address = 0;
  ph.ats_string = NULL;

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 'a', "addresses", NULL,
          gettext_noop ("addresses to use"),
          1, &GNUNET_GETOPT_set_uint, &ph.N_address },
      { 's', "start", NULL,
          gettext_noop ("start with peer"),
          1, &GNUNET_GETOPT_set_uint, &ph.N_peers_start },
      { 'e', "end", NULL,
          gettext_noop ("end with peer"),
          1, &GNUNET_GETOPT_set_uint, &ph.N_peers_end },
      { 'p', "percentage", NULL,
          gettext_noop ("update a fix percentage of addresses"),
          1, &GNUNET_GETOPT_set_uint, &ph.opt_update_percent },
      { 'q', "quantity", NULL,
          gettext_noop ("update a fix quantity of addresses"),
          1, &GNUNET_GETOPT_set_uint, &ph.opt_update_quantity },
      GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run (argc, argv, argv[0], NULL, options, &run, argv[0]);

  return ret;
}

/* end of file perf_ats_solver.c */

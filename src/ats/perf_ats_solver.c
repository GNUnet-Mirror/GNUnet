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

#define DEFAULT_PEERS_START     10
#define DEFAULT_PEERS_END       10
#define DEFAULT_ADDRESSES       10
#define DEFAULT_ATS_COUNT       2

#define GNUPLOT_PROP_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Execution time Proportional solver  \" \n" \
"set xlabel \"Time in us\" \n" \
"set ylabel \"Bytes/s\" \n" \
"set grid \n"

#define GNUPLOT_MLP_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Execution time MLP solver \" \n" \
"set xlabel \"Time in us\" \n" \
"set ylabel \"Bytes/s\" \n" \
"set grid \n"

#define GNUPLOT_RIL_TEMPLATE "#!/usr/bin/gnuplot \n" \
"set datafile separator ';' \n" \
"set title \"Execution time RIL solver \" \n" \
"set xlabel \"Time in us\" \n" \
"set ylabel \"Bytes/s\" \n" \
"set grid \n"

/**
 * Handle for ATS address component
 */
struct PerfHandle
{
  /**
   * Performance peers
   */
  struct PerfPeer *peers;

  /**
   *  Solver handle
   */
  void *solver;

  /**
   * Statistics stat;
   */
  struct GNUNET_STATISTICS_Handle *stat;

  /**
   * A multihashmap to store all addresses
   */
  struct GNUNET_CONTAINER_MultiPeerMap *addresses;

  /**
   * Solver functions
   * */
  struct GNUNET_ATS_PluginEnvironment env;

  struct Result *head;

  struct Result *tail;

  struct Result *current_result;

  int current_p;
  int current_a;

  /**
   * Solver description as string
   */
  char *ats_string;

  /**
   * Configured ATS solver
   */
  int ats_mode;

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

  /**
   * Percentage of peers to update
   */
  int opt_update_percent;

  /**
   * Number of peers to update
   */
  int opt_update_quantity;

  /**
   * Create gnuplot file
   */
  int create_plot;

  /**
   * Is a bulk operation running?
   */
  int bulk_running;

  /**
   * Is a bulk operation running?
   */
  int expecting_solution;
};

struct Result
{
  struct Result *prev;
  struct Result *next;

  int peers;
  int addresses;

  struct GNUNET_TIME_Relative d_setup;
  struct GNUNET_TIME_Relative d_lp;
  struct GNUNET_TIME_Relative d_mlp;
  struct GNUNET_TIME_Relative d_total;

  struct GNUNET_TIME_Absolute s_setup;
  struct GNUNET_TIME_Absolute s_lp;
  struct GNUNET_TIME_Absolute s_mlp;
  struct GNUNET_TIME_Absolute s_total;

  struct GNUNET_TIME_Absolute e_setup;
  struct GNUNET_TIME_Absolute e_lp;
  struct GNUNET_TIME_Absolute e_mlp;
  struct GNUNET_TIME_Absolute e_total;
};

struct PerfPeer
{
  struct GNUNET_PeerIdentity id;

  struct ATS_Address *head;
  struct ATS_Address *tail;
};

static struct PerfHandle ph;

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

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
      &ph.peers[cp].id, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Creating peer #%u: %s \n", cp,
      GNUNET_i2s (&ph.peers[cp].id));
}



static void
perf_update_address (struct ATS_Address *cur)
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
  if (0 == ntohl(address->assigned_bw_out.value__) &&
      0 == ntohl(address->assigned_bw_in.value__))
    return;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Bandwidth changed addresses %s %p to %llu Bps out / %llu Bps in\n",
      GNUNET_i2s (&address->peer),
      address,
      ntohl(address->assigned_bw_out.value__),
      ntohl(address->assigned_bw_in.value__));
  if (GNUNET_YES == ph.bulk_running)
    GNUNET_break (0);
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
perf_address_initial_update (void *solver,
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
perf_update_all_addresses (unsigned int cp, unsigned int ca, unsigned int up_q)
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
        perf_update_address (cur);
      c_addr++;
    }
  }
}


static struct ATS_Address *
perf_create_address (int cp, int ca)
{
  struct ATS_Address *a;
  a = create_address (&ph.peers[cp].id,
      "Test 1", "test 1", strlen ("test 1") + 1, 0);
  GNUNET_CONTAINER_DLL_insert (ph.peers[cp].head, ph.peers[cp].tail, a);
  GNUNET_CONTAINER_multipeermap_put (ph.addresses, &ph.peers[cp].id, a,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return a;
}

static void
solver_info_cb (void *cls, enum GAS_Solver_Operation op,
    enum GAS_Solver_Status stat)
{

  struct Result *tmp;
  switch (op)
  {
    case GAS_OP_SOLVE_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if (GNUNET_NO == ph.expecting_solution)
      {
        /* We do not expect a solution at the moment */
        GNUNET_break (0);
        return;
      }
      if ((GAS_STAT_SUCCESS == stat) && (NULL == ph.current_result))
      {
        /* Create new result */
        tmp = GNUNET_malloc (sizeof (struct Result));
        ph.current_result = tmp;
        GNUNET_CONTAINER_DLL_insert_tail(ph.head, ph.tail, tmp);
        ph.current_result->addresses = ph.current_a;
        ph.current_result->peers = ph.current_p;
        ph.current_result->s_total = GNUNET_TIME_absolute_get ();
        ph.current_result->d_total = GNUNET_TIME_relative_get_forever_ ();
        ph.current_result->d_setup = GNUNET_TIME_relative_get_forever_ ();
        ph.current_result->d_lp = GNUNET_TIME_relative_get_forever_ ();
        ph.current_result->d_mlp = GNUNET_TIME_relative_get_forever_ ();
      }
      return;
    case GAS_OP_SOLVE_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        /* We do not expect a solution at the moment */
        GNUNET_break (0);
        return;
      }
      if (NULL != ph.current_result)
      {
        /* Finalize result */
        ph.current_result->e_total = GNUNET_TIME_absolute_get ();
        ph.current_result->d_total = GNUNET_TIME_absolute_get_difference (
            ph.current_result->s_total, ph.current_result->e_total);
      }
      ph.current_result = NULL;
      return;

    case GAS_OP_SOLVE_SETUP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }
      ph.current_result->s_setup = GNUNET_TIME_absolute_get ();
      return;

    case GAS_OP_SOLVE_SETUP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_SETUP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }
      ph.current_result->e_setup = GNUNET_TIME_absolute_get ();
      ph.current_result->d_setup = GNUNET_TIME_absolute_get_difference (
          ph.current_result->s_setup, ph.current_result->e_setup);
      return;

    case GAS_OP_SOLVE_LP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }
      ph.current_result->s_lp = GNUNET_TIME_absolute_get ();
      return;
    case GAS_OP_SOLVE_LP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_LP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }
      ph.current_result->e_lp = GNUNET_TIME_absolute_get ();
      ph.current_result->d_lp = GNUNET_TIME_absolute_get_difference (
          ph.current_result->s_lp, ph.current_result->e_lp);
      return;

    case GAS_OP_SOLVE_MLP_START:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_START",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }
      ph.current_result->s_mlp = GNUNET_TIME_absolute_get ();
      return;
    case GAS_OP_SOLVE_MLP_STOP:
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "Solver notifies `%s' with result `%s'\n", "GAS_OP_SOLVE_MLP_STOP",
          (GAS_STAT_SUCCESS == stat) ? "SUCCESS" : "FAIL");
      if ((GNUNET_NO == ph.expecting_solution) || (NULL == ph.current_result))
      {
        GNUNET_break(0);
        return;
      }
      ph.current_result->e_mlp = GNUNET_TIME_absolute_get ();
      ph.current_result->d_mlp = GNUNET_TIME_absolute_get_difference (
          ph.current_result->s_mlp, ph.current_result->e_mlp);
      return;

    default:
      break;
    }
}

static void
write_gnuplot_script ()
{
  struct Result *cur;
  struct Result *next;
  struct GNUNET_DISK_FileHandle *f;
  char * gfn;
  char *data;
  char *template;
  int c_s;
  int index;
  int plot_d_total;
  int plot_d_setup;
  int plot_d_lp;
  int plot_d_mlp;

  GNUNET_asprintf (&gfn, "perf_%s_%u_%u_%u", ph.ats_string, ph.N_peers_start, ph.N_peers_end, ph.N_address);
  f = GNUNET_DISK_file_open (gfn,
      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
      GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", gfn);
    GNUNET_free (gfn);
    return;
  }

  /* Write header */

  switch (ph.ats_mode) {
    case MODE_PROPORTIONAL:
      template = GNUPLOT_PROP_TEMPLATE;
      break;
    case MODE_MLP:
      template = GNUPLOT_MLP_TEMPLATE;
      break;
    case MODE_RIL:
      template = GNUPLOT_RIL_TEMPLATE;
      break;
    default:
      break;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, template, strlen(template)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);
#if 0
  cur = ph.head->d_total;
  if (cur->d_total != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    plot_d_total = GNUNET_YES;

  if (cur->d_total != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    plot_d_total = GNUNET_YES;
  if (cur->d_setup != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    plot_d_setup = GNUNET_YES;
  if (cur->d_lp != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    plot_d_lp = GNUNET_YES;
  if (cur->d_mlp != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    plot_d_mlp = GNUNET_YES;


    GNUNET_asprintf (&data, "plot "\
        "'%s' using 2:%u with lines title 'BW out master %u - Slave %u ', \\\n" \
        "'%s' using 2:%u with lines title 'BW in master %u - Slave %u '"\
        "%s\n",
        "\n pause -1",
        fn, index + LOG_ITEM_ATS_BW_OUT, lp->peer->no, lp->peer->partners[c_s].dest->no,
        fn, index + LOG_ITEM_ATS_BW_IN, lp->peer->no, lp->peer->partners[c_s].dest->no);

    GNUNET_free (data);
#endif
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to plot file `%s'\n", gfn);


#if 0
  index = LOG_ITEMS_TIME + LOG_ITEMS_PER_PEER;
  for (c_s = 0; c_s < lp->peer->num_partners; c_s++)
  {
    GNUNET_asprintf (&data, "%s"\
        "'%s' using 2:%u with lines title 'BW out master %u - Slave %u ', \\\n" \
        "'%s' using 2:%u with lines title 'BW in master %u - Slave %u '"\
        "%s\n",
        (0 == c_s) ? "plot " :"",
        fn, index + LOG_ITEM_ATS_BW_OUT, lp->peer->no, lp->peer->partners[c_s].dest->no,
        fn, index + LOG_ITEM_ATS_BW_IN, lp->peer->no, lp->peer->partners[c_s].dest->no,
        (c_s < lp->peer->num_partners -1) ? ", \\" : "\n pause -1");

    GNUNET_free (data);
    index += LOG_ITEMS_PER_PEER;
  }
#endif

  if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close gnuplot file `%s'\n", gfn);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Data successfully written to plot file `%s'\n", gfn);
  GNUNET_free (gfn);

}


static void
evaluate ()
{
  struct GNUNET_DISK_FileHandle *f;
  char * data_fn;
  char * data;
  struct Result *cur;
  struct Result *next;
  char * str_d_total;
  char * str_d_setup;
  char * str_d_lp;
  char * str_d_mlp;

  if (ph.create_plot)
  {
    GNUNET_asprintf (&data_fn, "perf_%s_%u_%u_%u_data", ph.ats_string, ph.N_peers_start, ph.N_peers_end, ph.N_address);
    f = GNUNET_DISK_file_open (data_fn,
        GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE,
        GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == f)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot open gnuplot file `%s'\n", data_fn);
      GNUNET_free (data_fn);
      return;
    }
    data = "#peers;addresses;time total in us;#time setup in us;#time lp in us;#time mlp in us;\n";
    if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to log file `%s'\n", data_fn);

    write_gnuplot_script ();
  }

  next = ph.head;
  while (NULL != (cur = next))
  {
    next = cur->next;

    /* Print log */
    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_total.rel_value_us)
    {
      fprintf (stderr, "Total time to solve for %u peers %u addresses: %llu us\n",
          cur->peers, cur->addresses, (unsigned long long )cur->d_total.rel_value_us);
      GNUNET_asprintf(&str_d_total, "%llu", (unsigned long long )cur->d_total.rel_value_us);
    }
    else
      GNUNET_asprintf(&str_d_total, "-1");
    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_setup.rel_value_us)
    {
      fprintf (stderr, "Total time to setup %u peers %u addresses: %llu us\n",
          cur->peers, cur->addresses, (unsigned long long )cur->d_setup.rel_value_us);
      GNUNET_asprintf(&str_d_setup, "%llu", (unsigned long long )cur->d_setup.rel_value_us);
    }
    else
      GNUNET_asprintf(&str_d_setup, "-1");
    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_lp.rel_value_us)
    {
      fprintf (stderr, "Total time to solve LP for %u peers %u addresses: %llu us\n",
          cur->peers, cur->addresses, (unsigned long long )cur->d_lp.rel_value_us);
      GNUNET_asprintf(&str_d_lp, "%llu", (unsigned long long )cur->d_lp.rel_value_us);
    }
    else
      GNUNET_asprintf(&str_d_lp, "-1");
    if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us != cur->d_mlp.rel_value_us)
    {
      fprintf (stderr, "Total time to solve MLP for %u peers %u addresses: %llu us\n",
          cur->peers, cur->addresses, (unsigned long long )cur->d_mlp.rel_value_us);
      GNUNET_asprintf(&str_d_mlp, "%llu", (unsigned long long )cur->d_mlp.rel_value_us);
    }
    else
      GNUNET_asprintf(&str_d_mlp, "-1");

    if (GNUNET_YES == ph.create_plot)
    {

      GNUNET_asprintf(&data,"%u;%u;%s;%s;%s;%s\n",
          cur->peers, cur->addresses,
          str_d_total,
          str_d_setup,
          str_d_lp,
          str_d_mlp);

      if (GNUNET_SYSERR == GNUNET_DISK_file_write(f, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot write data to log file `%s'\n", data_fn);
      GNUNET_free (str_d_total);
      GNUNET_free (str_d_setup);
      GNUNET_free (str_d_lp);
      GNUNET_free (str_d_mlp);
      GNUNET_free (data);

    }

    GNUNET_CONTAINER_DLL_remove (ph.head, ph.tail, cur);
    GNUNET_free (cur);
  }

  if (GNUNET_YES == ph.create_plot)
  {
    if (GNUNET_SYSERR == GNUNET_DISK_file_close(f))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot close log file `%s'\n", data_fn);
      GNUNET_free (data_fn);
    }

  }
}

static void
perf_run ()
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
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Added %u peers\n", cp);

  /* Set initial bulk start to not solve */
  ph.env.sf.s_bulk_start (ph.solver);
  ph.bulk_running = GNUNET_YES;

  for (cp = 0; cp < count_p; cp++)
  {
    ph.current_p = cp + 1;
    for (ca = 0; ca < count_a; ca++)
    {
      cur_addr = perf_create_address (cp, ca);
      /* Add address */
      ph.env.sf.s_add (ph.solver, cur_addr, GNUNET_ATS_NET_LAN);
      ph.current_a = ca + 1;
      perf_address_initial_update (ph.solver, ph.addresses, cur_addr);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Adding address for peer %u address %u\n", cp, ca);
    }
    /* Notify solver about request */
    ph.env.sf.s_get (ph.solver, &ph.peers[cp].id);

    if (cp + 1 >= ph.N_peers_start)
    {
      /* Disable bulk to solve the problem */
      if (GNUNET_YES == ph.bulk_running)
      {
        ph.bulk_running = GNUNET_NO;
        ph.expecting_solution = GNUNET_YES;
        ph.env.sf.s_bulk_stop (ph.solver);
      }
      else
      {
        GNUNET_break (0);
      }

      /* Problem is solved by the solver here due to unlocking */

      ph.expecting_solution = GNUNET_NO;
      /* Disable bulk to solve the problem */
      if (GNUNET_NO == ph.bulk_running)
      {
        ph.env.sf.s_bulk_start (ph.solver);
        ph.bulk_running = GNUNET_YES;
      }
#if 0
      if ((0 < ph.opt_update_quantity) || (0 < ph.opt_update_percent))
      {
        /* Update */
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
            "Updating problem with %u peers and %u addresses\n", cp + 1, ca);
        //ph.env.sf.s_bulk_start (ph.solver);
        //update_addresses (cp + 1, ca, ph.opt_update_quantity);
        //ph.env.sf.s_bulk_stop (ph.solver);
      }
#endif
    }
  }
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Done, cleaning up addresses\n");
  if (GNUNET_NO == ph.bulk_running)
  {
    ph.env.sf.s_bulk_start (ph.solver);
    ph.bulk_running = GNUNET_YES;
  }

  for (cp = 0; cp < count_p; cp++)
  {
    for (cur = ph.peers[cp].head; cur != NULL ; cur = next)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Deleting addresses for peer %u\n", cp);
      GNUNET_CONTAINER_multipeermap_remove (ph.addresses, &ph.peers[cp].id, cur);
      ph.env.sf.s_del (ph.solver, cur, GNUNET_NO);
      next = cur->next;
      GNUNET_CONTAINER_DLL_remove(ph.peers[cp].head, ph.peers[cp].tail, cur);
      GNUNET_free(cur);
    }

  }
  GNUNET_free(ph.peers);

  evaluate ();
}


static void
run (void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log_setup ("perf-ats-solver", "WARNING", NULL);
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
      quotas_out, quotas_in, GNUNET_ATS_NetworkTypeCount))
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
  ph.env.info_cb = &solver_info_cb;
  ph.env.info_cb_cls = NULL;

  int networks[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    ph.env.networks[c] = networks[c];
    ph.env.out_quota[c] = quotas_out[c];
    ph.env.in_quota[c] = quotas_in[c];
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Loading network quotas: `%s' %llu %llu \n",
        GNUNET_ATS_print_network_type(ph.env.networks[c]),
        ph.env.out_quota[c],
        ph.env.in_quota[c]);
  }
  GAS_normalization_start (NULL, NULL, &normalized_property_changed_cb, NULL );

  GNUNET_asprintf (&plugin, "libgnunet_plugin_ats_%s", ph.ats_string);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Initializing solver `%s'\n"), ph.ats_string);
  if  (NULL == (ph.solver = GNUNET_PLUGIN_load (plugin, &ph.env)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Failed to initialize solver `%s'!\n"), plugin);
    ret = 1;
    return;
  }

  /* Do work */
  perf_run ();

  /* Unload solver*/
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Unloading solver `%s'\n"), ph.ats_string);
  GNUNET_PLUGIN_unload (plugin, ph.solver);
  GNUNET_free (plugin);
  ph.solver = NULL;
}

int
main (int argc, char *argv[])
{
  /* extract command line arguments */
  ph.opt_update_quantity = 0;
  ph.opt_update_percent = 0;
  ph.N_peers_start = 0;
  ph.N_peers_end = 0;
  ph.N_address = 0;
  ph.ats_string = NULL;
  ph.create_plot = GNUNET_NO;

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
      { 'g', "gnuplot", NULL,
          gettext_noop ("create GNUplot file"),
          0, &GNUNET_GETOPT_set_one, &ph.create_plot},
      GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run (argc, argv, argv[0], NULL, options, &run, argv[0]);

  return ret;
}

/* end of file perf_ats_solver.c */

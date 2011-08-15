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
 * @file transport/gnunet-service-transport_ats.h
 * @brief common internal definitions for transport service's ats code
 * @author Matthias Wachs
 */
#ifndef GNUNET_SERVICE_TRANSPORT_ATS_H
#define GNUNET_SERVICE_TRANSPORT_ATS_H

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_time_lib.h"


#if HAVE_LIBGLPK
#include <glpk.h>
#endif

/*
 *  ATS defines
 */

#define DEBUG_ATS GNUNET_NO
#define VERBOSE_ATS GNUNET_NO


/* Minimum time between to calculations*/
#define ATS_MIN_INTERVAL  GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 15)
#define ATS_EXEC_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)
#define ATS_MAX_EXEC_DURATION GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define ATS_MAX_ITERATIONS INT_MAX

#define ATS_DEFAULT_D 1.0
#define ATS_DEFAULT_U 1.0
#define ATS_DEFAULT_R 1.0
#define ATS_DEFAULT_B_MIN 64000
#define ATS_DEFAULT_N_MIN 10

#define VERY_BIG_DOUBLE_VALUE 100000000000LL


/*
 * Callback Functions
 */

struct ATS_mechanism;
struct ATS_peer;

typedef void (*GNUNET_TRANSPORT_ATS_AddressNotification) (struct ATS_peer **
                                                          peers, int *c_p,
                                                          struct ATS_mechanism
                                                          ** mechanisms,
                                                          int *c_m);

typedef void (*GNUNET_TRANSPORT_ATS_ResultCallback) (void);

enum ATS_problem_state
{
  /**
   * Problem is new
   */
  ATS_NEW = 0,

  /**
   * Problem quality properties were modified
   */
  ATS_QUALITY_UPDATED = 1,

  /**
   * Problem ressource properties were modified
   */
  ATS_COST_UPDATED = 2,

  /**
   * Problem quality and ressource properties were modified
   */
  ATS_QUALITY_COST_UPDATED = 3,

  /**
   * Problem is modified and needs to be completely recalculated
   * due to e.g. connecting or disconnecting peers
   */
  ATS_MODIFIED = 4,

  /**
   * Problem is unmodified
   */
  ATS_UNMODIFIED = 8
};

/*
*  ATS data structures
*/

struct ATS_internals
{
    /**
     * result of last GLPK run
     * 5 == OPTIMAL
     */
  int solution;

    /**
     * Ressource costs or quality metrics changed
     * update problem before solving
     */
  int modified_resources;

    /**
     * Ressource costs or quality metrics changed, update matrix
     * update problem before solving
     */
  int modified_quality;

    /**
     * Peers have connected or disconnected
     * problem has to be recreated
     */
  int recreate_problem;

    /**
     * Was the available basis invalid and we needed to rerun simplex?
     */
  int simplex_rerun_required;

    /**
     * is problem currently valid and can it be solved
     */
  int valid;

    /**
     * Number of transport mechanisms in the problem
     */
  int c_mechs;

    /**
     * Number of transport mechanisms in the problem
     */
  int c_peers;

    /**
     * row index where quality related rows start
     */
  int begin_qm;

    /**
     * row index where quality related rows end
     */
  int end_qm;

    /**
     * row index where ressource cost related rows start
     */
  int begin_cr;

    /**
     * row index where ressource cost related rows end
     */
  int end_cr;

    /**
     * column index for objective function value d
     */
  int col_d;

    /**
     * column index for objective function value u
     */
  int col_u;

    /**
     * column index for objective function value r
     */
  int col_r;

    /**
     * column index for objective function value quality metrics
     */
  int col_qm;

    /**
     * column index for objective function value cost ressources
     */
  int col_cr;
};

struct ATS_Handle
{
  /*
   *  Callback functions
   */

  GNUNET_TRANSPORT_ATS_AddressNotification addr_notification;

  GNUNET_TRANSPORT_ATS_ResultCallback result_cb;


    /**
     * Statistics handle
     */
  struct GNUNET_STATISTICS_Handle *stats;

    /**
     * Maximum execution time per calculation
     */
  struct GNUNET_TIME_Relative max_exec_duration;

    /**
     * GLPK (MLP) problem object
     */
#if HAVE_LIBGLPK

  glp_prob *prob;
#else
  void *prob;
#endif

    /**
     * Internal information state of the GLPK problem
     */
  struct ATS_internals internal;

    /**
     * mechanisms used in current problem
     * needed for problem modification
     */
  struct ATS_mechanism *mechanisms;

    /**
     * peers used in current problem
     * needed for problem modification
     */
  struct ATS_peer *peers;

    /**
     * State of the MLP problem
     * value of ATS_problem_state
     *
     */
  int state;

    /**
     * number of successful executions
     */
  int successful_executions;

    /**
     * number with an invalid result
     */
  int invalid_executions;

    /**
     * Maximum number of LP iterations per calculation
     */
  int max_iterations;


  /*
   * ATS configuration
   */


    /**
     * Diversity weight
     */
  double D;

    /**
     * Utility weight
     */
  double U;

    /**
     * Relativity weight
     */
  double R;

    /**
     * Minimum bandwidth per peer
     */
  int v_b_min;

    /**
     * Minimum number of connections per peer
     */
  int v_n_min;


    /**
     * Logging related variables
     */


    /**
     * Dump problem to a file?
     */
  int save_mlp;

    /**
     * Dump solution to a file
     */
  int save_solution;

    /**
     * Dump solution when minimum peers:
     */
  int dump_min_peers;

    /**
     * Dump solution when minimum addresses:
     */
  int dump_min_addr;

    /**
     * Dump solution overwrite file:
     */
  int dump_overwrite;
};

struct ATS_mechanism
{
  struct ATS_mechanism *prev;
  struct ATS_mechanism *next;
  struct ForeignAddressList *addr;
  struct ATS_quality_entry *quality;
  struct ATS_ressource_entry *ressources;
  struct TransportPlugin *plugin;
  struct ATS_peer *peer;
  int col_index;
  int id;
  struct ATS_ressource_cost *rc;
};

struct ATS_peer
{
  struct GNUNET_PeerIdentity peer;

  struct ATS_mechanism *m_head;
  struct ATS_mechanism *m_tail;

  /* preference value f */
  double f;

  //struct NeighbourList * n;
};

struct ATS_ressource
{
  /* index in ressources array */
  int index;
  /* depending ATSi parameter to calculcate limits */
  int atis_index;
  /* cfg option to load limits */
  char *cfg_param;
  /* lower bound */
  double c_min;
  /* upper bound */
  double c_max;

  /* cofficients for the specific plugins */
  double c_unix;
  double c_tcp;
  double c_udp;
  double c_http;
  double c_https;
  double c_wlan;
  double c_default;
};


struct ATS_ressource_entry
{
  /* index in ressources array */
  int index;
  /* depending ATSi parameter to calculcate limits */
  int atis_index;
  /* lower bound */
  double c;
};


struct ATS_quality_metric
{
  int index;
  int atis_index;
  char *name;
};

struct ATS_quality_entry
{
  int index;
  int atsi_index;
  uint32_t values[3];
  int current;
};

/*
 * ATS ressources
 */


static struct ATS_ressource ressources[] = {
  /* FIXME: the coefficients for the specific plugins */
  {1, 7, "LAN_BW_LIMIT", 0, VERY_BIG_DOUBLE_VALUE, 0, 1, 1, 2, 2, 1, 3},
  {2, 7, "WAN_BW_LIMIT", 0, VERY_BIG_DOUBLE_VALUE, 0, 1, 1, 2, 2, 2, 3},
  {3, 4, "WLAN_ENERGY_LIMIT", 0, VERY_BIG_DOUBLE_VALUE, 0, 0, 0, 0, 0, 2, 1}
/*
    {4, 4, "COST_ENERGY_CONSUMPTION", VERY_BIG_DOUBLE_VALUE},
    {5, 5, "COST_CONNECT", VERY_BIG_DOUBLE_VALUE},
    {6, 6, "COST_BANDWITH_AVAILABLE", VERY_BIG_DOUBLE_VALUE},
    {7, 7, "COST_NETWORK_OVERHEAD", VERY_BIG_DOUBLE_VALUE},*/
};

#define available_ressources (sizeof(ressources)/sizeof(*ressources))

/*
 * ATS quality metrics
 */

static struct ATS_quality_metric qm[] = {
  {1, 1028, "QUALITY_NET_DISTANCE"},
  {2, 1034, "QUALITY_NET_DELAY"},
};

#define available_quality_metrics (sizeof(qm)/sizeof(*qm))


/*
 * ATS functions
 */
struct ATS_Handle *ats_init (double D, double U, double R, int v_b_min,
                             int v_n_min, int max_iterations,
                             struct GNUNET_TIME_Relative max_duration,
                             GNUNET_TRANSPORT_ATS_AddressNotification
                             address_not,
                             GNUNET_TRANSPORT_ATS_ResultCallback res_cb);

void ats_shutdown (struct ATS_Handle *ats);

void ats_delete_problem (struct ATS_Handle *ats);

int ats_create_problem (struct ATS_Handle *ats, struct ATS_internals *stat,
                        struct ATS_peer *peers, int c_p,
                        struct ATS_mechanism *mechanisms, int c_m);

void ats_modify_problem_state (struct ATS_Handle *ats,
                               enum ATS_problem_state s);

void ats_calculate_bandwidth_distribution (struct ATS_Handle *ats);

void ats_solve_problem (struct ATS_Handle *ats, unsigned int max_it,
                        unsigned int max_dur, unsigned int c_peers,
                        unsigned int c_mechs, struct ATS_internals *stat);

int ats_evaluate_results (int result, int solution, char *problem);

void ats_update_problem_qm (struct ATS_Handle *ats);

void ats_update_problem_cr (struct ATS_Handle *ats);


void ats_set_logging_options (struct ATS_Handle *ats,
                              struct GNUNET_STATISTICS_Handle *stats,
                              const struct GNUNET_CONFIGURATION_Handle *cfg);

#endif
/* end of file gnunet-service-transport_ats.h */

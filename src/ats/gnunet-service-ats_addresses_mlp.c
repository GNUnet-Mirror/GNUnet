/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_addresses_mlp.c
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_addresses_mlp.h"
#include "gnunet_statistics_service.h"
#include "glpk.h"

/**
 *
 * NOTE: Do not modify this documentation. This documentation is based on
 * gnunet.org:/vcs/fsnsg/ats-paper.git/tech-doku/ats-tech-guide.tex
 * use build_txt.sh to generate plaintext output
 *
 *    The MLP solver (mlp) tries to finds an optimal bandwidth assignmentby
 *    optimizing an mixed integer programming problem. The MLP solver uses a
 *    number of constraints to find the best adddress for a peer and an optimal
 *    bandwidth assignment. mlp uses the GNU Linear Programming Kit to solve the
 *    MLP problem.
 *
 *    We defined a constraint system to find an optimal bandwidth assignment.
 *    This constraint system uses as an input data addresses, bandwidth quotas,
 *    preferences and quality values. This constraint system is stored in an
 *    matrix based equotation system.
 *
 *   5 Using GLPK
 *
 *    A (M)LP problem consists of a target function to optimizes, constraints
 *    and rows and columns. FIXME GLP uses three arrays to index the matrix: two
 *    integer arrays storing the row and column indices in the matrix and an
 *    float array to store the coeeficient.
 *
 *    To solve the problem we first find an initial solution for the LP problem
 *    using the LP solver and then find an MLP solution based on this solution
 *    using the MLP solver.
 *
 *    Solving (M)LP problems has the property that finding an initial solution
 *    for the LP problem is computationally expensive and finding the MLP
 *    solution is cheaper. This is especially interesting an existing LP
 *    solution can be reused if only coefficients in the matrix have changed
 *    (addresses updated). Only when the problem size changes (addresses added
 *    or deleted) a new LP solution has to be found.
 *
 *    Intended usage
 *    The mlp solver solves the bandwidth assignment problem only on demand when
 *    an address suggestion is requested. When an address is requested mlp the
 *    solves the mlp problem and if the active address or the bandwidth assigned
 *    changes it calls the callback to addresses. The mlp solver gets notified
 *    about new addresses (adding sessions), removed addresses (address
 *    deletions) and address updates. To benefit from the mlp properties
 *    mentioned in section 5 the solver rembers if since the last solution
 *    addresses were added or deleted (problem size changed, problem has to be
 *    rebuild and solved from sratch) or if addresses were updated and the
 *    existing solution can be reused.
 *
 *     5.1 Input data
 *
 *    The quotas for each network segment are passed by addresses. MLP can be
 *    adapted using configuration settings and uses the following parameters:
 *      * MLP_MAX_DURATION:
 *        Maximum duration for a MLP solution procees (default: 3 sec.)
 *      * MLP_MAX_DURATION:
 *        Maximum number of iterations for a MLP solution process (default:
 *        1024)
 *      * MLP_MIN_CONNECTIONS:
 *        Minimum number of desired connections (default: 4)
 *      * MLP_MIN_BANDWIDTH:
 *        Minimum amount of bandwidth assigned to an address (default: 1024)
 *      * MLP_COEFFICIENT_D:
 *        Diversity coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_R:
 *        Relativity coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_U:
 *        Utilization coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_D:
 *        Diversity coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DELAY:
 *        Quality delay coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *
 *     5.2 Data structures used
 *
 *    mlp has for each known peer a struct ATS_Peer containing information about
 *    a specific peer. The address field solver_information contains information
 *    about the mlp properties of this address.
 *
 *     5.3 Initializing
 *
 *    During initialization mlp initializes the GLPK libray used to solve the
 *    MLP problem: it initializes the glpk environment and creates an initial LP
 *    problem. Next it loads the configuration values from the configuration or
 *    uses the default values configured in -addresses_mlp.h. The quotas used
 *    are given by addresses but may have to be adjusted. mlp uses a upper limit
 *    for the bandwidth assigned called BIG M and a minimum amount of bandwidth
 *    an address gets assigned as well as a minium desired number of
 *    connections. If the configured quota is bigger than BIG M, it is reduced
 *    to BIG M. If the configured quota is smaller than MLP_MIN_CONNECTIONS
 *    *MLP_MIN_BANDWIDTH it is increased to this value.
 *
 *     5.4 Shutdown

 */

#define LOG(kind,...) GNUNET_log_from (kind, "ats-mlp",__VA_ARGS__)

#define WRITE_MLP GNUNET_NO
#define DEBUG_MLP_PROBLEM_CREATION GNUNET_NO
#define VERBOSE_GLPK GNUNET_NO
#define TEST_MAX_BW_ASSIGNMENT GNUNET_YES

/**
 * Intercept GLPK terminal output
 * @param info the mlp handle
 * @param s the string to print
 * @return 0: glpk prints output on terminal, 0 != surpress output
 */
static int
mlp_term_hook (void *info, const char *s)
{
  /* Not needed atm struct MLP_information *mlp = info; */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s", s);
  return 1;
}


/**
 * Reset peers for next problem creation
 *
 * @param cls not used
 * @param key the key
 * @param value ATS_Peer
 * @return GNUNET_OK
 */
static int
reset_peers (void *cls, const struct GNUNET_HashCode * key, void *value)
 {
	 struct ATS_Peer *peer = value;
	 peer->processed = GNUNET_NO;
	 return GNUNET_OK;
 }

/**
 * Delete the MLP problem and free the constrain matrix
 *
 * @param mlp the MLP handle
 */
static void
mlp_delete_problem (struct GAS_MLP_Handle *mlp)
{
  if (mlp != NULL)
  {
    if (mlp->p.prob != NULL)
      glp_delete_prob(mlp->p.prob);

    /* delete row index */
    if (mlp->p.ia != NULL)
    {
      GNUNET_free (mlp->p.ia);
      mlp->p.ia = NULL;
    }

    /* delete column index */
    if (mlp->p.ja != NULL)
    {
      GNUNET_free (mlp->p.ja);
      mlp->p.ja = NULL;
    }

    /* delete coefficients */
    if (mlp->p.ar != NULL)
    {
      GNUNET_free (mlp->p.ar);
      mlp->p.ar = NULL;
    }
    mlp->p.ci = 0;
    mlp->p.prob = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (mlp->peers, &reset_peers, NULL);
}


/**
 * Translate ATS properties to text
 * Just intended for debugging
 *
 * @param ats_index the ATS index
 * @return string with result
 */
const char *
mlp_ats_to_string (int ats_index)
{
  switch (ats_index) {
    case GNUNET_ATS_ARRAY_TERMINATOR:
      return "GNUNET_ATS_ARRAY_TERMINATOR";
    case GNUNET_ATS_UTILIZATION_UP:
      return "GNUNET_ATS_UTILIZATION_UP";
    case GNUNET_ATS_UTILIZATION_DOWN:
      return "GNUNET_ATS_UTILIZATION_DOWN";
    case GNUNET_ATS_COST_LAN:
      return "GNUNET_ATS_COST_LAN";
    case GNUNET_ATS_COST_WAN:
      return "GNUNET_ATS_COST_LAN";
    case GNUNET_ATS_COST_WLAN:
      return "GNUNET_ATS_COST_WLAN";
    case GNUNET_ATS_NETWORK_TYPE:
      return "GNUNET_ATS_NETWORK_TYPE";
    case GNUNET_ATS_QUALITY_NET_DELAY:
      return "GNUNET_ATS_QUALITY_NET_DELAY";
    case GNUNET_ATS_QUALITY_NET_DISTANCE:
      return "GNUNET_ATS_QUALITY_NET_DISTANCE";
    default:
      GNUNET_break (0);
      return "unknown";
  }
}

/**
 * Translate glpk status error codes to text
 * @param retcode return code
 * @return string with result
 */
const char *
mlp_status_to_string (int retcode)
{
  switch (retcode) {
    case GLP_UNDEF:
      return "solution is undefined";
    case GLP_FEAS:
      return "solution is feasible";
    case GLP_INFEAS:
      return "solution is infeasible";
    case GLP_NOFEAS:
      return "no feasible solution exists";
    case GLP_OPT:
      return "solution is optimal";
    case GLP_UNBND:
      return "solution is unbounded";
    default:
      GNUNET_break (0);
      return "unknown error";
  }
}

/**
 * Translate glpk solver error codes to text
 * @param retcode return code
 * @return string with result
 */
const char *
mlp_solve_to_string (int retcode)
{
  switch (retcode) {
    case 0:
      return "ok";
    case GLP_EBADB:
      return "invalid basis";
    case GLP_ESING:
      return "singular matrix";
    case GLP_ECOND:
      return "ill-conditioned matrix";
    case GLP_EBOUND:
      return "invalid bounds";
    case GLP_EFAIL:
      return "solver failed";
    case GLP_EOBJLL:
      return "objective lower limit reached";
    case GLP_EOBJUL:
      return "objective upper limit reached";
    case GLP_EITLIM:
      return "iteration limit exceeded";
    case GLP_ETMLIM:
      return "time limit exceeded";
    case GLP_ENOPFS:
      return "no primal feasible solution";
    case GLP_ENODFS:
      return "no dual feasible solution";
    case GLP_EROOT:
      return "root LP optimum not provided";
    case GLP_ESTOP:
      return "search terminated by application";
    case GLP_EMIPGAP:
      return "relative mip gap tolerance reached";
    case GLP_ENOFEAS:
      return "no dual feasible solution";
    case GLP_ENOCVG:
      return "no convergence";
    case GLP_EINSTAB:
      return "numerical instability";
    case GLP_EDATA:
      return "invalid data";
    case GLP_ERANGE:
      return "result out of range";
    default:
      GNUNET_break (0);
      return "unknown error";
  }
}


#if 0
/**
 * Find a peer in the DLL
 *
 * @param mlp the mlp handle
 * @param peer the peer to find
 * @return the peer struct
 */
static struct ATS_Peer *
mlp_find_peer (struct GAS_MLP_Handle *mlp, const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Peer *res = mlp->peer_head;
  while (res != NULL)
  {
    if (0 == memcmp (peer, &res->id, sizeof (struct GNUNET_PeerIdentity)))
      break;
    res = res->next;
  }
  return res;
}



#if 0
/**
 * Find the required ATS information for an address
 *
 * @param addr the address
 * @param ats_index the desired ATS index
 *
 * @return the index on success, otherwise GNUNET_SYSERR
 */
static int
mlp_lookup_ats (struct ATS_Address *addr, int ats_index)
{
  struct GNUNET_ATS_Information * ats = addr->ats;
  int c = 0;
  int found = GNUNET_NO;
  for (c = 0; c < addr->ats_count; c++)
  {
    if (ats[c].type == ats_index)
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (found == GNUNET_YES)
    return c;
  else
    return GNUNET_SYSERR;
}
#endif

static void
update_quality (struct GAS_MLP_Handle *mlp, struct ATS_Address * address)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating quality metrics for peer `%s'\n",
      GNUNET_i2s (&address->peer));

  GNUNET_assert (NULL != address);
  GNUNET_assert (NULL != address->solver_information);
//  GNUNET_assert (NULL != address->ats);

  struct MLP_information *mlpi = address->solver_information;
  //struct GNUNET_ATS_Information *ats = address->ats;
  GNUNET_assert (mlpi != NULL);

  int c;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {

    /* FIXME int index = mlp_lookup_ats(address, mlp->q[c]); */
    int index = GNUNET_SYSERR;

    if (index == GNUNET_SYSERR)
      continue;
    /* FIXME
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s' value `%s': %f\n",
        GNUNET_i2s (&address->peer),
        mlp_ats_to_string(mlp->q[c]),
        (double) ats[index].value);

    int i = mlpi->q_avg_i[c];*/
    double * qp = mlpi->q[c];
    /* FIXME
    qp[i] = (double) ats[index].value;
    */

    int t;
    for (t = 0; t < MLP_AVERAGING_QUEUE_LENGTH; t++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s': `%s' queue[%u]: %f\n",
        GNUNET_i2s (&address->peer),
        mlp_ats_to_string(mlp->q[c]),
        t,
        qp[t]);
    }

    if (mlpi->q_avg_i[c] + 1 < (MLP_AVERAGING_QUEUE_LENGTH))
      mlpi->q_avg_i[c] ++;
    else
      mlpi->q_avg_i[c] = 0;


    int c2;
    int c3;
    double avg = 0.0;
    switch (mlp->q[c])
    {
      case GNUNET_ATS_QUALITY_NET_DELAY:
        c3 = 0;
        for (c2 = 0; c2 < MLP_AVERAGING_QUEUE_LENGTH; c2++)
        {
          if (mlpi->q[c][c2] != -1)
          {
            double * t2 = mlpi->q[c] ;
            avg += t2[c2];
            c3 ++;
          }
        }
        if ((c3 > 0) && (avg > 0))
          /* avg = 1 / ((q[0] + ... + q[l]) /c3) => c3 / avg*/
          mlpi->q_averaged[c] = (double) c3 / avg;
        else
          mlpi->q_averaged[c] = 0.0;

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s': `%s' average sum: %f, average: %f, weight: %f\n",
          GNUNET_i2s (&address->peer),
          mlp_ats_to_string(mlp->q[c]),
          avg,
          avg / (double) c3,
          mlpi->q_averaged[c]);

        break;
      case GNUNET_ATS_QUALITY_NET_DISTANCE:
        c3 = 0;
        for (c2 = 0; c2 < MLP_AVERAGING_QUEUE_LENGTH; c2++)
        {
          if (mlpi->q[c][c2] != -1)
          {
            double * t2 = mlpi->q[c] ;
            avg += t2[c2];
            c3 ++;
          }
        }
        if ((c3 > 0) && (avg > 0))
          /* avg = 1 / ((q[0] + ... + q[l]) /c3) => c3 / avg*/
          mlpi->q_averaged[c] = (double) c3 / avg;
        else
          mlpi->q_averaged[c] = 0.0;

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s': `%s' average sum: %f, average: %f, weight: %f\n",
          GNUNET_i2s (&address->peer),
          mlp_ats_to_string(mlp->q[c]),
          avg,
          avg / (double) c3,
          mlpi->q_averaged[c]);

        break;
      default:
        break;
    }

    if ((mlpi->c_b != 0) && (mlpi->r_q[c] != 0))
    {

      /* Get current number of columns */
      int found = GNUNET_NO;
      int cols = glp_get_num_cols(mlp->prob);
      int *ind = GNUNET_malloc (cols * sizeof (int) + 1);
      double *val = GNUNET_malloc (cols * sizeof (double) + 1);

      /* Get the matrix row of quality */
      int length = glp_get_mat_row(mlp->prob, mlp->r_q[c], ind, val);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "cols %i, length %i c_b %i\n", cols, length, mlpi->c_b);
      int c4;
      /* Get the index if matrix row of quality */
      for (c4 = 1; c4 <= length; c4++ )
      {
        if (mlpi->c_b == ind[c4])
        {
          /* Update the value */
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating quality `%s' column `%s' row `%s' : %f -> %f\n",
              mlp_ats_to_string(mlp->q[c]),
              glp_get_col_name (mlp->prob, ind[c4]),
              glp_get_row_name (mlp->prob, mlp->r_q[c]),
              val[c4],
              mlpi->q_averaged[c]);
          val[c4] = mlpi->q_averaged[c];
          found = GNUNET_YES;
          break;
        }
      }

      if (found == GNUNET_NO)
        {

          ind[length+1] = mlpi->c_b;
          val[length+1] = mlpi->q_averaged[c];
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%i ind[%i] val[%i]:  %i %f\n", length+1,  length+1, length+1, mlpi->c_b, mlpi->q_averaged[c]);
          glp_set_mat_row (mlp->prob, mlpi->r_q[c], length+1, ind, val);
        }
      else
        {
        /* Get the index if matrix row of quality */
        glp_set_mat_row (mlp->prob, mlpi->r_q[c], length, ind, val);
        }

      GNUNET_free (ind);
      GNUNET_free (val);
    }
  }
}

#endif



/**
 * Adds the problem constraints for all addresses
 * Required for problem recreation after address deletion
 *
 * @param mlp the mlp handle
 * @param addresses all addresses
 */

static void
mlp_add_constraints_all_addresses (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
  unsigned int n_addresses;
  struct MLP_Problem *p = &mlp->p;
  int c;
  char *name;

  /* Problem matrix*/
  n_addresses = p->num_addresses;

  /* Required indices in the constrain matrix
   *
   * feasibility constraints:
   *
   * c 1) bandwidth capping
   * #rows: |n_addresses|
   * #indices: 2 * |n_addresses|
   *
   * c 2) one active address per peer
   * #rows: |peers|
   * #indices: |n_addresses|
   *
   * c 3) minium bandwidth assigned
   * #rows: |n_addresses|
   * #indices: 2 * |n_addresses|
   *
   * c 4) minimum number of active connections
   * #rows: 1
   * #indices: |n_addresses|
   *
   * c 5) maximum ressource consumption
   * #rows: |ressources|
   * #indices: |n_addresses|
   *
   * c 10) obey network specific quota
   * #rows: |network types
   * #indices: |n_addresses|
   *
   * Sum for feasibility constraints:
   * #rows: 3 * |n_addresses| +  |ressources| + |peers| + 1
   * #indices: 7 * |n_addresses|
   *
   * optimality constraints:
   *
   * c 6) diversity
   * #rows: 1
   * #indices: |n_addresses| + 1
   *
   * c 7) quality
   * #rows: |quality properties|
   * #indices: |n_addresses| + |quality properties|
   *
   * c 8) utilization
   * #rows: 1
   * #indices: |n_addresses| + 1
   *
   * c 9) relativity
   * #rows: |peers|
   * #indices: |n_addresses| + |peers|
   * */

  /* last +1 caused by glpk index starting with one: [1..pi]*/
  int pi = ((7 * n_addresses) + (5 * n_addresses +  mlp->pv.m_q + p->num_peers + 2) + 1);
  p->ci = 1;

  /* row index */
  int *ia = GNUNET_malloc (pi * sizeof (int));
  p->ia = ia;

  /* column index */
  int *ja = GNUNET_malloc (pi * sizeof (int));
  p->ja = ja;

  /* coefficient */
  double *ar= GNUNET_malloc (pi * sizeof (double));
  p->ar = ar;

  /* Adding constraint rows
   * This constraints are kind of "for all addresses"
   * Feasibility constraints:
   *
   * c 1) bandwidth capping
   * c 3) minimum bandwidth
   * c 4) minimum number of connections
   * c 6) maximize diversity
   * c 10) obey network specific quota
   */


  /* Adding constraint rows
   * This constraints are kind of "for all peers"
   * Feasibility constraints:
   *
   * c 2) 1 address per peer
   * sum (n_p1_1 + ... + n_p1_n) = 1
   *
   * c 8) utilization
   * sum (f_p * b_p1_1 + ... + f_p * b_p1_n) - u = 0
   *
   * c 9) relativity
   * V p : sum (bt_1 + ... +bt_n) - f_p * r = 0
   * */

#if 0
  struct ATS_Peer * peer = mlp->peer_head;
  /* For all peers */
  while (peer != NULL)
  {
    struct ATS_Address *addr = peer->head;
    struct MLP_information *mlpi = NULL;


    /* For all addresses of this peer */
    while (addr != NULL)
    {
      mlpi = (struct MLP_information *) addr->solver_information;

      /* coefficient for c 2) */
      ia[p->ci] = peer->r_c2;
      ja[p->ci] = mlpi->c_n;
      ar[p->ci] = 1;
#if  DEBUG_MLP_PROBLEM_CREATION
			LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Set value [%u,%u] ==  %.2f\n",
					p->ia[p->ci], p->ja[p->ci], p->ar[p->ci]);
#endif
      p->ci++;

      /* coefficient for c 8) */
      ia[p->ci] = p->r_c8;
      ja[p->ci] = mlpi->c_b;
      ar[p->ci] = peer->f;
#if  DEBUG_MLP_PROBLEM_CREATION
			LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Set value [%u,%u] ==  %.2f\n",
					p->ia[p->ci], p->ja[p->ci], p->ar[p->ci]);
#endif
      p->ci++;

      /* coefficient for c 9) */
      ia[p->ci] = peer->r_c9;
      ja[p->ci] = mlpi->c_b;
      ar[p->ci] = 1;
#if  DEBUG_MLP_PROBLEM_CREATION
			LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Set value [%u,%u] ==  %.2f\n",
					p->ia[p->ci], p->ja[p->ci], p->ar[p->ci]);
#endif
      p->ci++;
      addr = addr->next;
    }
    peer = peer->next;
  }
#endif

  /* c 7) For all quality metrics */
  for (c = 0; c < mlp->pv.m_q; c++)
  {
    struct ATS_Peer *tp;
    struct ATS_Address *ta;
    struct MLP_information * mlpi;
    double value = 1.0;

    /* Adding rows for c 7) */
    p->r_q[c] = glp_add_rows (p->prob, 1);
    GNUNET_asprintf(&name, "c7_q%i_%s", c, mlp_ats_to_string(mlp->pv.q[c]));
    glp_set_row_name (p->prob, p->r_q[c], name);
    /* Set row bound == 0 */
    glp_set_row_bnds (p->prob, p->r_q[c], GLP_FX, 0.0, 0.0);
#if  DEBUG_MLP_PROBLEM_CREATION
		LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Added row [%u] `%s': %s %u\n",
				p->r_q[c], name,
				"<=", 0);
#endif
    GNUNET_free (name);

    ia[p->ci] = p->r_q[c];
    ja[p->ci] = p->c_q[c];
    ar[p->ci] = -1;
#if  DEBUG_MLP_PROBLEM_CREATION
		LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Set value [%u,%u] ==  %.2f\n",
				p->ia[p->ci], p->ja[p->ci], p->ar[p->ci]);
#endif
    p->ci++;
#if 0
    for (tp = mlp->peer_head; tp != NULL; tp = tp->next)
      for (ta = tp->head; ta != NULL; ta = ta->next)
        {
          mlpi = ta->solver_information;
          value = mlpi->q_averaged[c];

          mlpi->r_q[c] = p->r_q[c];

          ia[p->ci] = p->r_q[c];
          ja[p->ci] = mlpi->c_b;
          ar[p->ci] = tp->f_q[c] * value;
#if  DEBUG_MLP_PROBLEM_CREATION
          LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Set value [%u,%u] ==  %.2f\n",
          		p->ia[p->ci], p->ja[p->ci], p->ar[p->ci]);
#endif
          p->ci++;
        }
#endif
  }
}



struct CountContext
{
	struct GNUNET_CONTAINER_MultiHashMap * peers;
	int result;
};

static int
mlp_create_problem_count_addresses_it (void *cls, const struct GNUNET_HashCode *key, void *value)
{
	struct CountContext *cctx = cls;
  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(cctx->peers, key))
  	cctx->result++;
  return GNUNET_OK;
}

static int mlp_create_problem_count_addresses (
		struct GNUNET_CONTAINER_MultiHashMap * peers,
		struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
	struct CountContext cctx;
	cctx.peers = peers;
	cctx.result = 0;
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &mlp_create_problem_count_addresses_it, &cctx);
  return cctx.result;
}



static void
mlp_create_problem_set_value (struct MLP_Problem *p,
															int row, int col, double val,
															int line)
{
	if ((p->ci) >= p->num_elements)
	{
		LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: line %u: Request for index %u bigger than array size of %u\n",
				line, p->ci + 1, p->num_elements);
		GNUNET_break (0);
		return;
	}
	if ((0 == row) || (0 == col))
		GNUNET_break (0);
  p->ia[p->ci] = row ;
  p->ja[p->ci] = col;
  p->ar[p->ci] = val;
#if  DEBUG_MLP_PROBLEM_CREATION
	LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: line %u: Set value [%u,%u] in index %u ==  %.2f\n",
			line, p->ia[p->ci], p->ja[p->ci], p->ci, p->ar[p->ci]);
#endif
  p->ci++;
}

static int
mlp_create_problem_create_column (struct MLP_Problem *p, char *name,
		unsigned int type, unsigned int bound, double lb, double ub,
		double coef)
{
	int col = glp_add_cols (p->prob, 1);
  glp_set_col_name (p->prob, col, name);
  glp_set_col_bnds (p->prob, col, bound, lb, ub);
  glp_set_col_kind (p->prob, col, type);
  glp_set_obj_coef (p->prob, col, coef);
#if  DEBUG_MLP_PROBLEM_CREATION
	LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Added column [%u] `%s': %.2f\n",
			col, name, coef);
#endif
  return col;
}

static int
mlp_create_problem_create_constraint (struct MLP_Problem *p, char *name,
		unsigned int bound, double lb, double ub)
{
	char * op;
  int row = glp_add_rows (p->prob, 1);
  /* set row name */
  glp_set_row_name (p->prob, row, name);
  /* set row bounds: <= 0 */
  glp_set_row_bnds (p->prob, row, bound, lb, ub);
  switch (bound) {
		case GLP_UP:
			GNUNET_asprintf(&op, "-inf <= x <= %.2f", ub);
			break;
		case GLP_DB:
			GNUNET_asprintf(&op, "%.2f <= x <= %.2f", lb, ub);
			break;
		case GLP_FX:
			GNUNET_asprintf(&op, "%.2f == x == %.2f", lb, ub);
			break;
		case GLP_LO:
			GNUNET_asprintf(&op, "%.2f <= x <= inf", lb);
			break;
		default:
			GNUNET_asprintf(&op, "ERROR");
			break;
	}
#if  DEBUG_MLP_PROBLEM_CREATION
		LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Added row [%u] `%s': %s\n",
				row, name, op);
#endif
	GNUNET_free (op);
	return row;
}

/**
 * Create the
 * - address columns b and n
 * - address dependent constraint rows c1, c3
 * - peer dependent rows c2 and c9
 * - Set address dependent entries in problem matrix as well
 */
static int
mlp_create_problem_add_address_information (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct MLP_Problem *p = &mlp->p;
  struct ATS_Address *address = value;
  struct ATS_Peer *peer;
  struct MLP_information *mlpi;
  char *name;
  int c;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(mlp->peers, key))
  	return GNUNET_OK;

  /* Get peer */
  peer = GNUNET_CONTAINER_multihashmap_get (mlp->peers, key);
  if (peer->processed == GNUNET_NO)
  {
  		/* Add peer dependent constraints */
  		/* Add constraint c2 */
  	  GNUNET_asprintf(&name, "c2_%s", GNUNET_i2s(&address->peer));
  	  peer->r_c2 = mlp_create_problem_create_constraint (p, name, GLP_FX, 1.0, 1.0);
  		GNUNET_free (name);
  		/* Add constraint c9 */
  	  GNUNET_asprintf(&name, "c9_%s", GNUNET_i2s(&address->peer));
  	  peer->r_c9 = mlp_create_problem_create_constraint (p, name, GLP_LO, 0.0, 0.0);
  		GNUNET_free (name);
  	  /* c 9) set coefficient */
  		mlp_create_problem_set_value (p, peer->r_c9, p->c_r, -peer->f, __LINE__);

  		peer->processed = GNUNET_YES;
  }


  /* Prepare solver information */
  if (NULL != address->solver_information)
  {
  	GNUNET_free (address->solver_information);
		address->solver_information = NULL;
  }
  mlpi = GNUNET_malloc (sizeof (struct MLP_information));
  address->solver_information = mlpi;

  /* Add bandwidth column */
  GNUNET_asprintf (&name, "b_%s_%s", GNUNET_i2s (&address->peer), address->plugin);
#if TEST_MAX_BW_ASSIGNMENT
  mlpi->c_b = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 1.0);
#else
  mlpi->c_b = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 0.0);
#endif

  GNUNET_free (name);

  /* Add usage column */
  GNUNET_asprintf (&name, "n_%s_%s", GNUNET_i2s (&address->peer), address->plugin);
  mlpi->c_n = mlp_create_problem_create_column (p, name, GLP_IV, GLP_DB, 0.0, 1.0, 0.0);
  GNUNET_free (name);

	/* Add address dependent constraints */
	/* Add constraint c1) bandwidth capping
   * b_t  + (-M) * n_t <= 0
   * */
  GNUNET_asprintf(&name, "c1_%s_%s", GNUNET_i2s(&address->peer), address->plugin);
  mlpi->r_c1 = mlp_create_problem_create_constraint (p, name, GLP_UP, 0.0, 0.0);
	GNUNET_free (name);

	/*  c1) set b = 1 coefficient */
	mlp_create_problem_set_value (p, mlpi->r_c1, mlpi->c_b, 1, __LINE__);
	/*  c1) set n = -M coefficient */
	mlp_create_problem_set_value (p, mlpi->r_c1, mlpi->c_n, -mlp->pv.BIG_M, __LINE__);

  /* Add constraint c 3) minimum bandwidth
   * b_t + (-n_t * b_min) >= 0
   * */
  GNUNET_asprintf(&name, "c3_%s_%s", GNUNET_i2s(&address->peer), address->plugin);
	mlpi->r_c3 = mlp_create_problem_create_constraint (p, name, GLP_LO, 0.0, 0.0);
	GNUNET_free (name);

	/*  c3) set b = 1 coefficient */
	mlp_create_problem_set_value (p, mlpi->r_c3, mlpi->c_b, 1, __LINE__);
	/*  c3) set n = -b_min coefficient */
	mlp_create_problem_set_value (p, mlpi->r_c3, mlpi->c_n, - ((double )mlp->pv.b_min), __LINE__);


	/* Set coefficient entries in invariant rows */
  /* c 4) minimum connections */
	mlp_create_problem_set_value (p, p->r_c4, mlpi->c_n, 1, __LINE__);
  /* c 6) maximize diversity */
	mlp_create_problem_set_value (p, p->r_c6, mlpi->c_n, 1, __LINE__);
  /* c 2) 1 address peer peer */
	mlp_create_problem_set_value (p, peer->r_c2, mlpi->c_n, 1, __LINE__);
  /* c 9) relativity */
	mlp_create_problem_set_value (p, peer->r_c9, mlpi->c_b, 1, __LINE__);
  /* c 8) utility */
	mlp_create_problem_set_value (p, p->r_c8, mlpi->c_b, 1, __LINE__);

  /* c 10) obey network specific quotas
   * (1)*b_1 + ... + (1)*b_m <= quota_n
   */
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    if (mlp->pv.quota_index[c] == address->atsp_network_type)
    {
  		mlp_create_problem_set_value (p, p->r_quota[c], mlpi->c_b, 1, __LINE__);
      break;
    }
  }

  /* c 7) Optimize quality */
  /* For all quality metrics, set quality of this address */
  for (c = 0; c < mlp->pv.m_q; c++)
    	mlp_create_problem_set_value (p, p->r_q[c], mlpi->c_b, mlpi->q_averaged[c], __LINE__);


  return GNUNET_OK;
}

/**
 * Create the invariant columns c4, c6, c10, c8, c7
 */
static void
mlp_create_problem_add_invariant_rows (struct GAS_MLP_Handle *mlp, struct MLP_Problem *p)
{
  char *name;
  int c;

  /* Row for c4) minimum connection */

  /* Number of minimum connections is min(|Peers|, n_min) */
  p->r_c4 = mlp_create_problem_create_constraint (p, "c4", GLP_LO, (mlp->pv.n_min > p->num_peers) ? p->num_peers : mlp->pv.n_min, 0.0);

  /* Add row for c6) */
	p->r_c6 = mlp_create_problem_create_constraint (p, "c6", GLP_FX, 0.0, 0.0);
  /* c6 )Setting -D */
	mlp_create_problem_set_value (p, p->r_c6, p->c_d, -1, __LINE__);

  /* Add rows for c 10) */
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
      char * text;
      GNUNET_asprintf(&text, "c10_quota_ats_%s", GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]));
  		p->r_quota[c] = mlp_create_problem_create_constraint (p, text, GLP_DB, 0.0, mlp->pv.quota_out[c]);
  		GNUNET_free (text);
  }

  /* Adding rows for c 8) */
  p->r_c8 = mlp_create_problem_create_constraint (p, "c8", GLP_FX, 0.0, 0.0);
  /* -u */
	mlp_create_problem_set_value (p, p->r_c8, p->c_u, -1, __LINE__);

	/* c 7) For all quality metrics */
	for (c = 0; c < mlp->pv.m_q; c++)
	{
		GNUNET_asprintf(&name, "c7_q%i_%s", c, mlp_ats_to_string(mlp->pv.q[c]));
		p->r_q[c] = mlp_create_problem_create_constraint (p, name, GLP_FX, 0.0, 0.0);
		GNUNET_free (name);
		mlp_create_problem_set_value (p, p->r_q[c], p->c_q[c], -1, __LINE__);
	}
}


/**
 * Create the invariant columns d, u, r, q0 ... qm
 */
static void
mlp_create_problem_add_invariant_columns (struct GAS_MLP_Handle *mlp, struct MLP_Problem *p)
{
  char *name;
  int c;

#if TEST_MAX_BW_ASSIGNMENT
  mlp->pv.co_D = 0.0;
  mlp->pv.co_U = 0.0;
  mlp->pv.co_R = 0.0;
#endif

  /* Diversity d column  */
  p->c_d = mlp_create_problem_create_column (p, "d", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_D);

  /* Utilization u column  */
  p->c_u = mlp_create_problem_create_column (p, "u", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_U);

  /* Relativity r column  */
  p->c_r = mlp_create_problem_create_column (p, "r", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_R);

  /* Quality metric columns */
  for (c = 0; c < mlp->pv.m_q; c++)
  {
    GNUNET_asprintf (&name, "q_%u", mlp->pv.q[c]);
#if TEST_MAX_BW_ASSIGNMENT
  	p->c_q[c] = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 0.0);
#else
  	p->c_q[c] = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_Q[c]);
#endif
  	GNUNET_free (name);
  }
}


/**
 * Create the MLP problem
 *
 * @param mlp the MLP handle
 * @param addresses the hashmap containing all adresses
 * @return GNUNET_OK or GNUNET_SYSERR
 */
static int
mlp_create_problem (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
  struct MLP_Problem *p = &mlp->p;
	int res = GNUNET_OK;

  GNUNET_assert (p->prob == NULL);
  GNUNET_assert (p->ia == NULL);
  GNUNET_assert (p->ja == NULL);
  GNUNET_assert (p->ar == NULL);
  /* Reset MLP problem struct */

  /* create the glpk problem */
  p->prob = glp_create_prob ();
  GNUNET_assert (NULL != p->prob);
  p->num_peers = GNUNET_CONTAINER_multihashmap_size (mlp->peers);
  p->num_addresses = mlp_create_problem_count_addresses (mlp->peers, addresses);

  /* Create problem matrix: 10 * #addresses + #q * #addresses + #q, + #peer + 2 + 1 */
  p->num_elements = (10 * p->num_addresses + mlp->pv.m_q * p->num_addresses +  mlp->pv.m_q + p->num_peers + 2 + 1);
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Rebuilding problem for %u peer(s) and %u addresse(s) and %u quality metrics == %u elements\n",
			p->num_peers, p->num_addresses, mlp->pv.m_q, p->num_elements);

  /* Set a problem name */
  glp_set_prob_name (p->prob, "GNUnet ATS bandwidth distribution");
  /* Set optimization direction to maximize */
  glp_set_obj_dir (p->prob, GLP_MAX);

  /* Create problem matrix */
  /* last +1 caused by glpk index starting with one: [1..elements]*/
  p->ci = 1;
  /* row index */
  int *ia = GNUNET_malloc (p->num_elements * sizeof (int));
  p->ia = ia;
  /* column index */
  int *ja = GNUNET_malloc (p->num_elements * sizeof (int));
  p->ja = ja;
  /* coefficient */
  double *ar= GNUNET_malloc (p->num_elements * sizeof (double));
  p->ar = ar;

  /* Adding invariant columns */
  mlp_create_problem_add_invariant_columns (mlp, p);

  /* Adding address independent constraint rows */
  mlp_create_problem_add_invariant_rows (mlp, p);

  /* Adding address independent constraint rows */
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &mlp_create_problem_add_address_information, mlp);

  /* Load the matrix */
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Loading matrix\n");
  glp_load_matrix(p->prob, (p->ci)-1, p->ia, p->ja, p->ar);

  return res;
}

/**
 * Solves the LP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
static int
mlp_solve_lp_problem (struct GAS_MLP_Handle *mlp)
{
	int res = 0;
	if (GNUNET_YES == mlp->mlp_prob_changed)
	{
		/* Problem was recreated: use LP presolver */
    mlp->control_param_lp.presolve = GLP_ON;
	}
	else
	{
		/* Problem was not recreated: do not use LP presolver */
		mlp->control_param_lp.presolve = GLP_OFF;
	}

	res = glp_simplex(mlp->p.prob, &mlp->control_param_lp);
	if (0 == res)
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem: 0x%02X %s\n", res, mlp_solve_to_string(res));
	else
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem failed: 0x%02X %s\n", res, mlp_solve_to_string(res));

  /* Analyze problem status  */
  res = glp_get_status (mlp->p.prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem: 0x%02X %s\n",
      		res, mlp_status_to_string(res));
      return GNUNET_OK;
    /* Problem was ill-defined, no way to handle that */
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem failed, no solution: 0x%02X %s\n",
      		res, mlp_status_to_string(res));
      return GNUNET_SYSERR;
  }
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_solve_mlp_problem (struct GAS_MLP_Handle *mlp)
{
	int res = 0;
	res = glp_intopt(mlp->p.prob, &mlp->control_param_mlp);
	if (0 == res)
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving MLP problem: 0x%02X %s\n", res, mlp_solve_to_string(res));
	else
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving MLP problem failed: 0x%02X %s\n", res, mlp_solve_to_string(res));
  /* Analyze problem status  */
  res = glp_mip_status(mlp->p.prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving MLP problem: %s\n", mlp_status_to_string(res));
      return GNUNET_OK;
    /* Problem was ill-defined, no way to handle that */
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG,"Solving MLP problem failed, %s\n\n", mlp_status_to_string(res));
      return GNUNET_SYSERR;
  }
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_propagate_results (void *cls, const struct GNUNET_HashCode *key, void *value)
{
	struct GAS_MLP_Handle *mlp = cls;
	struct ATS_Address *address;
	struct MLP_information *mlpi;
	double mlp_bw = NaN;
	double mlp_use = NaN;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(mlp->peers, key))
  	return GNUNET_OK;
  address = value;
  GNUNET_assert (address->solver_information != NULL);
  mlpi = address->solver_information;

  mlp_bw = glp_mip_col_val(mlp->p.prob, mlpi->c_b);
  mlp_use = glp_mip_col_val(mlp->p.prob, mlpi->c_n);

  if ((GLP_YES == mlp_use) && (GNUNET_NO == address->active))
  {
  	/* Address switch: Activate address*/
  	LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %f : enabling address\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw);
		address->active = GNUNET_YES;
		address->assigned_bw_in.value__ = htonl (mlp_bw);
		address->assigned_bw_out.value__ = htonl (mlp_bw);
		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
  }
  else if ((GLP_NO == mlp_use) && (GNUNET_YES == address->active))
  {
		/* Address switch: Disable address*/
  	LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %f : disabling address\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw);
		address->active = GNUNET_NO;
		/* Set bandwidth to 0 */
		address->assigned_bw_in.value__ = htonl (0);
		address->assigned_bw_out.value__ = htonl (0);
		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
  }
  else if ((mlp_bw != ntohl(address->assigned_bw_out.value__)) ||
  				 (mlp_bw != ntohl(address->assigned_bw_in.value__)))
  {
  	/* Bandwidth changed */
		LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %f : bandwidth changed\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw);
		address->assigned_bw_in.value__ = htonl (mlp_bw);
		address->assigned_bw_out.value__ = htonl (mlp_bw);
		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %f : no change\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw);
  }

  return GNUNET_OK;
}




/**
 * Solves the MLP problem
 *
 * @param solver the MLP Handle
 * @param addresses the address hashmap
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
GAS_mlp_solve_problem (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
	struct GAS_MLP_Handle *mlp = solver;
	int res = 0;
	struct GNUNET_TIME_Absolute start_lp;
	struct GNUNET_TIME_Relative duration_lp;
	struct GNUNET_TIME_Absolute start_mlp;
	struct GNUNET_TIME_Relative duration_mlp;
	GNUNET_assert (NULL != solver);

	if ((GNUNET_NO == mlp->mlp_prob_changed) && (GNUNET_NO == mlp->mlp_prob_updated))
	{
		LOG (GNUNET_ERROR_TYPE_DEBUG, "No changes to problem\n");
		return GNUNET_OK;
	}

	if (GNUNET_YES == mlp->mlp_prob_changed)
	{
			LOG (GNUNET_ERROR_TYPE_DEBUG, "Problem size changed, rebuilding\n");
			mlp_delete_problem (mlp);
			mlp_create_problem (mlp, addresses);
	}
	else
	{
			LOG (GNUNET_ERROR_TYPE_DEBUG, "Problem was updated, resolving\n");
	}


	/* Run LP solver */
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Running LP solver \n");
	start_lp = GNUNET_TIME_absolute_get();
	res = mlp_solve_lp_problem (mlp);
	duration_lp = GNUNET_TIME_absolute_get_duration (start_lp);

  /* Run LP solver */
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Running MLP solver \n");
	start_mlp = GNUNET_TIME_absolute_get();
	res = mlp_solve_mlp_problem (mlp);
	duration_mlp = GNUNET_TIME_absolute_get_duration (start_mlp);
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Solver took LP %llu ms,  MLP %llu ms\n",
			(unsigned long long) duration_lp.rel_value,
			(unsigned long long) duration_mlp.rel_value);

	/* Propagate result*/
	if (GNUNET_OK == res)
	{
		GNUNET_CONTAINER_multihashmap_iterate (addresses, &mlp_propagate_results, mlp);
	}

	/* Store LP */
#if WRITE_MLP
	char *filename;
	struct GNUNET_TIME_Absolute time = GNUNET_TIME_absolute_get();
	GNUNET_asprintf (&filename, "problem_%llu.lp", time.abs_value);
	glp_write_prob (mlp->p.prob, 0, filename);
	GNUNET_free (filename);
	GNUNET_asprintf (&filename, "problem_%llu.sol", time.abs_value);
	glp_print_sol(mlp->p.prob, filename);
	GNUNET_free (filename);
#endif

	/* Reset change and update marker */
	mlp->mlp_prob_updated = GNUNET_NO;
	mlp->mlp_prob_changed = GNUNET_NO;

	return res;

	/* Solve problem */
#if 0
  struct GAS_MLP_Handle *mlp = solver;
  int res;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != ctx);

  /* Check if solving is already running */
  if (GNUNET_YES == mlp->semaphore)
  {
    if (mlp->mlp_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(mlp->mlp_task);
      mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;
    }
    mlp->mlp_task = GNUNET_SCHEDULER_add_delayed (mlp->exec_interval, &mlp_scheduler, mlp);
    return GNUNET_SYSERR;
  }
  mlp->semaphore = GNUNET_YES;

  mlp->last_execution = GNUNET_TIME_absolute_get ();

  ctx->lp_result = GNUNET_SYSERR;
  ctx->mlp_result = GNUNET_SYSERR;
  ctx->lp_duration = GNUNET_TIME_UNIT_FOREVER_REL;
  ctx->mlp_duration = GNUNET_TIME_UNIT_FOREVER_REL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Solve LP problem\n");
#if WRITE_MLP
  char * name;
  static int i;
  i++;
  GNUNET_asprintf(&name, "problem_%i", i);
  glp_write_lp (mlp->prob, 0, name);
  GNUNET_free (name);
# endif

  res = mlp_solve_lp_problem (mlp, ctx);
  ctx->lp_result = res;
  if (res != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "LP Problem solving failed\n");
    mlp->semaphore = GNUNET_NO;
    return GNUNET_SYSERR;
  }

#if WRITE_MLP
  GNUNET_asprintf(&name, "problem_%i_lp_solution", i);
  glp_print_sol (mlp->prob,  name);
  GNUNET_free (name);
# endif


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Solve MLP problem\n");
  res = mlp_solve_mlp_problem (mlp, ctx);
  ctx->mlp_result = res;
  if (res != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MLP Problem solving failed\n");
    mlp->semaphore = GNUNET_NO;
    return GNUNET_SYSERR;
  }
#if WRITE_MLP
  GNUNET_asprintf(&name, "problem_%i_mlp_solution", i);
  glp_print_mip (mlp->prob, name);
  GNUNET_free (name);
# endif

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Problem solved %s (LP duration %llu / MLP duration %llu)\n",
      (GNUNET_OK == res) ? "successfully" : "failed",
      ctx->lp_duration.rel_value,
      ctx->mlp_duration.rel_value);
  /* Process result */
  struct ATS_Peer *p = NULL;
  struct ATS_Address *a = NULL;
  struct MLP_information *mlpi = NULL;

  for (p = mlp->peer_head; p != NULL; p = p->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s'\n", GNUNET_i2s (&p->id));
    for (a = p->head; a != NULL; a = a->next)
    {
      double b = 0.0;
      double n = 0.0;

      mlpi = a->solver_information;

      b = glp_mip_col_val(mlp->prob, mlpi->c_b);
      mlpi->b = b;

      n = glp_mip_col_val(mlp->prob, mlpi->c_n);
      if (n == 1.0)
      {
      	/* This is the address to be used */
        mlpi->n = GNUNET_YES;
      }
      else
      {
      	/* This is the address not used */
        mlpi->n = GNUNET_NO;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tAddress %s %f\n",
          (n == 1.0) ? "[x]" : "[ ]", b);

      /* Notify addresses */
      if ((ntohl(a->assigned_bw_in.value__) != b) ||
      		(ntohl(a->assigned_bw_out.value__) != b) ||
      		(mlpi->n != a->active))
      {
      		a->assigned_bw_in.value__ = htonl(b);
      		a->assigned_bw_out.value__ = htonl(b);
      		a->active = mlpi->n;
      		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, a);
      }
    }
  }

  if (mlp->mlp_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(mlp->mlp_task);
    mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;
  }
  mlp->mlp_task = GNUNET_SCHEDULER_add_delayed (mlp->exec_interval, &mlp_scheduler, mlp);
  mlp->semaphore = GNUNET_NO;
  return res;
#endif
}

/**
 * Add a single address to the solve
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to add
 */
void
GAS_mlp_address_add (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != addresses);
  GNUNET_assert (NULL != address);

	/* TODO Add address here */

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->peers, &address->peer.hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding address for peer `%s' without address request \n", GNUNET_i2s(&address->peer));
  	return;
  }
  if (NULL != address->solver_information)
  {
  		GNUNET_break (0);
  }

	LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding address for peer `%s' with address request \n", GNUNET_i2s(&address->peer));
	/* Problem size changed: new address for peer with pending request */
	mlp->mlp_prob_changed = GNUNET_YES;
	if (GNUNET_YES == mlp->mlp_auto_solve)
		GAS_mlp_solve_problem (solver, addresses);
}

/**
 * Updates a single address in the MLP problem
 *
 * If the address did not exist before in the problem:
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * Otherwise the addresses' values can be updated and the existing base can
 * be reused
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the update address
 * @param session the new session (if changed otherwise current)
 * @param in_use the new address in use state (if changed otherwise current)
 * @param atsi the latest ATS information
 * @param atsi_count the atsi count
 */
void
GAS_mlp_address_update (void *solver,
                        struct GNUNET_CONTAINER_MultiHashMap *addresses,
                        struct ATS_Address *address,
                        uint32_t session,
                        int in_use,
                        const struct GNUNET_ATS_Information *atsi,
                        uint32_t atsi_count)
{
	struct ATS_Peer *p;
	struct GAS_MLP_Handle *mlp = solver;

	GNUNET_assert (NULL != solver);
	GNUNET_assert (NULL != addresses);
	GNUNET_assert (NULL != address);
	GNUNET_assert ((NULL != atsi) || (0 == atsi_count));

	/* TODO Update address here */

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->peers, &address->peer.hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s' without address request \n", GNUNET_i2s(&address->peer));
  	return;
  }
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s' with address request \n", GNUNET_i2s(&address->peer));

	/* Problem size changed: new address for peer with pending request */
	mlp->mlp_prob_updated = GNUNET_YES;
	if (GNUNET_YES == mlp->mlp_auto_solve)
		GAS_mlp_solve_problem (solver, addresses);
  return;

#if 0
  GNUNET_STATISTICS_update (mlp->stats, "# MLP address updates", 1, GNUNET_NO);

  /* We add a new address */
  if (address->solver_information == NULL)
    new = GNUNET_YES;
  else
    new = GNUNET_NO;

  /* Do the update */
  if (new == GNUNET_YES)
  {
    mlpi = GNUNET_malloc (sizeof (struct MLP_information));

    int c;
    for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
    {
      int c2;
      mlpi->r_q[c] = 0;
      for (c2 = 0; c2 < MLP_AVERAGING_QUEUE_LENGTH; c2++)
        mlpi->q[c][c2] = -1.0; /* -1.0: invalid value */
      mlpi->q_avg_i[c] = 0;
      mlpi->q_averaged[c] = 0.0;
    }

    address->solver_information = mlpi;
    mlp->num_addresses ++;
    GNUNET_STATISTICS_update (mlp->stats, "# addresses in MLP", 1, GNUNET_NO);

    /* Check for and add peer */
    struct ATS_Peer *peer = mlp_find_peer (mlp, &address->peer);
    if (peer == NULL)
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding new peer `%s'\n",
          GNUNET_i2s (&address->peer));

      peer = GNUNET_malloc (sizeof (struct ATS_Peer));
      peer->head = NULL;
      peer->tail = NULL;

      int c;
      for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
      {
        peer->f_q[c] = 1.0;
      }
      peer->f = 1.0;

      memcpy (&peer->id, &address->peer, sizeof (struct GNUNET_PeerIdentity));
      GNUNET_assert(address->prev == NULL);
      GNUNET_assert(address->next == NULL);
      GNUNET_CONTAINER_DLL_insert (peer->head, peer->tail, address);
      GNUNET_CONTAINER_DLL_insert (mlp->peer_head, mlp->peer_tail, peer);
      mlp->c_p ++;
      GNUNET_STATISTICS_update (mlp->stats, "# peers in MLP", 1, GNUNET_NO);
    }
    else
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding address to peer `%s'\n",
          GNUNET_i2s (&address->peer));

      GNUNET_CONTAINER_DLL_insert (peer->head, peer->tail, address);
    }
    update_quality (mlp, address);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating existing address to peer `%s'\n",
        GNUNET_i2s (&address->peer));

    update_quality (mlp, address);
  }

  /* Recalculate */
  if (new == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Recreating problem: new address\n");

    mlp_delete_problem (mlp);
    mlp_create_problem (mlp, peers);
    mlp->presolver_required = GNUNET_YES;
  }
  if (mlp->auto_solve == GNUNET_YES)
    GAS_mlp_solve_problem (mlp, &ctx);
#endif
}

/**
 * Deletes a single address in the MLP problem
 *
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * @param solver the MLP Handle
 * @param addresses the address hashmap
 *        the address has to be already removed from the hashmap
 * @param address the address to delete
 * @param session_only delete only session not whole address
 */
void
GAS_mlp_address_delete (void *solver,
    struct GNUNET_CONTAINER_MultiHashMap * addresses,
    struct ATS_Address *address,
    int session_only)
{
	struct ATS_Peer *p;
	struct GAS_MLP_Handle *mlp = solver;

	GNUNET_assert (NULL != solver);
	GNUNET_assert (NULL != addresses);
	GNUNET_assert (NULL != address);

	/* TODO Delete address here */
	if (NULL != address->solver_information)
	{
			GNUNET_free (address->solver_information);
			address->solver_information = NULL;
	}

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->peers, &address->peer.hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Deleting address for peer `%s' without address request \n", GNUNET_i2s(&address->peer));
  	return;
  }
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Deleting address for peer `%s' with address request \n", GNUNET_i2s(&address->peer));

	/* Problem size changed: new address for peer with pending request */
	mlp->mlp_prob_changed = GNUNET_YES;
	if (GNUNET_YES == mlp->mlp_auto_solve)
		GAS_mlp_solve_problem (solver, addresses);
  return;

#if 0
  GNUNET_STATISTICS_update (mlp->stats,"# LP address deletions", 1, GNUNET_NO);
  struct GAS_MLP_SolutionContext ctx;

  /* Free resources */
  if (address->solver_information != NULL)
  {
    GNUNET_free (address->solver_information);
    address->solver_information = NULL;

    mlp->num_addresses --;
    GNUNET_STATISTICS_update (mlp->stats, "# addresses in MLP", -1, GNUNET_NO);
  }

  /* Remove from peer list */
  struct ATS_Peer *head = mlp_find_peer (mlp, &address->peer);
  GNUNET_assert (head != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting address for `%s'\n", GNUNET_i2s (&address->peer));

  GNUNET_CONTAINER_DLL_remove (head->head, head->tail, address);
  if ((head->head == NULL) && (head->tail == NULL))
  {
    /* No address for peer left, remove peer */

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting peer `%s'\n", GNUNET_i2s (&address->peer));

    GNUNET_CONTAINER_DLL_remove (mlp->peer_head, mlp->peer_tail, head);
    GNUNET_free (head);
    mlp->c_p --;
    GNUNET_STATISTICS_update (mlp->stats, "# peers in MLP", -1, GNUNET_NO);
  }

  /* Update problem */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Recreating problem: new address\n");

  mlp_delete_problem (mlp);
  if ((GNUNET_CONTAINER_multihashmap_size (peers) > 0) && (mlp->c_p > 0))
  {
    mlp_create_problem (mlp, peers);

    /* Recalculate */
    mlp->presolver_required = GNUNET_YES;
    if (mlp->auto_solve == GNUNET_YES)
      GAS_mlp_solve_problem (mlp, &ctx);
  }
#endif
}


/**
 * Find the active address in the set of addresses of a peer
 * @param cls destination
 * @param key peer id
 * @param value address
 * @return GNUNET_OK
 */
static int
mlp_get_preferred_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{

  struct ATS_Address *aa = (struct ATS_Address *) cls;
  struct ATS_Address *addr = value;
  struct MLP_information *mlpi = addr->solver_information;
  if (mlpi == NULL)
    return GNUNET_YES;
  if (mlpi->n == GNUNET_YES)
  {
    aa = addr;
    if (mlpi->b > (double) UINT32_MAX)
      aa->assigned_bw_out.value__ = htonl (UINT32_MAX);
    else
      aa->assigned_bw_out.value__ = htonl((uint32_t) mlpi->b);
    aa->assigned_bw_in.value__ = htonl(0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Get the preferred address for a specific peer
 *
 * @param solver the MLP Handle
 * @param addresses address hashmap
 * @param peer the peer
 * @return suggested address
 */
const struct ATS_Address *
GAS_mlp_get_preferred_address (void *solver,
                               struct GNUNET_CONTAINER_MultiHashMap * addresses,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p;
  struct ATS_Address *res = NULL;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != addresses);
  GNUNET_assert (NULL != peer);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Getting preferred address for `%s'\n",
  		GNUNET_i2s (peer));

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->peers, &peer->hashPubKey)))
  {
  	  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding peer `%s' to list of peers with requests\n",
  	  		GNUNET_i2s (peer));

  	  p = GNUNET_malloc (sizeof (struct ATS_Peer));
  	  p->id = (*peer);
  	  GNUNET_CONTAINER_multihashmap_put (mlp->peers, &peer->hashPubKey, p, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  	  /* Added new peer, we have to rebuild problem before solving */
  	  mlp->mlp_prob_changed = GNUNET_YES;
  }
  GAS_mlp_solve_problem (mlp, addresses);

  /* Get prefered address */
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey,
  																						mlp_get_preferred_address_it, res);

  return res;
}


/**
 * Changes the preferences for a peer in the MLP problem
 *
 * @param solver the MLP Handle
 * @param client client
 * @param peer the peer
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_mlp_address_change_preference (void *solver,
                                   void *client,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score)
{
  //struct GAS_MLP_Handle *mlp = solver;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing preference for address for peer `%s'\n",
  		GNUNET_i2s(peer));

  return;
#if 0
  GNUNET_STATISTICS_update (mlp->stats,"# LP address preference changes", 1, GNUNET_NO);

  //struct ATS_Peer *p = mlp_find_peer (mlp, peer);
  //FIXME to finish implementation
  /* Here we have to do the matching */
#endif
}


static int
mlp_free_peers (void *cls, const struct GNUNET_HashCode *key, void *value)
{
	struct GNUNET_CONTAINER_MultiHashMap *map = cls;
	struct ATS_Peer *p = value;

	GNUNET_CONTAINER_multihashmap_remove (map, key, value);
	GNUNET_free (p);

	return GNUNET_OK;
}


/**
 * Shutdown the MLP problem solving component
 *
 * @param solver the solver handle
 */
void
GAS_mlp_done (void *solver)
{
  struct GAS_MLP_Handle *mlp = solver;
  GNUNET_assert (mlp != NULL);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down mlp solver\n");
  mlp_delete_problem (mlp);

  GNUNET_CONTAINER_multihashmap_iterate (mlp->peers, &mlp_free_peers, mlp->peers);
  GNUNET_CONTAINER_multihashmap_destroy (mlp->peers);
  mlp->peers = NULL;

  /* Clean up GLPK environment */
  glp_free_env();
  GNUNET_free (mlp);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutdown down of mlp solver complete\n");
}


/**
 * Init the MLP problem solving component
 *
 * @param cfg the GNUNET_CONFIGURATION_Handle handle
 * @param stats the GNUNET_STATISTICS handle
 * @param network array of GNUNET_ATS_NetworkType with length dest_length
 * @param out_dest array of outbound quotas
 * @param in_dest array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @return struct GAS_MLP_Handle on success, NULL on fail
 */
void *
GAS_mlp_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_STATISTICS_Handle *stats,
              int *network,
              unsigned long long *out_dest,
              unsigned long long *in_dest,
              int dest_length,
              GAS_bandwidth_changed_cb bw_changed_cb,
              void *bw_changed_cb_cls)
{
  struct GAS_MLP_Handle * mlp = GNUNET_malloc (sizeof (struct GAS_MLP_Handle));

  double D;
  double R;
  double U;
  unsigned long long tmp;
  unsigned int b_min;
  unsigned int n_min;
  int c;
  int c2;
  int found;

  struct GNUNET_TIME_Relative max_duration;
  long long unsigned int max_iterations;

  /* Init GLPK environment */
  int res = glp_init_env();
  switch (res) {
    case 0:
    	LOG (GNUNET_ERROR_TYPE_DEBUG, "GLPK: `%s'\n",
          "initialization successful");
      break;
    case 1:
    	LOG (GNUNET_ERROR_TYPE_DEBUG, "GLPK: `%s'\n",
          "environment is already initialized");
      break;
    case 2:
    	LOG (GNUNET_ERROR_TYPE_ERROR, "Could not init GLPK: `%s'\n",
          "initialization failed (insufficient memory)");
      GNUNET_free(mlp);
      return NULL;
      break;
    case 3:
    	LOG (GNUNET_ERROR_TYPE_ERROR, "Could not init GLPK: `%s'\n",
          "initialization failed (unsupported programming model)");
      GNUNET_free(mlp);
      return NULL;
      break;
    default:
      break;
  }


  mlp->pv.BIG_M = (double) BIG_M_VALUE;

  /* Get timeout for iterations */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time(cfg, "ats", "MLP_MAX_DURATION", &max_duration))
  {
    max_duration = MLP_MAX_EXEC_DURATION;
  }

  /* Get maximum number of iterations */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_size(cfg, "ats", "MLP_MAX_ITERATIONS", &max_iterations))
  {
    max_iterations = MLP_MAX_ITERATIONS;
  }

  /* Get diversity coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_D",
                                                      &tmp))
    D = (double) tmp / 100;
  else
    D = DEFAULT_D;

  /* Get proportionality coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_R",
                                                      &tmp))
    R = (double) tmp / 100;
  else
    R = DEFAULT_R;

  /* Get utilization coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_U",
                                                      &tmp))
    U = (double) tmp / 100;
  else
    U = DEFAULT_U;

  /* Get quality metric coefficients from configuration */
  int i_delay = NaN;
  int i_distance = NaN;
  int q[GNUNET_ATS_QualityPropertiesCount] = GNUNET_ATS_QualityProperties;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {
    /* initialize quality coefficients with default value 1.0 */
  		mlp->pv.co_Q[c] = DEFAULT_QUALITY;

    mlp->pv.q[c] = q[c];
    if (q[c] == GNUNET_ATS_QUALITY_NET_DELAY)
      i_delay = c;
    if (q[c] == GNUNET_ATS_QUALITY_NET_DISTANCE)
      i_distance = c;
  }

  if ((i_delay != NaN) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_QUALITY_DELAY",
                                                      &tmp)))

  	mlp->pv.co_Q[i_delay] = (double) tmp / 100;
  else
  	mlp->pv.co_Q[i_delay] = DEFAULT_QUALITY;

  if ((i_distance != NaN) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_QUALITY_DISTANCE",
                                                      &tmp)))
  	mlp->pv.co_Q[i_distance] = (double) tmp / 100;
  else
  	mlp->pv.co_Q[i_distance] = DEFAULT_QUALITY;

  /* Get minimum bandwidth per used address from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_MIN_BANDWIDTH",
                                                      &tmp))
    b_min = tmp;
  else
  {
    b_min = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  }

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_MIN_CONNECTIONS",
                                                      &tmp))
    n_min = tmp;
  else
    n_min = DEFAULT_MIN_CONNECTIONS;

  /* Init network quotas */
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
  		found = GNUNET_NO;
  	  for (c2 = 0; c2 < dest_length; c2++)
  	  {
  	  		if (quotas[c] == network[c2])
  	  	  {
  	  				mlp->pv.quota_index[c] = network[c2];
  	  				mlp->pv.quota_out[c] = out_dest[c2];
  	  	      mlp->pv.quota_in[c] = in_dest[c2];
  	  	      found = GNUNET_YES;
  	  	      LOG (GNUNET_ERROR_TYPE_DEBUG, "Quota for network `%s' (in/out) %llu/%llu\n",
  	  	      						GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
  	  	      						mlp->pv.quota_out[c],
  	  	      						mlp->pv.quota_in[c]);
  	  	      break;
  	  	  }
  	  }

      /* Check if defined quota could make problem unsolvable */
      if ((n_min * b_min) > mlp->pv.quota_out[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting inconsistent outbound quota configuration for network `%s', is %llu must be at least %llu\n"),
        		GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
        		mlp->pv.quota_out[c],
        		(n_min * b_min));
        mlp->pv.quota_out[c] = (n_min * b_min);
      }
      if ((n_min * b_min) > mlp->pv.quota_in[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting inconsistent inbound quota configuration for network `%s', is %llu must be at least %llu\n"),
        		GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
        		mlp->pv.quota_in[c],
        		(n_min * b_min));
        mlp->pv.quota_in[c] = (n_min * b_min);
      }

      /* Check if bandwidth is too big to make problem solvable */
      if (mlp->pv.BIG_M < mlp->pv.quota_out[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting outbound quota configuration for network `%s'from %llu to %.0f\n"),
        		GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
        		mlp->pv.quota_out[c],
        		mlp->pv.BIG_M);
        mlp->pv.quota_out[c] = mlp->pv.BIG_M ;
      }
      if (mlp->pv.BIG_M < mlp->pv.quota_in[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting inbound quota configuration for network `%s' from %llu to %.0f\n"),
        		GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
        		mlp->pv.quota_in[c],
        		mlp->pv.BIG_M);
        mlp->pv.quota_in[c] = mlp->pv.BIG_M ;
      }

  	  if (GNUNET_NO == found)
			{
  	  	mlp->pv.quota_in[c] = ntohl(GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  	  	mlp->pv.quota_out[c] = ntohl(GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
				LOG (GNUNET_ERROR_TYPE_INFO, _("Using default quota configuration for network `%s' (in/out) %llu/%llu\n"),
						GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
						mlp->pv.quota_in[c],
						mlp->pv.quota_out[c]);
			}
  }

  /* Assign options to handle */
  mlp->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  mlp->bw_changed_cb = bw_changed_cb;
  mlp->bw_changed_cb_cls = bw_changed_cb_cls;
  /* Setting MLP Input variables */
  mlp->pv.co_D = D;
  mlp->pv.co_R = R;
  mlp->pv.co_U = U;
  mlp->pv.b_min = b_min;
  mlp->pv.n_min = n_min;
  mlp->pv.m_q = GNUNET_ATS_QualityPropertiesCount;
  mlp->mlp_prob_changed = GNUNET_NO;
  mlp->mlp_prob_updated = GNUNET_NO;
  mlp->mlp_auto_solve = GNUNET_YES;
  mlp->peers = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);

  /* Setup GLPK */
  /* Redirect GLPK output to GNUnet logging */
  glp_term_hook (&mlp_term_hook, (void *) mlp);

  /* Init LP solving parameters */
  glp_init_smcp(&mlp->control_param_lp);
  mlp->control_param_lp.msg_lev = GLP_MSG_OFF;
#if VERBOSE_GLPK
  mlp->control_param_lp.msg_lev = GLP_MSG_ALL;
#endif
  mlp->control_param_lp.it_lim = max_iterations;
  mlp->control_param_lp.tm_lim = max_duration.rel_value;

  /* Init MLP solving parameters */
  glp_init_iocp(&mlp->control_param_mlp);
  mlp->control_param_mlp.msg_lev = GLP_MSG_OFF;
#if VERBOSE_GLPK
  mlp->control_param_mlp.msg_lev = GLP_MSG_ALL;
#endif
  mlp->control_param_mlp.tm_lim = max_duration.rel_value;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "solver ready\n");

  return mlp;
}

/* end of gnunet-service-ats_addresses_mlp.c */

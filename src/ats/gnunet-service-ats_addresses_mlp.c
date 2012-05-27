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

#define WRITE_MLP GNUNET_NO
#define DEBUG_ATS GNUNET_NO
#define VERBOSE_GLPK GNUNET_NO

#define ENABLE_C8 GNUNET_YES
#define ENABLE_C9 GNUNET_YES
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
      break;
    case GLP_EBADB:
      return "invalid basis";
      break;
    case GLP_ESING:
      return "singular matrix";
      break;
    case GLP_ECOND:
      return "ill-conditioned matrix";
      break;
    case GLP_EBOUND:
      return "invalid bounds";
      break;
    case GLP_EFAIL:
      return "solver failed";
      break;
    case GLP_EOBJLL:
      return "objective lower limit reached";
      break;
    case GLP_EOBJUL:
      return "objective upper limit reached";
      break;
    case GLP_EITLIM:
      return "iteration limit exceeded";
      break;
    case GLP_ETMLIM:
      return "time limit exceeded";
      break;
    case GLP_ENOPFS:
      return "no primal feasible solution";
      break;
    case GLP_EROOT:
      return "root LP optimum not provided";
      break;
    case GLP_ESTOP:
      return "search terminated by application";
      break;
    case GLP_EMIPGAP:
      return "relative mip gap tolerance reached";
      break;
    case GLP_ENOFEAS:
      return "no dual feasible solution";
      break;
    case GLP_ENOCVG:
      return "no convergence";
      break;
    case GLP_EINSTAB:
      return "numerical instability";
      break;
    case GLP_EDATA:
      return "invalid data";
      break;
    case GLP_ERANGE:
      return "result out of range";
      break;
    default:
      GNUNET_break (0);
      return "unknown error";
      break;
  }
  GNUNET_break (0);
  return "unknown error";
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
      break;
    case GLP_FEAS:
      return "solution is feasible";
      break;
    case GLP_INFEAS:
      return "solution is infeasible";
      break;
    case GLP_NOFEAS:
      return "no feasible solution exists";
      break;
    case GLP_OPT:
      return "solution is optimal";
      break;
    case GLP_UNBND:
      return "solution is unbounded";
      break;
    default:
      GNUNET_break (0);
      return "unknown error";
      break;
  }
  GNUNET_break (0);
  return "unknown error";
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
      break;
    case GNUNET_ATS_UTILIZATION_UP:
      return "GNUNET_ATS_UTILIZATION_UP";
      break;
    case GNUNET_ATS_UTILIZATION_DOWN:
      return "GNUNET_ATS_UTILIZATION_DOWN";
      break;
    case GNUNET_ATS_COST_LAN:
      return "GNUNET_ATS_COST_LAN";
      break;
    case GNUNET_ATS_COST_WAN:
      return "GNUNET_ATS_COST_LAN";
      break;
    case GNUNET_ATS_COST_WLAN:
      return "GNUNET_ATS_COST_WLAN";
      break;
    case GNUNET_ATS_NETWORK_TYPE:
      return "GNUNET_ATS_NETWORK_TYPE";
      break;
    case GNUNET_ATS_QUALITY_NET_DELAY:
      return "GNUNET_ATS_QUALITY_NET_DELAY";
      break;
    case GNUNET_ATS_QUALITY_NET_DISTANCE:
      return "GNUNET_ATS_QUALITY_NET_DISTANCE";
      break;
    default:
      return "unknown";
      break;
  }
  GNUNET_break (0);
  return "unknown error";
}

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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s", s);
  return 1;
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
    if (mlp->prob != NULL)
      glp_delete_prob(mlp->prob);

    /* delete row index */
    if (mlp->ia != NULL)
    {
      GNUNET_free (mlp->ia);
      mlp->ia = NULL;
    }

    /* delete column index */
    if (mlp->ja != NULL)
    {
      GNUNET_free (mlp->ja);
      mlp->ja = NULL;
    }

    /* delete coefficients */
    if (mlp->ar != NULL)
    {
      GNUNET_free (mlp->ar);
      mlp->ar = NULL;
    }
    mlp->ci = 0;
    mlp->prob = NULL;
  }
}

/**
 * Add constraints that are iterating over "forall addresses"
 * and collects all existing peers for "forall peers" constraints
 *
 * @param cls GAS_MLP_Handle
 * @param key Hashcode
 * @param value ATS_Address
 *
 * @return GNUNET_OK to continue
 */
static int
create_constraint_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct ATS_Address *address = value;
  struct MLP_information *mlpi;
  unsigned int row_index;
  char *name;

  GNUNET_assert (address->mlp_information != NULL);
  mlpi = (struct MLP_information *) address->mlp_information;

  /* c 1) bandwidth capping
   * b_t  + (-M) * n_t <= 0
   */
  row_index = glp_add_rows (mlp->prob, 1);
  mlpi->r_c1 = row_index;
  /* set row name */
  GNUNET_asprintf(&name, "c1_%s_%s", GNUNET_i2s(&address->peer), address->plugin);
  glp_set_row_name (mlp->prob, row_index, name);
  GNUNET_free (name);
  /* set row bounds: <= 0 */
  glp_set_row_bnds (mlp->prob, row_index, GLP_UP, 0.0, 0.0);
  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_b;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_n;
  mlp->ar[mlp->ci] = -mlp->BIG_M;
  mlp->ci++;

  /* c 3) minimum bandwidth
   * b_t + (-n_t * b_min) >= 0
   */

  row_index = glp_add_rows (mlp->prob, 1);
  /* set row name */
  GNUNET_asprintf(&name, "c3_%s_%s", GNUNET_i2s(&address->peer), address->plugin);
  glp_set_row_name (mlp->prob, row_index, name);
  GNUNET_free (name);
  mlpi->r_c3 = row_index;
  /* set row bounds: >= 0 */
  glp_set_row_bnds (mlp->prob, row_index, GLP_LO, 0.0, 0.0);

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_b;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_n;
  mlp->ar[mlp->ci] = - (double) mlp->b_min;
  mlp->ci++;

  /* c 4) minimum connections
   * (1)*n_1 + ... + (1)*n_m >= n_min
   */
  mlp->ia[mlp->ci] = mlp->r_c4;
  mlp->ja[mlp->ci] = mlpi->c_n;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  /* c 6) maximize diversity
   * (1)*n_1 + ... + (1)*n_m - d == 0
   */
  mlp->ia[mlp->ci] = mlp->r_c6;
  mlp->ja[mlp->ci] = mlpi->c_n;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  /* c 10) obey network specific quotas
   * (1)*b_1 + ... + (1)*b_m <= quota_n
   */

  int cur_row = 0;
  int c;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
    {
    if (mlp->quota_index[c] == address->atsp_network_type)
    {
      cur_row = mlp->r_quota[c];
      break;
    }
  }

  if (cur_row != 0)
  {
    mlp->ia[mlp->ci] = cur_row;
    mlp->ja[mlp->ci] = mlpi->c_b;
    mlp->ar[mlp->ci] = 1;
    mlp->ci++;
  }
  else
  {
    GNUNET_break (0);
  }

  return GNUNET_OK;
}

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
  int c;
  char *name;

  /* Problem matrix*/
  n_addresses = GNUNET_CONTAINER_multihashmap_size(addresses);

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
  int pi = ((7 * n_addresses) + (5 * n_addresses +  mlp->m_q + mlp->c_p + 2) + 1);
  mlp->cm_size = pi;
  mlp->ci = 1;

  /* row index */
  int *ia = GNUNET_malloc (pi * sizeof (int));
  mlp->ia = ia;

  /* column index */
  int *ja = GNUNET_malloc (pi * sizeof (int));
  mlp->ja = ja;

  /* coefficient */
  double *ar= GNUNET_malloc (pi * sizeof (double));
  mlp->ar = ar;

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

  /* Row for c4) minimum connection */
  int min = mlp->n_min;
  /* Number of minimum connections is min(|Peers|, n_min) */
  if (mlp->n_min > mlp->c_p)
    min = mlp->c_p;

  mlp->r_c4 = glp_add_rows (mlp->prob, 1);
  glp_set_row_name (mlp->prob, mlp->r_c4, "c4");
  glp_set_row_bnds (mlp->prob, mlp->r_c4, GLP_LO, min, min);

  /* Add row for c6) */

  mlp->r_c6 = glp_add_rows (mlp->prob, 1);
  /* Set type type to fix */
  glp_set_row_bnds (mlp->prob, mlp->r_c6, GLP_FX, 0.0, 0.0);
  /* Setting -D */
  ia[mlp->ci] = mlp->r_c6 ;
  ja[mlp->ci] = mlp->c_d;
  ar[mlp->ci] = -1;
  mlp->ci++;

  /* Add rows for c 10) */
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    mlp->r_quota[c] = glp_add_rows (mlp->prob, 1);
    char * text;
    GNUNET_asprintf(&text, "quota_ats_%i", mlp->quota_index[c]);
    glp_set_row_name (mlp->prob, mlp->r_quota[c], text);
    GNUNET_free (text);
    /* Set bounds to 0 <= x <= quota_out */
    glp_set_row_bnds (mlp->prob, mlp->r_quota[c], GLP_UP, 0.0, mlp->quota_out[c]);
  }

  GNUNET_CONTAINER_multihashmap_iterate (addresses, create_constraint_it, mlp);

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

  /* Adding rows for c 8) */
  mlp->r_c8 = glp_add_rows (mlp->prob, mlp->c_p);
  glp_set_row_name (mlp->prob, mlp->r_c8, "c8");
  /* Set row bound == 0 */
  glp_set_row_bnds (mlp->prob, mlp->r_c8, GLP_FX, 0.0, 0.0);
  /* -u */

  ia[mlp->ci] = mlp->r_c8;
  ja[mlp->ci] = mlp->c_u;
  ar[mlp->ci] = -1;
  mlp->ci++;

  struct ATS_Peer * peer = mlp->peer_head;
  /* For all peers */
  while (peer != NULL)
  {
    struct ATS_Address *addr = peer->head;
    struct MLP_information *mlpi = NULL;

    /* Adding rows for c 2) */
    peer->r_c2 = glp_add_rows (mlp->prob, 1);
    GNUNET_asprintf(&name, "c2_%s", GNUNET_i2s(&peer->id));
    glp_set_row_name (mlp->prob, peer->r_c2, name);
    GNUNET_free (name);
    /* Set row bound == 1 */
    glp_set_row_bnds (mlp->prob, peer->r_c2, GLP_FX, 1.0, 1.0);

    /* Adding rows for c 9) */
#if ENABLE_C9
    peer->r_c9 = glp_add_rows (mlp->prob, 1);
    GNUNET_asprintf(&name, "c9_%s", GNUNET_i2s(&peer->id));
    glp_set_row_name (mlp->prob, peer->r_c9, name);
    GNUNET_free (name);
    /* Set row bound == 0 */
    glp_set_row_bnds (mlp->prob, peer->r_c9, GLP_LO, 0.0, 0.0);

    /* Set -r */
    ia[mlp->ci] = peer->r_c9;
    ja[mlp->ci] = mlp->c_r;
    ar[mlp->ci] = -peer->f;
    mlp->ci++;
#endif
    /* For all addresses of this peer */
    while (addr != NULL)
    {
      mlpi = (struct MLP_information *) addr->mlp_information;

      /* coefficient for c 2) */
      ia[mlp->ci] = peer->r_c2;
      ja[mlp->ci] = mlpi->c_n;
      ar[mlp->ci] = 1;
      mlp->ci++;

      /* coefficient for c 8) */
      ia[mlp->ci] = mlp->r_c8;
      ja[mlp->ci] = mlpi->c_b;
      ar[mlp->ci] = peer->f;
      mlp->ci++;

#if ENABLE_C9
      /* coefficient for c 9) */
      ia[mlp->ci] = peer->r_c9;
      ja[mlp->ci] = mlpi->c_b;
      ar[mlp->ci] = 1;
      mlp->ci++;
#endif

      addr = addr->next;
    }
    peer = peer->next;
  }

  /* c 7) For all quality metrics */
  for (c = 0; c < mlp->m_q; c++)
  {
    struct ATS_Peer *tp;
    struct ATS_Address *ta;
    struct MLP_information * mlpi;
    double value = 1.0;

    /* Adding rows for c 7) */
    mlp->r_q[c] = glp_add_rows (mlp->prob, 1);
    GNUNET_asprintf(&name, "c7_q%i_%s", c, mlp_ats_to_string(mlp->q[c]));
    glp_set_row_name (mlp->prob, mlp->r_q[c], name);
    GNUNET_free (name);
    /* Set row bound == 0 */
    glp_set_row_bnds (mlp->prob, mlp->r_q[c], GLP_FX, 0.0, 0.0);

    ia[mlp->ci] = mlp->r_q[c];
    ja[mlp->ci] = mlp->c_q[c];
    ar[mlp->ci] = -1;
    mlp->ci++;

    for (tp = mlp->peer_head; tp != NULL; tp = tp->next)
      for (ta = tp->head; ta != NULL; ta = ta->next)
        {
          mlpi = ta->mlp_information;
          value = mlpi->q_averaged[c];

          mlpi->r_q[c] = mlp->r_q[c];

          ia[mlp->ci] = mlp->r_q[c];
          ja[mlp->ci] = mlpi->c_b;
          ar[mlp->ci] = tp->f_q[c] * value;
          mlp->ci++;
        }
  }
}


/**
 * Add columns for all addresses
 *
 * @param cls GAS_MLP_Handle
 * @param key Hashcode
 * @param value ATS_Address
 *
 * @return GNUNET_OK to continue
 */
static int
create_columns_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct ATS_Address *address = value;
  struct MLP_information *mlpi;
  unsigned int col;
  char *name;

  GNUNET_assert (address->mlp_information != NULL);
  mlpi = address->mlp_information;

  /* Add bandwidth column */
  col = glp_add_cols (mlp->prob, 2);
  mlpi->c_b = col;
  mlpi->c_n = col + 1;


  GNUNET_asprintf (&name, "b_%s_%s", GNUNET_i2s (&address->peer), address->plugin);
  glp_set_col_name (mlp->prob, mlpi->c_b , name);
  GNUNET_free (name);
  /* Lower bound == 0 */
  glp_set_col_bnds (mlp->prob, mlpi->c_b , GLP_LO, 0.0, 0.0);
  /* Continuous value*/
  glp_set_col_kind (mlp->prob, mlpi->c_b , GLP_CV);
  /* Objective function coefficient == 0 */
  glp_set_obj_coef (mlp->prob, mlpi->c_b , 0);


  /* Add usage column */
  GNUNET_asprintf (&name, "n_%s_%s", GNUNET_i2s (&address->peer), address->plugin);
  glp_set_col_name (mlp->prob, mlpi->c_n, name);
  GNUNET_free (name);
  /* Limit value : 0 <= value <= 1 */
  glp_set_col_bnds (mlp->prob, mlpi->c_n, GLP_DB, 0.0, 1.0);
  /* Integer value*/
  glp_set_col_kind (mlp->prob, mlpi->c_n, GLP_IV);
  /* Objective function coefficient == 0 */
  glp_set_obj_coef (mlp->prob, mlpi->c_n, 0);

  return GNUNET_OK;
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
  int res = GNUNET_OK;
  int col;
  int c;
  char *name;

  GNUNET_assert (mlp->prob == NULL);

  /* create the glpk problem */
  mlp->prob = glp_create_prob ();

  /* Set a problem name */
  glp_set_prob_name (mlp->prob, "gnunet ats bandwidth distribution");

  /* Set optimization direction to maximize */
  glp_set_obj_dir (mlp->prob, GLP_MAX);

  /* Adding invariant columns */

  /* Diversity d column  */
  col = glp_add_cols (mlp->prob, 1);
  mlp->c_d = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "d");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_D);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Utilization u column  */
  col = glp_add_cols (mlp->prob, 1);
  mlp->c_u = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "u");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_U);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

#if ENABLE_C9
  /* Relativity r column  */
  col = glp_add_cols (mlp->prob, 1);
  mlp->c_r = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "r");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_R);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);
#endif

  /* Quality metric columns */
  col = glp_add_cols(mlp->prob, mlp->m_q);
  for (c = 0; c < mlp->m_q; c++)
  {
    mlp->c_q[c] = col + c;
    GNUNET_asprintf (&name, "q_%u", mlp->q[c]);
    glp_set_col_name (mlp->prob, col + c, name);
    /* Column lower bound = 0.0 */
    glp_set_col_bnds (mlp->prob, col + c, GLP_LO, 0.0, 0.0);
    GNUNET_free (name);
    /* Coefficient == Qm */
    glp_set_obj_coef (mlp->prob, col + c, mlp->co_Q[c]);
  }

  /* Add columns for addresses */
  GNUNET_CONTAINER_multihashmap_iterate (addresses, create_columns_it, mlp);

  /* Add constraints */
  mlp_add_constraints_all_addresses (mlp, addresses);

  /* Load the matrix */
  glp_load_matrix(mlp->prob, (mlp->ci-1), mlp->ia, mlp->ja, mlp->ar);

  return res;
}


/**
 * Solves the LP problem
 *
 * @param mlp the MLP Handle
 * @param s_ctx context to return results
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
static int
mlp_solve_lp_problem (struct GAS_MLP_Handle *mlp, struct GAS_MLP_SolutionContext *s_ctx)
{
  int res;
  struct GNUNET_TIME_Relative duration;
  struct GNUNET_TIME_Absolute end;
  struct GNUNET_TIME_Absolute start = GNUNET_TIME_absolute_get();

  /* LP presolver?
   * Presolver is required if the problem was modified and an existing
   * valid basis is now invalid */
  if (mlp->presolver_required == GNUNET_YES)
    mlp->control_param_lp.presolve = GLP_ON;
  else
    mlp->control_param_lp.presolve = GLP_OFF;

  /* Solve LP problem to have initial valid solution */
lp_solv:
  res = glp_simplex(mlp->prob, &mlp->control_param_lp);
  if (res == 0)
  {
    /* The LP problem instance has been successfully solved. */
  }
  else if (res == GLP_EITLIM)
  {
    /* simplex iteration limit has been exceeded. */
    // TODO Increase iteration limit?
  }
  else if (res == GLP_ETMLIM)
  {
    /* Time limit has been exceeded.  */
    // TODO Increase time limit?
  }
  else
  {
    /* Problem was ill-defined, retry with presolver */
    if (mlp->presolver_required == GNUNET_NO)
    {
      mlp->presolver_required = GNUNET_YES;
      goto lp_solv;
    }
    else
    {
      /* Problem was ill-defined, no way to handle that */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
          "ats-mlp",
          "Solving LP problem failed: %i %s\n", res, mlp_solve_to_string(res));
      return GNUNET_SYSERR;
    }
  }

  end = GNUNET_TIME_absolute_get ();
  duration = GNUNET_TIME_absolute_get_difference (start, end);
  mlp->lp_solved++;
  mlp->lp_total_duration =+ duration.rel_value;
  s_ctx->lp_duration = duration;

  GNUNET_STATISTICS_update (mlp->stats,"# LP problem solved", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# LP execution time (ms)", duration.rel_value, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# LP execution time average (ms)",
                         mlp->lp_total_duration / mlp->lp_solved,  GNUNET_NO);

  /* Analyze problem status  */
  res = glp_get_status (mlp->prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      break;

    /* Problem was ill-defined, no way to handle that */
    default:
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
          "ats-mlp",
          "Solving LP problem failed, no solution: %s\n", mlp_status_to_string(res));
      return GNUNET_SYSERR;
      break;
  }

  /* solved sucessfully, no presolver required next time */
  mlp->presolver_required = GNUNET_NO;

  return GNUNET_OK;
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @param s_ctx context to return results
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_solve_mlp_problem (struct GAS_MLP_Handle *mlp, struct GAS_MLP_SolutionContext *s_ctx)
{
  int res;
  struct GNUNET_TIME_Relative duration;
  struct GNUNET_TIME_Absolute end;
  struct GNUNET_TIME_Absolute start = GNUNET_TIME_absolute_get();

  /* solve MLP problem */
  res = glp_intopt(mlp->prob, &mlp->control_param_mlp);

  if (res == 0)
  {
    /* The MLP problem instance has been successfully solved. */
  }
  else if (res == GLP_EITLIM)
  {
    /* simplex iteration limit has been exceeded. */
    // TODO Increase iteration limit?
  }
  else if (res == GLP_ETMLIM)
  {
    /* Time limit has been exceeded.  */
    // TODO Increase time limit?
  }
  else
  {
    /* Problem was ill-defined, no way to handle that */
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
        "ats-mlp",
        "Solving MLP problem failed:  %s\n", mlp_solve_to_string(res));
    return GNUNET_SYSERR;
  }

  end = GNUNET_TIME_absolute_get ();
  duration = GNUNET_TIME_absolute_get_difference (start, end);
  mlp->mlp_solved++;
  mlp->mlp_total_duration =+ duration.rel_value;
  s_ctx->mlp_duration = duration;

  GNUNET_STATISTICS_update (mlp->stats,"# MLP problem solved", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# MLP execution time (ms)", duration.rel_value, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# MLP execution time average (ms)",
                         mlp->mlp_total_duration / mlp->mlp_solved,  GNUNET_NO);

  /* Analyze problem status  */
  res = glp_mip_status(mlp->prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      break;

    /* Problem was ill-defined, no way to handle that */
    default:
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
          "ats-mlp",
          "Solving MLP problem failed, %s\n\n", mlp_status_to_string(res));
      return GNUNET_SYSERR;
      break;
  }

  return GNUNET_OK;
}

int GAS_mlp_solve_problem (struct GAS_MLP_Handle *mlp, struct GAS_MLP_SolutionContext *ctx);


static void
mlp_scheduler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct GAS_MLP_SolutionContext ctx;

  mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Scheduled problem solving\n");

  if (mlp->addr_in_problem != 0)
    GAS_mlp_solve_problem(mlp, &ctx);
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @param ctx solution context
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
GAS_mlp_solve_problem (struct GAS_MLP_Handle *mlp, struct GAS_MLP_SolutionContext *ctx)
{
  int res;
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
      (GNUNET_OK == res) ? "successfully" : "failed", ctx->lp_duration.rel_value, ctx->mlp_duration.rel_value);
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

      mlpi = a->mlp_information;

      b = glp_mip_col_val(mlp->prob, mlpi->c_b);
      mlpi->b = b;

      n = glp_mip_col_val(mlp->prob, mlpi->c_n);
      if (n == 1.0)
        mlpi->n = GNUNET_YES;
      else
        mlpi->n = GNUNET_NO;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tAddress %s %f\n",
          (n == 1.0) ? "[x]" : "[ ]", b);
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
}

/**
 * Init the MLP problem solving component
 *
 * @param cfg the GNUNET_CONFIGURATION_Handle handle
 * @param stats the GNUNET_STATISTICS handle
 * @param max_duration maximum numbers of iterations for the LP/MLP Solver
 * @param max_iterations maximum time limit for the LP/MLP Solver
 * @return struct GAS_MLP_Handle * on success, NULL on fail
 */
struct GAS_MLP_Handle *
GAS_mlp_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_STATISTICS_Handle *stats,
              struct GNUNET_TIME_Relative max_duration,
              unsigned int max_iterations)
{
  struct GAS_MLP_Handle * mlp = GNUNET_malloc (sizeof (struct GAS_MLP_Handle));

  double D;
  double R;
  double U;
  unsigned long long tmp;
  unsigned int b_min;
  unsigned int n_min;
  struct GNUNET_TIME_Relative i_exec;
  int c;
  char * quota_out_str;
  char * quota_in_str;

  /* Init GLPK environment */
  int res = glp_init_env();
  switch (res) {
    case 0:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GLPK: `%s'\n",
          "initialization successful");
      break;
    case 1:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GLPK: `%s'\n",
          "environment is already initialized");
      break;
    case 2:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not init GLPK: `%s'\n",
          "initialization failed (insufficient memory)");
      GNUNET_free(mlp);
      return NULL;
      break;
    case 3:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not init GLPK: `%s'\n",
          "initialization failed (unsupported programming model)");
      GNUNET_free(mlp);
      return NULL;
      break;
    default:
      break;
  }

  /* Create initial MLP problem */
  mlp->prob = glp_create_prob();
  GNUNET_assert (mlp->prob != NULL);

  mlp->BIG_M = (double) BIG_M_VALUE;

  /* Get diversity coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_D",
                                                      &tmp))
    D = (double) tmp / 100;
  else
    D = 1.0;

  /* Get proportionality coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_R",
                                                      &tmp))
    R = (double) tmp / 100;
  else
    R = 1.0;

  /* Get utilization coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_U",
                                                      &tmp))
    U = (double) tmp / 100;
  else
    U = 1.0;

  /* Get quality metric coefficients from configuration */
  int i_delay = -1;
  int i_distance = -1;
  int q[GNUNET_ATS_QualityPropertiesCount] = GNUNET_ATS_QualityProperties;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {
    /* initialize quality coefficients with default value 1.0 */
    mlp->co_Q[c] = 1.0;

    mlp->q[c] = q[c];
    if (q[c] == GNUNET_ATS_QUALITY_NET_DELAY)
      i_delay = c;
    if (q[c] == GNUNET_ATS_QUALITY_NET_DISTANCE)
      i_distance = c;
  }

  if ((i_delay != -1) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_QUALITY_DELAY",
                                                      &tmp)))

    mlp->co_Q[i_delay] = (double) tmp / 100;
  else
    mlp->co_Q[i_delay] = 1.0;

  if ((i_distance != -1) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_QUALITY_DISTANCE",
                                                      &tmp)))
    mlp->co_Q[i_distance] = (double) tmp / 100;
  else
    mlp->co_Q[i_distance] = 1.0;

  /* Get minimum bandwidth per used address from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MIN_BANDWIDTH",
                                                      &tmp))
    b_min = tmp;
  else
  {
    b_min = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  }

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MIN_CONNECTIONS",
                                                      &tmp))
    n_min = tmp;
  else
    n_min = 4;

  /* Init network quotas */
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    mlp->quota_index[c] = quotas[c];
    static char * entry_in = NULL;
    static char * entry_out = NULL;
    unsigned long long quota_in = 0;
    unsigned long long quota_out = 0;

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

    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_out, &quota_out_str))
    {
      if (0 == strcmp(quota_out_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_out_str, &quota_out)))
        quota_out = mlp->BIG_M;

      GNUNET_free (quota_out_str);
      quota_out_str = NULL;
    }
    else if (GNUNET_ATS_NET_UNSPECIFIED == quotas[c])
    {
      quota_out = mlp->BIG_M;
    }
    else
    {
      quota_out = mlp->BIG_M;
    }

    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "ats", entry_in, &quota_in_str))
    {
      if (0 == strcmp(quota_in_str, BIG_M_STRING) ||
          (GNUNET_SYSERR == GNUNET_STRINGS_fancy_size_to_bytes (quota_in_str, &quota_in)))
        quota_in = mlp->BIG_M;

      GNUNET_free (quota_in_str);
      quota_in_str = NULL;
    }
    else if (GNUNET_ATS_NET_UNSPECIFIED == quotas[c])
    {
      quota_in = mlp->BIG_M;
    }
    else
    {
      quota_in = mlp->BIG_M;
    }

    /* Check if defined quota could make problem unsolvable */
    if (((n_min * b_min) > quota_out) && (GNUNET_ATS_NET_UNSPECIFIED != quotas[c]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Inconsistent quota configuration value `%s': " 
		  "outbound quota (%u Bps) too small for combination of minimum connections and minimum bandwidth per peer (%u * %u Bps = %u)\n", entry_out, quota_out, n_min, b_min, n_min * b_min);

      GAS_mlp_done(mlp);
      mlp = NULL;
      return NULL;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found `%s' quota %llu and `%s' quota %llu\n",
                entry_out, quota_out, entry_in, quota_in);
    GNUNET_STATISTICS_update ((struct GNUNET_STATISTICS_Handle *) stats, entry_out, quota_out, GNUNET_NO);
    GNUNET_STATISTICS_update ((struct GNUNET_STATISTICS_Handle *) stats, entry_in, quota_in, GNUNET_NO);
    mlp->quota_out[c] = quota_out;
    mlp->quota_in[c] = quota_in;
  }

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_time (cfg, "ats",
                                                        "ATS_EXEC_INTERVAL",
                                                        &i_exec))
    mlp->exec_interval = i_exec;
  else
    mlp->exec_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30);

  mlp->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  mlp->max_iterations = max_iterations;
  mlp->max_exec_duration = max_duration;
  mlp->auto_solve = GNUNET_YES;

  /* Redirect GLPK output to GNUnet logging */
  glp_error_hook((void *) mlp, &mlp_term_hook);

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

  mlp->last_execution = GNUNET_TIME_UNIT_FOREVER_ABS;

  mlp->co_D = D;
  mlp->co_R = R;
  mlp->co_U = U;
  mlp->b_min = b_min;
  mlp->n_min = n_min;
  mlp->m_q = GNUNET_ATS_QualityPropertiesCount;
  mlp->semaphore = GNUNET_NO;
  return mlp;
}

static void
update_quality (struct GAS_MLP_Handle *mlp, struct ATS_Address * address)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating quality metrics for peer `%s'\n",
      GNUNET_i2s (&address->peer));

  GNUNET_assert (NULL != address);
  GNUNET_assert (NULL != address->mlp_information);
  GNUNET_assert (NULL != address->ats);

  struct MLP_information *mlpi = address->mlp_information;
  struct GNUNET_ATS_Information *ats = address->ats;
  GNUNET_assert (mlpi != NULL);

  int c;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {
    int index = mlp_lookup_ats(address, mlp->q[c]);

    if (index == GNUNET_SYSERR)
      continue;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s' value `%s': %f\n",
        GNUNET_i2s (&address->peer),
        mlp_ats_to_string(mlp->q[c]),
        (double) ats[index].value);

    int i = mlpi->q_avg_i[c];
    double * qp = mlpi->q[c];
    qp[i] = (double) ats[index].value;

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

/**
 * Updates a single address in the MLP problem
 *
 * If the address did not exist before in the problem:
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * Otherwise the addresses' values can be updated and the existing base can
 * be reused
 *
 * @param mlp the MLP Handle
 * @param addresses the address hashmap
 *        the address has to be already removed from the hashmap
 * @param address the address to update
 */
void
GAS_mlp_address_update (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  int new;
  struct MLP_information *mlpi;
  struct GAS_MLP_SolutionContext ctx;

  GNUNET_STATISTICS_update (mlp->stats, "# MLP address updates", 1, GNUNET_NO);

  /* We add a new address */
  if (address->mlp_information == NULL)
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

    address->mlp_information = mlpi;
    mlp->addr_in_problem ++;
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
    mlp_create_problem (mlp, addresses);
    mlp->presolver_required = GNUNET_YES;
  }
  if (mlp->auto_solve == GNUNET_YES)
    GAS_mlp_solve_problem (mlp, &ctx);
}

/**
 * Deletes a single address in the MLP problem
 *
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * @param mlp the MLP Handle
 * @param addresses the address hashmap
 *        the address has to be already removed from the hashmap
 * @param address the address to delete
 */
void
GAS_mlp_address_delete (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  GNUNET_STATISTICS_update (mlp->stats,"# LP address deletions", 1, GNUNET_NO);
  struct GAS_MLP_SolutionContext ctx;

  /* Free resources */
  if (address->mlp_information != NULL)
  {
    GNUNET_free (address->mlp_information);
    address->mlp_information = NULL;

    mlp->addr_in_problem --;
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
  if ((GNUNET_CONTAINER_multihashmap_size (addresses) > 0) && (mlp->c_p > 0))
  {
    mlp_create_problem (mlp, addresses);

    /* Recalculate */
    mlp->presolver_required = GNUNET_YES;
    if (mlp->auto_solve == GNUNET_YES)
      GAS_mlp_solve_problem (mlp, &ctx);
  }
}

static int
mlp_get_preferred_address_it (void *cls, const GNUNET_HashCode * key, void *value)
{

  struct ATS_PreferedAddress *aa = (struct ATS_PreferedAddress *) cls;
  struct ATS_Address *addr = value;
  struct MLP_information *mlpi = addr->mlp_information;
  if (mlpi == NULL)
    return GNUNET_YES;
  if (mlpi->n == GNUNET_YES)
  {
    aa->address = addr;
    if (mlpi->b > (double) UINT32_MAX)
      aa->bandwidth_out = UINT32_MAX;
    else
      aa->bandwidth_out = (uint32_t) mlpi->b;
    aa->bandwidth_in = 0;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Get the preferred address for a specific peer
 *
 * @param mlp the MLP Handle
 * @param addresses address hashmap
 * @param peer the peer
 * @return suggested address
 */
struct ATS_PreferedAddress *
GAS_mlp_get_preferred_address (struct GAS_MLP_Handle *mlp,
                               struct GNUNET_CONTAINER_MultiHashMap * addresses,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_PreferedAddress * aa = GNUNET_malloc (sizeof (struct ATS_PreferedAddress));
  aa->address = NULL;
  aa->bandwidth_in = 0;
  aa->bandwidth_out = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Getting preferred address for `%s'\n", GNUNET_i2s (peer));
  GNUNET_CONTAINER_multihashmap_get_multiple (addresses, &peer->hashPubKey, mlp_get_preferred_address_it, aa);
  return aa;
}


/**
 * Changes the preferences for a peer in the MLP problem
 *
 * @param mlp the MLP Handle
 * @param peer the peer
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_mlp_address_change_preference (struct GAS_MLP_Handle *mlp,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score)
{
  GNUNET_STATISTICS_update (mlp->stats,"# LP address preference changes", 1, GNUNET_NO);

  struct ATS_Peer *p = mlp_find_peer (mlp, peer);
  p = p;
  /* Here we have to do the matching */
}

/**
 * Shutdown the MLP problem solving component
 * @param mlp the MLP handle
 */
void
GAS_mlp_done (struct GAS_MLP_Handle *mlp)
{
  struct ATS_Peer * peer;
  struct ATS_Address *addr;

  GNUNET_assert (mlp != NULL);

  if (mlp->mlp_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(mlp->mlp_task);
    mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;
  }

  /* clean up peer list */
  peer = mlp->peer_head;
  while (peer != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up peer `%s'\n", GNUNET_i2s (&peer->id));
    GNUNET_CONTAINER_DLL_remove(mlp->peer_head, mlp->peer_tail, peer);
    for (addr = peer->head; NULL != addr; addr = peer->head)
    {
      GNUNET_CONTAINER_DLL_remove(peer->head, peer->tail, addr);
      GNUNET_free (addr->mlp_information);
      addr->mlp_information = NULL;
    }
    GNUNET_free (peer);
    peer = mlp->peer_head;
  }
  mlp_delete_problem (mlp);

  /* Clean up GLPK environment */
  glp_free_env();

  GNUNET_free (mlp);
}


/* end of gnunet-service-ats_addresses_mlp.c */

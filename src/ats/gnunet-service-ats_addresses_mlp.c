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
  int c;
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

  /* last +1 caused by glpk index starting with one */
  int pi = ((7 * n_addresses) + (4 * n_addresses +  mlp->m_q + mlp->c_p + 2) + 1);
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
   */

  int min = mlp->n_min;
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
    peer->r_c9 = glp_add_rows (mlp->prob, 1);
    GNUNET_asprintf(&name, "c9_%s", GNUNET_i2s(&peer->id));
    glp_set_row_name (mlp->prob, peer->r_c9, name);
    GNUNET_free (name);
    /* Set row bound == 0 */
    glp_set_row_bnds (mlp->prob, peer->r_c9, GLP_LO, 0.0, 0.0);

    /* Set -r */
    ia[mlp->ci] = peer->r_c9;
    ja[mlp->ci] = mlp->c_r;
    ar[mlp->ci] = -1;
    mlp->ci++;

    while (addr != NULL)
    {
      mlpi = (struct MLP_information *) addr->mlp_information;

      ia[mlp->ci] = peer->r_c2;
      ja[mlp->ci] = mlpi->c_n;
      ar[mlp->ci] = 1;
      mlp->ci++;

      ia[mlp->ci] = mlp->r_c8;
      ja[mlp->ci] = mlpi->c_b;
      ar[mlp->ci] = peer->f;
      mlp->ci++;

      ia[mlp->ci] = peer->r_c9;
      ja[mlp->ci] = mlpi->c_b;
      ar[mlp->ci] = 1;
      mlp->ci++;

      addr = addr->next;
    }
    peer = peer->next;
  }

  /* c 7) For all quality metrics */

  for (c = 0; c < mlp->m_q; c++)
  {
    struct ATS_Peer *p = mlp->peer_head;
    struct ATS_Address *addr = p->head;
    struct MLP_information * mlpi;
    double value = 1.0;

    while (p != NULL)
    {
      /* Adding rows for c 7) */
      mlp->r_q[c] = glp_add_rows (mlp->prob, 1);
      GNUNET_asprintf(&name, "c7_q%i_atsi_%i", c, mlp->q[c]);
      glp_set_row_name (mlp->prob, mlp->r_q[c], name);
      GNUNET_free (name);
      /* Set row bound == 0 */
      glp_set_row_bnds (mlp->prob, mlp->r_q[c], GLP_LO, 0.0, 0.0);

      /* Set -q_m */
      ia[mlp->ci] = mlp->r_q[c];
      ja[mlp->ci] = mlp->c_q[c];
      ar[mlp->ci] = -1;
      mlp->ci++;

      while (addr != NULL)
      {
        mlpi = addr->mlp_information;
        /* lookup ATS information */
        int index = mlp_lookup_ats(addr, mlp->q[c]);

        if (index != GNUNET_SYSERR)
        {
          value = (double) addr->ats[index].value;

          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Quality %i with ATS property `%s' has index %i in addresses ats information has value %f\n", c,  mlp_ats_to_string(mlp->q[c]), index, (double) addr->ats[index].value);

        }

        else
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Quality %i with ATS property `%s' not existing\n", c,  mlp_ats_to_string(mlp->q[c]), index);

        mlpi = addr->mlp_information;

        mlpi->r_q[c] = mlp->r_q[c];
        mlpi->c_q[c] = mlpi->c_b;
        mlpi->q[c] = value;

        ia[mlp->ci] = mlp->r_q[c];
        ja[mlp->ci] = mlpi->c_b;
        ar[mlp->ci] = p->f * value;
        mlp->ci++;

        addr = addr->next;
      }
      p = p->next;
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

  /* Relativity r column  */
  col = glp_add_cols (mlp->prob, 1);
  mlp->c_r = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "r");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_R);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

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
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
static int
mlp_solve_lp_problem (struct GAS_MLP_Handle *mlp)
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

  GNUNET_STATISTICS_update (mlp->stats,"# LP problem solved", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# LP execution time", duration.rel_value, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# LP execution time average",
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
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_solve_mlp_problem (struct GAS_MLP_Handle *mlp)
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

  GNUNET_STATISTICS_update (mlp->stats,"# MLP problem solved", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# MLP execution time", duration.rel_value, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# MLP execution time average",
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

int GAS_mlp_solve_problem (struct GAS_MLP_Handle *mlp);

static void
mlp_scheduler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GAS_MLP_Handle *mlp = cls;

  mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Scheduled problem solving\n");

  if (mlp->addr_in_problem != 0)
    GAS_mlp_solve_problem(mlp);
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
GAS_mlp_solve_problem (struct GAS_MLP_Handle *mlp)
{
  int res;
  mlp->last_execution = GNUNET_TIME_absolute_get ();

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Problem solving\n");


#if WRITE_MLP
  char * name;
  static int i;
  i++;
  GNUNET_asprintf(&name, "problem_%i", i);
  glp_write_lp (mlp->prob, 0, name);
  GNUNET_free (name);
# endif

  res = mlp_solve_lp_problem (mlp);

#if WRITE_MLP
  GNUNET_asprintf(&name, "problem_%i_lp_solution", i);
  glp_print_sol (mlp->prob,  name);
  GNUNET_free (name);
# endif

  if (res != GNUNET_OK)
  {

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "LP Problem solving failed\n");

    return GNUNET_SYSERR;
  }

  res = mlp_solve_mlp_problem (mlp);

#if WRITE_MLP
  GNUNET_asprintf(&name, "problem_%i_mlp_solution", i);
  glp_print_mip (mlp->prob, name);
  GNUNET_free (name);
# endif
  if (res != GNUNET_OK)
  {

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MLP Problem solving failed\n");

    return GNUNET_SYSERR;
  }


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Problem solved\n");
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
      n = glp_mip_col_val(mlp->prob, mlpi->c_n);

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tAddress %f %f\n", n, b);

    }

  }




  if (mlp->mlp_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(mlp->mlp_task);
    mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;
  }
  mlp->mlp_task = GNUNET_SCHEDULER_add_delayed (mlp->exec_interval, &mlp_scheduler, mlp);
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
  long long unsigned int tmp;
  unsigned int b_min;
  unsigned int n_min;
  struct GNUNET_TIME_Relative i_exec;

  /* Init GLPK environment */
  GNUNET_assert (glp_init_env() == 0);

  /* Create initial MLP problem */
  mlp->prob = glp_create_prob();
  GNUNET_assert (mlp->prob != NULL);

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
  int c;
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
    b_min = 64000;

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MIN_CONNECTIONS",
                                                      &tmp))
    n_min = tmp;
  else
    n_min = 4;

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

  mlp->last_execution = GNUNET_TIME_absolute_get_forever();


  mlp->BIG_M = (double) UINT32_MAX;
  mlp->co_D = D;
  mlp->co_R = R;
  mlp->co_U = U;
  mlp->b_min = b_min;
  mlp->n_min = n_min;
  mlp->m_q = GNUNET_ATS_QualityPropertiesCount;

  return mlp;
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

  GNUNET_STATISTICS_update (mlp->stats,"# LP address updates", 1, GNUNET_NO);

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
      mlpi->c_q[c] = 0;
      mlpi->r_q[c] = 0;
      mlpi->q[c] = 0.0;
    }

    address->mlp_information = mlpi;
    mlp->addr_in_problem ++;

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
    }
    else
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding address to peer `%s'\n",
          GNUNET_i2s (&address->peer));

      GNUNET_CONTAINER_DLL_insert (peer->head, peer->tail, address);
    }
  }
  else
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating existing address to peer `%s'\n",
        GNUNET_i2s (&address->peer));

    mlpi = address->mlp_information;
    int c;
    for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
    {
      int index = mlp_lookup_ats(address, mlp->q[c]);
      if ((index != GNUNET_SYSERR) && (mlpi->c_q[c] != 0) && (mlpi->r_q[c] != 0))
      {
        if (mlpi->q[c] == (double) address->ats[index].value)
          break;

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Updating address for peer `%s' value `%s'from %f to %f\n",
            GNUNET_i2s (&address->peer),
            mlp_ats_to_string(mlp->q[c]),
            mlpi->q[c],
            (double) address->ats[index].value);

        switch (mlp->q[c])
        {
          case GNUNET_ATS_QUALITY_NET_DELAY:
            mlpi->q[c] = (double) address->ats[index].value;
            break;
          case GNUNET_ATS_QUALITY_NET_DISTANCE:
            mlpi->q[c] = (double) address->ats[index].value;
            break;
          default:
            break;
        }

        /* Get current number of columns */
        int cols = glp_get_num_cols(mlp->prob);
        int *ind = GNUNET_malloc (cols * sizeof (int));
        double *val = GNUNET_malloc (cols * sizeof (double));

        /* Get the matrix row of quality */
        cols = glp_get_mat_row(mlp->prob, mlp->r_q[c], ind, val);

        int c2;
        /* Get the index if matrix row of quality */
        for (c2 = 1; c2 <= cols; c2++ )
        {

          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Existing element column %i : %f\n",
            ind[c2], val[c2]);

          if ((mlpi->c_b == ind[c2]) && (val[c2] != mlpi->q[c]))
          {
            /* Update the value */
            val[c2] = mlpi->q[c];

            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New element column %i : %f\n",
                ind[c2], val[c2]);

        }
      }

      /* Get the index if matrix row of quality */
      glp_set_mat_row (mlp->prob, mlpi->r_q[c], cols, ind, val);

      GNUNET_free (ind);
      GNUNET_free (val);
      }
    }
  }

  /* Recalculate */
  if (new == GNUNET_YES)
  {
    mlp_delete_problem (mlp);
    mlp_create_problem (mlp, addresses);
    mlp->presolver_required = GNUNET_YES;
  }
  if (mlp->auto_solve == GNUNET_YES)
    GAS_mlp_solve_problem (mlp);
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

  /* Free resources */
  if (address->mlp_information != NULL)
  {
    GNUNET_free (address->mlp_information);
    address->mlp_information = NULL;

    mlp->addr_in_problem --;
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
  }

  /* Update problem */
  mlp_delete_problem (mlp);
  if ((GNUNET_CONTAINER_multihashmap_size (addresses) > 0) && (mlp->c_p > 0))
  {
    mlp_create_problem (mlp, addresses);

    /* Recalculate */
    mlp->presolver_required = GNUNET_YES;
    if (mlp->auto_solve == GNUNET_YES)
      GAS_mlp_solve_problem (mlp);
  }
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
  struct ATS_Peer * tmp;

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
    GNUNET_CONTAINER_DLL_remove(mlp->peer_head, mlp->peer_tail, peer);
    tmp = peer->next;
    GNUNET_free (peer);
    peer = tmp;
  }
  mlp_delete_problem (mlp);

  /* Clean up GLPK environment */
  glp_free_env();

  GNUNET_free (mlp);
}


/* end of gnunet-service-ats_addresses_mlp.c */

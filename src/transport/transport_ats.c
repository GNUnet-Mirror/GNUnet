/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_ats.c
 * @brief automatic transport selection
 * @author Matthias Wachs
 *
 */

#include "transport_ats.h"
#include "gnunet_transport_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_container_lib.h"


/*
 * Temporary included structs and defines
 */


/**
 * FIXME to be removed
 * Entry in linked list of all of our current neighbours.
 */
struct NeighbourList
{

  /**
   * This is a linked list.
   */
  struct NeighbourList *next;

  /**
   * Which of our transports is connected to this peer
   * and what is their status?
   */
  struct ReadyList *plugins;

  /**
   * Head of list of messages we would like to send to this peer;
   * must contain at most one message per client.
   */
  struct MessageQueue *messages_head;

  /**
   * Tail of list of messages we would like to send to this peer; must
   * contain at most one message per client.
   */
  struct MessageQueue *messages_tail;

  /**
   * Head of list of messages of messages we expected the continuation
   * to be called to destroy the message
   */
  struct MessageQueue *cont_head;

  /**
   * Tail of list of messages of messages we expected the continuation
   * to be called to destroy the message
   */
  struct MessageQueue *cont_tail;

  /**
   * Buffer for at most one payload message used when we receive
   * payload data before our PING-PONG has succeeded.  We then
   * store such messages in this intermediary buffer until the
   * connection is fully up.
   */
  struct GNUNET_MessageHeader *pre_connect_message_buffer;

  /**
   * Context for peerinfo iteration.
   * NULL after we are done processing peerinfo's information.
   */
  struct GNUNET_PEERINFO_IteratorContext *piter;

  /**
   * Public key for this peer.   Valid only if the respective flag is set below.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * ID of task scheduled to run when this peer is about to
   * time out (will free resources associated with the peer).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * ID of task scheduled to run when we should retry transmitting
   * the head of the message queue.  Actually triggered when the
   * transmission is timing out (we trigger instantly when we have
   * a chance of success).
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_task;

  /**
   * How long until we should consider this peer dead
   * (if we don't receive another message in the
   * meantime)?
   */
  struct GNUNET_TIME_Absolute peer_timeout;

  /**
   * Tracker for inbound bandwidth.
   */
  struct GNUNET_BANDWIDTH_Tracker in_tracker;

  /**
   * The latency we have seen for this particular address for
   * this particular peer.  This latency may have been calculated
   * over multiple transports.  This value reflects how long it took
   * us to receive a response when SENDING via this particular
   * transport/neighbour/address combination!
   *
   * FIXME: we need to periodically send PINGs to update this
   * latency (at least more often than the current "huge" (11h?)
   * update interval).
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * How often has the other peer (recently) violated the
   * inbound traffic limit?  Incremented by 10 per violation,
   * decremented by 1 per non-violation (for each
   * time interval).
   */
  unsigned int quota_violation_count;

  /**
   * DV distance to this peer (1 if no DV is used).
   */
  uint32_t distance;

  /**
   * Have we seen an PONG from this neighbour in the past (and
   * not had a disconnect since)?
   */
  int received_pong;

  /**
   * Do we have a valid public key for this neighbour?
   */
  int public_key_valid;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Identity of the neighbour.
   */
  struct GNUNET_PeerIdentity peer;

};

/**
 * FIXME to be removed
 *
 * List of addresses of other peers
 */
struct ForeignAddressList
{
  /**
   * This is a linked list.
   */
  struct ForeignAddressList *next;

  /**
   * Which ready list does this entry belong to.
   */
  struct ReadyList *ready_list;

  /**
   * How long until we auto-expire this address (unless it is
   * re-confirmed by the transport)?
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * Task used to re-validate addresses, updates latencies and
   * verifies liveness.
   */
  GNUNET_SCHEDULER_TaskIdentifier revalidate_task;

  /**
   * The address.
   */
  const void *addr;

  /**
   * Session (or NULL if no valid session currently exists or if the
   * plugin does not use sessions).
   */
  struct Session *session;

  struct ATS_ressource_entry * ressources;

  struct ATS_quality_entry * quality;

  /**
   * What was the last latency observed for this address, plugin and peer?
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * If we did not successfully transmit a message to the given peer
   * via this connection during the specified time, we should consider
   * the connection to be dead.  This is used in the case that a TCP
   * transport simply stalls writing to the stream but does not
   * formerly get a signal that the other peer died.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How often have we tried to connect using this plugin?  Used to
   * discriminate against addresses that do not work well.
   * FIXME: not yet used, but should be!
   */
  unsigned int connect_attempts;

  /**
   * DV distance to this peer (1 if no DV is used).
   * FIXME: need to set this from transport plugins!
   */
  uint32_t distance;

  /**
   * Length of addr.
   */
  uint16_t addrlen;

  /**
   * Have we ever estimated the latency of this address?  Used to
   * ensure that the first time we add an address, we immediately
   * probe its latency.
   */
  int8_t estimated;

  /**
   * Are we currently connected via this address?  The first time we
   * successfully transmit or receive data to a peer via a particularcurl:
   * (56) Recv failure: Connection reset by peer
   *
   * address, we set this to GNUNET_YES.  If we later get an error
   * (disconnect notification, transmission failure, timeout), we set
   * it back to GNUNET_NO.
   */
  int8_t connected;

  /**
   * Is this plugin currently busy transmitting to the specific target?
   * GNUNET_NO if not (initial, default state is GNUNET_NO).   Internal
   * messages do not count as 'in transmit'.
   */
  int8_t in_transmit;

  /**
   * Has this address been validated yet?
   */
  int8_t validated;

};

/**
 * FIXME: REMOVE
 *
 * For a given Neighbour, which plugins are available
 * to talk to this peer and what are their costs?
 */
struct ReadyList
{
  /**
   * This is a linked list.
   */
  struct ReadyList *next;

  /**
   * Which of our transport plugins does this entry
   * represent?
   */
  struct TransportPlugin *plugin;

  /**
   * Transport addresses, latency, and readiness for
   * this particular plugin.
   */
  struct ForeignAddressList *addresses;

  /**
   * To which neighbour does this ready list belong to?
   */
  struct NeighbourList *neighbour;
};


#if !HAVE_LIBGLPK
/* optimization direction flag: */
#define GLP_MIN            1  /* minimization */
#define GLP_MAX            2  /* maximization */

/* kind of structural variable: */
#define GLP_CV             1  /* continuous variable */
#define GLP_IV             2  /* integer variable */
#define GLP_BV             3  /* binary variable */

/* type of auxiliary/structural variable: */
#define GLP_FR             1  /* free variable */
#define GLP_LO             2  /* variable with lower bound */
#define GLP_UP             3  /* variable with upper bound */
#define GLP_DB             4  /* double-bounded variable */
#define GLP_FX             5  /* fixed variable */

/* solution status: */
#define GLP_UNDEF          1  /* solution is undefined */
#define GLP_FEAS           2  /* solution is feasible */
#define GLP_INFEAS         3  /* solution is infeasible */
#define GLP_NOFEAS         4  /* no feasible solution exists */
#define GLP_OPT            5  /* solution is optimal */
#define GLP_UNBND          6  /* solution is unbounded */

/* return codes: */
#define GLP_EBADB       0x01  /* invalid basis */
#define GLP_ESING       0x02  /* singular matrix */
#define GLP_ECOND       0x03  /* ill-conditioned matrix */
#define GLP_EBOUND      0x04  /* invalid bounds */
#define GLP_EFAIL       0x05  /* solver failed */
#define GLP_EOBJLL      0x06  /* objective lower limit reached */
#define GLP_EOBJUL      0x07  /* objective upper limit reached */
#define GLP_EITLIM      0x08  /* iteration limit exceeded */
#define GLP_ETMLIM      0x09  /* time limit exceeded */
#define GLP_ENOPFS      0x0A  /* no primal feasible solution */
#define GLP_ENODFS      0x0B  /* no dual feasible solution */
#define GLP_EROOT       0x0C  /* root LP optimum not provided */
#define GLP_ESTOP       0x0D  /* search terminated by application */
#define GLP_EMIPGAP     0x0E  /* relative mip gap tolerance reached */
#define GLP_ENOFEAS     0x0F  /* no primal/dual feasible solution */
#define GLP_ENOCVG      0x10  /* no convergence */
#define GLP_EINSTAB     0x11  /* numerical instability */
#define GLP_EDATA       0x12  /* invalid data */
#define GLP_ERANGE      0x13  /* result out of range */

/* enable/disable flag: */
#define GLP_ON             1  /* enable something */
#define GLP_OFF            0  /* disable something */


typedef struct
{     /* simplex method control parameters */
      int msg_lev;            /* message level: */
#define GLP_MSG_OFF        0  /* no output */
#define GLP_MSG_ERR        1  /* warning and error messages only */
#define GLP_MSG_ON         2  /* normal output */
#define GLP_MSG_ALL        3  /* full output */
#define GLP_MSG_DBG        4  /* debug output */
      int meth;               /* simplex method option: */
#define GLP_PRIMAL         1  /* use primal simplex */
#define GLP_DUALP          2  /* use dual; if it fails, use primal */
#define GLP_DUAL           3  /* use dual simplex */
      int pricing;            /* pricing technique: */
#define GLP_PT_STD      0x11  /* standard (Dantzig rule) */
#define GLP_PT_PSE      0x22  /* projected steepest edge */
      int r_test;             /* ratio test technique: */
#define GLP_RT_STD      0x11  /* standard (textbook) */
#define GLP_RT_HAR      0x22  /* two-pass Harris' ratio test */
      double tol_bnd;         /* spx.tol_bnd */
      double tol_dj;          /* spx.tol_dj */
      double tol_piv;         /* spx.tol_piv */
      double obj_ll;          /* spx.obj_ll */
      double obj_ul;          /* spx.obj_ul */
      int it_lim;             /* spx.it_lim */
      int tm_lim;             /* spx.tm_lim (milliseconds) */
      int out_frq;            /* spx.out_frq */
      int out_dly;            /* spx.out_dly (milliseconds) */
      int presolve;           /* enable/disable using LP presolver */
      double foo_bar[36];     /* (reserved) */
} glp_smcp;


typedef struct
{     /* integer optimizer control parameters */
      int msg_lev;            /* message level (see glp_smcp) */
      int br_tech;            /* branching technique: */
#define GLP_BR_FFV         1  /* first fractional variable */
#define GLP_BR_LFV         2  /* last fractional variable */
#define GLP_BR_MFV         3  /* most fractional variable */
#define GLP_BR_DTH         4  /* heuristic by Driebeck and Tomlin */
#define GLP_BR_PCH         5  /* hybrid pseudocost heuristic */
      int bt_tech;            /* backtracking technique: */
#define GLP_BT_DFS         1  /* depth first search */
#define GLP_BT_BFS         2  /* breadth first search */
#define GLP_BT_BLB         3  /* best local bound */
#define GLP_BT_BPH         4  /* best projection heuristic */
      double tol_int;         /* mip.tol_int */
      double tol_obj;         /* mip.tol_obj */
      int tm_lim;             /* mip.tm_lim (milliseconds) */
      int out_frq;            /* mip.out_frq (milliseconds) */
      int out_dly;            /* mip.out_dly (milliseconds) */

      void *cb_info;          /* mip.cb_info */
      int cb_size;            /* mip.cb_size */
      int pp_tech;            /* preprocessing technique: */
#define GLP_PP_NONE        0  /* disable preprocessing */
#define GLP_PP_ROOT        1  /* preprocessing only on root level */
#define GLP_PP_ALL         2  /* preprocessing on all levels */
      double mip_gap;         /* relative MIP gap tolerance */
      int mir_cuts;           /* MIR cuts       (GLP_ON/GLP_OFF) */
      int gmi_cuts;           /* Gomory's cuts  (GLP_ON/GLP_OFF) */
      int cov_cuts;           /* cover cuts     (GLP_ON/GLP_OFF) */
      int clq_cuts;           /* clique cuts    (GLP_ON/GLP_OFF) */
      int presolve;           /* enable/disable using MIP presolver */
      int binarize;           /* try to binarize integer variables */
      int fp_heur;            /* feasibility pump heuristic */
#if 1 /* 28/V-2010 */
      int alien;              /* use alien solver */
#endif
      double foo_bar[29];     /* (reserved) */
} glp_iocp;
#endif


/*
 * Wrappers for GLPK Functions
 */


void * _lp_create_prob ( void )
{
#if HAVE_LIBGLPK
  return glp_create_prob( );
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return NULL;
}

void _lp_set_obj_dir (void *P, int dir)
{
#if HAVE_LIBGLPK
  return glp_set_obj_dir (P, dir);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

void _lp_set_prob_name (void *P, const char *name)
{
#if HAVE_LIBGLPK
  glp_set_prob_name(P, name);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

int _lp_add_cols (void *P, int ncs)
{
#if HAVE_LIBGLPK
  return glp_add_cols(P, ncs);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

int _lp_add_rows (void *P, int nrs)
{
#if HAVE_LIBGLPK
  return glp_add_rows (P, nrs);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}


void _lp_set_row_bnds (void *P, int i, int type, double lb, double ub)
{
#if HAVE_LIBGLPK
  glp_set_row_bnds(P, i , type, lb, ub);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

void _lp_init_smcp (void * parm)
{
#if HAVE_LIBGLPK
  glp_init_smcp(parm);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

void _lp_set_col_name (void *P, int j, const char *name)
{
#if HAVE_LIBGLPK
  glp_set_col_name (P, j, name);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

void _lp_set_col_bnds (void *P, int j, int type, double lb,
      double ub)
{
#if HAVE_LIBGLPK
  glp_set_col_bnds(P, j, type, lb, ub);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

void _lp_set_obj_coef(void *P, int j, double coef)
{
#if HAVE_LIBGLPK
  glp_set_obj_coef(P, j, coef);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

void _lp_delete_prob (void * P)
{
#if HAVE_LIBGLPK
  glp_delete_prob (P);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

static int _lp_simplex(void *P, void *parm)
{
#if HAVE_LIBGLPK
  return glp_simplex (P, parm);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

static void _lp_load_matrix (void *P, int ne, const int ia[],
      const int ja[], const double ar[])
{
#if HAVE_LIBGLPK
  glp_load_matrix(P, ne, ia, ja, ar);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

static void _lp_set_mat_row (void *P, int i, int len, const int ind[],
      const double val[])
{
#if HAVE_LIBGLPK
  glp_set_mat_row (P, i, len, ind, val);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

static int _lp_write_lp (void *P, const void *parm, const char *fname)
{
#if HAVE_LIBGLPK
  return glp_write_lp ( P, parm, fname);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

static void _lp_init_iocp (void *parm)
{
#if HAVE_LIBGLPK
  glp_init_iocp (parm);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

static int _lp_intopt (void *P, const void *parm)
{
#if HAVE_LIBGLPK
  return glp_intopt (P, parm);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

static int _lp_get_status (void *P)
{
#if HAVE_LIBGLPK
  return glp_get_status (P);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

static int _lp_mip_status (void *P)
{
#if HAVE_LIBGLPK
  return glp_mip_status (P);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

static void _lp_set_col_kind (void *P, int j, int kind)
{
#if HAVE_LIBGLPK
  glp_set_col_kind (P, j, kind);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

static void _lp_free_env (void)
{
#if HAVE_LIBGLPK
  glp_free_env ();
#else
  // Function not implemented
  GNUNET_break (0);
#endif
}

static const char * _lp_get_col_name ( void *P, int j)
{
#if HAVE_LIBGLPK
  return glp_get_col_name (P, j);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return NULL;
}

static double _lp_mip_obj_val (void *P)
{
#if HAVE_LIBGLPK
  return glp_mip_obj_val (P);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0.0;
}


static double _lp_get_col_prim (void *P, int j)
{
#if HAVE_LIBGLPK
  return glp_get_col_prim (P , j);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0.0;
}

static int _lp_print_sol(void *P, const char *fname)
{
#if HAVE_LIBGLPK
  return glp_print_sol (P, fname);
#else
  // Function not implemented
  GNUNET_break (0);
#endif
  return 0;
}

/*
 * Dummy functions for CFLAGS
 */

static void _dummy2 ();
static void _dummy ()
{
  return;
  _lp_get_col_name (NULL, 0);
  _lp_mip_obj_val (NULL);
  _lp_get_col_prim (NULL, 0);
  _dummy2();
}

static void _dummy2 ()
{
  ats_modify_problem_state (NULL, 0);
   _dummy();
   int t = ATS_COST_UPDATED + ATS_MODIFIED + ATS_NEW;
   t = 0;
}

/*
 * ATS Functions
 */


/**
 * Initialize ATS
 * @param cfg configuration handle to retrieve configuration (to be removed)
 * @return
 */

struct ATS_Handle * ats_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{

#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return NULL;
#endif

  struct ATS_Handle * ats = NULL;
  int c = 0;
  unsigned long long  value;
  char * section;

  ats = GNUNET_malloc(sizeof (struct ATS_Handle));

  ats->prob = NULL;

  ats->min_delta = ATS_MIN_INTERVAL;
  ats->exec_interval = ATS_EXEC_INTERVAL;
  ats->max_exec_duration = ATS_MAX_EXEC_DURATION;
  ats->max_iterations = ATS_MAX_ITERATIONS;

  ats->D = 1.0;
  ats->U = 1.0;
  ats->R = 1.0;
  ats->v_b_min = 64000;
  ats->v_n_min = 10;
  ats->dump_min_peers = 1;
  ats->dump_min_addr = 1;
  ats->dump_overwrite = GNUNET_NO;
  ats->mechanisms = NULL;
  ats->peers = NULL;
  ats->successful_executions = 0;
  ats->invalid_executions = 0;

  /* loading cost ressources */
  for (c=0; c<available_ressources; c++)
  {
    GNUNET_asprintf(&section,"%s_UP",ressources[c].cfg_param);
    if (GNUNET_CONFIGURATION_have_value(cfg, "transport", section))
    {
      if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg,
          "transport",
          section,
          &value))
      {
#if DEBUG_ATS
              GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Found ressource cost: [%s] = %llu\n",
                  section, value);
#endif
              ressources[c].c_max = value;
      }
    }
    GNUNET_free (section);
    GNUNET_asprintf(&section,"%s_DOWN",ressources[c].cfg_param);
    if (GNUNET_CONFIGURATION_have_value(cfg, "transport", section))
    {
      if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg,
          "transport",
          section,
          &value))
      {
#if DEBUG_ATS
              GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Found ressource cost: [%s] = %llu\n",
                  section, value);
#endif
              ressources[c].c_min = value;
      }
    }
    GNUNET_free (section);
  }

  if (GNUNET_CONFIGURATION_have_value(cfg, "transport", "DUMP_MLP"))
      ats->save_mlp = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                             "transport","DUMP_MLP");

  if (GNUNET_CONFIGURATION_have_value(cfg, "transport", "DUMP_SOLUTION"))
      ats->save_solution = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                  "transport","DUMP_SOLUTION");
  if (GNUNET_CONFIGURATION_have_value(cfg, "transport", "DUMP_OVERWRITE"))
      ats->dump_overwrite = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                  "transport","DUMP_OVERWRITE");
  if (GNUNET_CONFIGURATION_have_value(cfg, "transport", "DUMP_MIN_PEERS"))
  {
          GNUNET_CONFIGURATION_get_value_number(cfg,
              "transport","DUMP_MIN_PEERS", &value);
          ats->dump_min_peers= value;
  }
  if (GNUNET_CONFIGURATION_have_value(cfg,
      "transport", "DUMP_MIN_ADDRS"))
  {
      GNUNET_CONFIGURATION_get_value_number(cfg,
        "transport","DUMP_MIN_ADDRS", &value);
      ats->dump_min_addr= value;
  }
  if (GNUNET_CONFIGURATION_have_value(cfg,
      "transport", "DUMP_OVERWRITE"))
  {
      GNUNET_CONFIGURATION_get_value_number(cfg,
          "transport","DUMP_OVERWRITE", &value);
      ats->min_delta.rel_value = value;
  }

  if (GNUNET_CONFIGURATION_have_value(cfg,
      "transport", "ATS_MIN_INTERVAL"))
  {
      GNUNET_CONFIGURATION_get_value_number(cfg,
          "transport","ATS_MIN_INTERVAL", &value);
      ats->min_delta.rel_value = value;
  }

  if (GNUNET_CONFIGURATION_have_value(cfg,
      "transport", "ATS_EXEC_INTERVAL"))
  {
      GNUNET_CONFIGURATION_get_value_number(cfg,
          "transport","ATS_EXEC_INTERVAL", &value);
      ats->exec_interval.rel_value = value;
  }
  if (GNUNET_CONFIGURATION_have_value(cfg, "transport", "ATS_MIN_INTERVAL"))
  {
      GNUNET_CONFIGURATION_get_value_number(cfg,
          "transport","ATS_MIN_INTERVAL", &value);
      ats->min_delta.rel_value = value;
  }
  return ats;
}


/** solve the bandwidth distribution problem
 * @param max_it maximum iterations
 * @param max_dur maximum duration in ms
 * @param D     weight for diversity
 * @param U weight for utility
 * @param R weight for relativity
 * @param v_b_min minimal bandwidth per peer
 * @param v_n_min minimum number of connections
 * @param stat result struct
 * @return GNUNET_SYSERR if glpk is not available, number of mechanisms used
 */
int ats_create_problem (struct ATS_Handle *ats,
                        struct NeighbourList *neighbours,
                        double D,
                        double U,
                        double R,
                        int v_b_min,
                        int v_n_min,
                        struct ATS_stat *stat)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return GNUNET_SYSERR;
#endif

  ats->prob = _lp_create_prob();

  int c;
  int c_peers = 0;
  int c_mechs = 0;

  int c_c_ressources = available_ressources;
  int c_q_metrics = available_quality_metrics;

  double M = VERY_BIG_DOUBLE_VALUE;
  double Q[c_q_metrics+1];
  for (c=1; c<=c_q_metrics; c++)
  {
          Q[c] = 1;
  }

  struct NeighbourList *next = neighbours;
  while (next!=NULL)
  {
          int found_addresses = GNUNET_NO;
          struct ReadyList *r_next = next->plugins;
          while (r_next != NULL)
          {
                  struct ForeignAddressList * a_next = r_next->addresses;
                  while (a_next != NULL)
                  {
                          c_mechs++;
                          found_addresses = GNUNET_YES;
                          a_next = a_next->next;
                  }
                  r_next = r_next->next;
          }
          if (found_addresses) c_peers++;
          next = next->next;
  }

  if (c_mechs==0)
  {
#if DEBUG_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "No addresses for bw distribution available\n",
              c_peers);
#endif
          stat->valid = GNUNET_NO;
          stat->c_peers = 0;
          stat->c_mechs = 0;
          return GNUNET_SYSERR;
  }

  GNUNET_assert (ats->mechanisms == NULL);
  ats->mechanisms = GNUNET_malloc((1+c_mechs) * sizeof (struct ATS_mechanism));
  GNUNET_assert (ats->peers == NULL);
  ats->peers =  GNUNET_malloc((1+c_peers) * sizeof (struct ATS_peer));

  struct ATS_mechanism * mechanisms = ats->mechanisms;
  struct ATS_peer * peers = ats->peers;

  c_mechs = 1;
  c_peers = 1;

  next = neighbours;
  while (next!=NULL)
  {
    int found_addresses = GNUNET_NO;
    struct ReadyList *r_next = next->plugins;
    while (r_next != NULL)
    {
        struct ForeignAddressList * a_next = r_next->addresses;
        while (a_next != NULL)
        {
            if (found_addresses == GNUNET_NO)
            {
              peers[c_peers].peer = next->id;
              peers[c_peers].m_head = NULL;
              peers[c_peers].m_tail = NULL;
              peers[c_peers].f = 1.0 / c_mechs;
            }

            mechanisms[c_mechs].addr = a_next;
            mechanisms[c_mechs].col_index = c_mechs;
            mechanisms[c_mechs].peer = &peers[c_peers];
            mechanisms[c_mechs].next = NULL;
            mechanisms[c_mechs].plugin = r_next->plugin;

            GNUNET_CONTAINER_DLL_insert_tail(peers[c_peers].m_head,
                                             peers[c_peers].m_tail,
                                             &mechanisms[c_mechs]);
            found_addresses = GNUNET_YES;
            c_mechs++;

            a_next = a_next->next;
        }
        r_next = r_next->next;
    }
    if (found_addresses == GNUNET_YES)
        c_peers++;
    next = next->next;
  }
  c_mechs--;
  c_peers--;

  if (v_n_min > c_peers)
          v_n_min = c_peers;

#if VERBOSE_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Creating problem with: %i peers, %i mechanisms, %i resource entries, %i quality metrics \n",
      c_peers,
      c_mechs,
      c_c_ressources,
      c_q_metrics);
#endif

  int size =  1 + 3 + 10 *c_mechs + c_peers +
              (c_q_metrics*c_mechs)+ c_q_metrics + c_c_ressources * c_mechs ;
  int row_index;
  int array_index=1;
  int * ia = GNUNET_malloc (size * sizeof (int));
  int * ja = GNUNET_malloc (size * sizeof (int));
  double * ar = GNUNET_malloc(size* sizeof (double));

  _lp_set_prob_name (ats->prob, "gnunet ats bandwidth distribution");
  _lp_set_obj_dir(ats->prob, GLP_MAX);

  /* adding columns */
  char * name;
  _lp_add_cols(ats->prob, 2 * c_mechs);
  /* adding b_t cols */
  for (c=1; c <= c_mechs; c++)
  {
    GNUNET_asprintf(&name,
        "p_%s_b%i",GNUNET_i2s(&(mechanisms[c].peer->peer)), c);
    _lp_set_col_name(ats->prob, c, name);
    GNUNET_free (name);
    _lp_set_col_bnds(ats->prob, c, GLP_LO, 0.0, 0.0);
    _lp_set_col_kind(ats->prob, c, GLP_CV);
    //_lp_set_obj_coef(ats->prob, c, 0);
  }

  /* adding n_t cols */
  for (c=c_mechs+1; c <= 2*c_mechs; c++)
  {
    GNUNET_asprintf(&name,
        "p_%s_n%i",GNUNET_i2s(&(mechanisms[c-c_mechs].peer->peer)),(c-c_mechs));
    _lp_set_col_name(ats->prob, c, name);
    GNUNET_free (name);
    _lp_set_col_bnds(ats->prob, c, GLP_DB, 0.0, 1.0);
    _lp_set_col_kind(ats->prob, c, GLP_IV);
    _lp_set_obj_coef(ats->prob, c, 0);
  }

  /* feasibility constraints */
  /* Constraint 1: one address per peer*/
  row_index = 1;

  _lp_add_rows(ats->prob, c_peers);

  for (c=1; c<=c_peers; c++)
  {
#if VERBOSE_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",
          row_index);
#endif

      _lp_set_row_bnds(ats->prob, row_index, GLP_FX, 1.0, 1.0);
      struct ATS_mechanism *m = peers[c].m_head;
      while (m!=NULL)
      {
        ia[array_index] = row_index;
        ja[array_index] = (c_mechs + m->col_index);
        ar[array_index] = 1;
#if VERBOSE_ATS
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
            array_index,
            ia[array_index],
            ja[array_index],
            ar[array_index]);
#endif
        array_index++;
        m = m->next;
      }
      row_index++;
  }

  /* Constraint 2: only active mechanism gets bandwidth assigned */
  _lp_add_rows(ats->prob, c_mechs);
  for (c=1; c<=c_mechs; c++)
  {
          /* b_t - n_t * M <= 0 */
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",
              row_index);
#endif
          _lp_set_row_bnds(ats->prob, row_index, GLP_UP, 0.0, 0.0);
          ia[array_index] = row_index;
          ja[array_index] = mechanisms[c].col_index;
          ar[array_index] = 1;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index,
              ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
          ia[array_index] = row_index;
          ja[array_index] = c_mechs + mechanisms[c].col_index;
          ar[array_index] = -M;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index,
              ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
          row_index ++;
  }

  /* Constraint 3: minimum bandwidth*/
  _lp_add_rows(ats->prob, c_mechs);

  for (c=1; c<=c_mechs; c++)
  {
          /* b_t - n_t * b_min <= 0 */
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",
              row_index);
#endif
#if HAVE_LIBGLPK
          _lp_set_row_bnds(ats->prob, row_index, GLP_LO, 0.0, 0.0);
#endif
          ia[array_index] = row_index;
          ja[array_index] = mechanisms[c].col_index;
          ar[array_index] = 1;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index,
              ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
          ia[array_index] = row_index;
          ja[array_index] = c_mechs + mechanisms[c].col_index;
          ar[array_index] = -v_b_min;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index,
              ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
          row_index ++;
  }
  int c2;

  /* Constraint 4: max ressource capacity */
  /* V cr: bt * ct_r <= cr_max
   * */

  _lp_add_rows(ats->prob, available_ressources);

  double ct_max = VERY_BIG_DOUBLE_VALUE;
  double ct_min = 0.0;

  stat->begin_cr = array_index;

  for (c=0; c<available_ressources; c++)
  {
      ct_max = ressources[c].c_max;
      ct_min = ressources[c].c_min;
#if VERBOSE_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] %f..%f\n",
          row_index,
          ct_min,
          ct_max);
#endif
#if HAVE_LIBGLPK
      _lp_set_row_bnds(ats->prob, row_index, GLP_DB, ct_min, ct_max);
#endif
      for (c2=1; c2<=c_mechs; c2++)
      {
          double value = 0;
          ia[array_index] = row_index;
          ja[array_index] = c2;
          value = mechanisms[c2].addr->ressources[c].c;
          ar[array_index] = value;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index, ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
      }
      row_index ++;
  }
  stat->end_cr = array_index--;

  /* Constraint 5: min number of connections*/
  _lp_add_rows(ats->prob, 1);

  for (c=1; c<=c_mechs; c++)
  {
          // b_t - n_t * b_min >= 0
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",
              row_index);
#endif
          _lp_set_row_bnds(ats->prob, row_index, GLP_LO, v_n_min, 0.0);
          ia[array_index] = row_index;
          ja[array_index] = c_mechs + mechanisms[c].col_index;
          ar[array_index] = 1;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index,
              ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
  }
  row_index ++;

  // optimisation constraints

  // adding columns

  // Constraint 6: optimize for diversity
  int col_d;
  col_d = _lp_add_cols(ats->prob, 1);

  _lp_set_col_name(ats->prob, col_d, "d");
  _lp_set_obj_coef(ats->prob, col_d, D);
  _lp_set_col_bnds(ats->prob, col_d, GLP_LO, 0.0, 0.0);
  _lp_add_rows(ats->prob, 1);
  _lp_set_row_bnds(ats->prob, row_index, GLP_FX, 0.0, 0.0);

  stat->col_d = col_d;
#if VERBOSE_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
#endif
  for (c=1; c<=c_mechs; c++)
  {
    ia[array_index] = row_index;
    ja[array_index] = c_mechs + mechanisms[c].col_index;
    ar[array_index] = 1;
#if VERBOSE_ATS
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
        array_index,
        ia[array_index],
        ja[array_index],
        ar[array_index]);
#endif
    array_index++;
  }
  ia[array_index] = row_index;
  ja[array_index] = col_d;
  ar[array_index] = -1;
#if VERBOSE_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
      array_index,
      ia[array_index],
      ja[array_index],
      ar[array_index]);
#endif
  array_index++;
  row_index ++;

  // Constraint 7: optimize for quality
  int col_qm;
  col_qm = _lp_add_cols(ats->prob, c_q_metrics);

  stat->col_qm = col_qm;
  //GNUNET_assert (col_qm == (2*c_mechs) + 3 + 1);
  for (c=0; c< c_q_metrics; c++)
  {
    GNUNET_asprintf(&name, "Q_%s",qm[c].name);
    _lp_set_col_name (ats->prob, col_qm + c, name);
    _lp_set_col_bnds (ats->prob, col_qm + c, GLP_LO, 0.0, 0.0);
    GNUNET_free (name);
    _lp_set_obj_coef (ats->prob, col_qm + c, Q[c]);
  }

  _lp_add_rows(ats->prob, available_quality_metrics);

  stat->begin_qm = row_index;
  for (c=1; c <= c_q_metrics; c++)
  {
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",
              row_index);
#endif
      double value = 1;
      _lp_set_row_bnds(ats->prob, row_index, GLP_FX, 0.0, 0.0);
      for (c2=1; c2<=c_mechs; c2++)
      {
          ia[array_index] = row_index;
          ja[array_index] = c2;
          if (qm[c-1].atis_index  == GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY)
          {
            double v0 = 0, v1 = 0, v2 = 0;
            v0 = mechanisms[c2].addr->quality[c-1].values[0];
            if (v1 < 1) v0 = 0.1;
              v1 = mechanisms[c2].addr->quality[c-1].values[1];
            if (v1 < 1) v0 = 0.1;
              v2 = mechanisms[c2].addr->quality[c-1].values[2];
            if (v1 < 1) v0 = 0.1;
              value = 100.0 / ((v0 + 2 * v1 + 3 * v2) / 6.0);
            value = 1;
          }
          if (qm[c-1].atis_index  == GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE)
          {
            double v0 = 0, v1 = 0, v2 = 0;
            v0 = mechanisms[c2].addr->quality[c-1].values[0];
            if (v0 < 1) v0 = 1;
              v1 = mechanisms[c2].addr->quality[c-1].values[1];
            if (v1 < 1) v1 = 1;
              v2 = mechanisms[c2].addr->quality[c-1].values[2];
            if (v2 < 1) v2 = 1;
              value =  (v0 + 2 * v1 + 3 * v2) / 6.0;
            if (value >= 1)
              value =  (double) 10 / value;
            else
              value = 10;
          }
          ar[array_index] = (mechanisms[c2].peer->f) * value ;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: %s [%i,%i]=%f \n",
              array_index,
              qm[c-1].name,
              ia[array_index],
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
      }
      ia[array_index] = row_index;
      ja[array_index] = col_qm + c - 1;
      ar[array_index] = -1;
#if VERBOSE_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
          array_index,
          ia[array_index],
          ja[array_index],
          ar[array_index]);
#endif
      array_index++;
      row_index++;
  }
  stat->end_qm = row_index-1;

  // Constraint 8: optimize bandwidth utility
  int col_u;

  col_u = _lp_add_cols(ats->prob, 1);

  _lp_set_col_name(ats->prob, col_u, "u");
  _lp_set_obj_coef(ats->prob, col_u, U);
  _lp_set_col_bnds(ats->prob, col_u, GLP_LO, 0.0, 0.0);
  _lp_add_rows(ats->prob, 1);
  stat->col_u = col_u;
#if VERBOSE_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
#endif
  _lp_set_row_bnds(ats->prob, row_index, GLP_FX, 0.0, 0.0);
  for (c=1; c<=c_mechs; c++)
  {
    ia[array_index] = row_index;
    ja[array_index] = c;
    ar[array_index] = mechanisms[c].peer->f;
#if VERBOSE_ATS
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
        array_index,
        ia[array_index],
        ja[array_index],
        ar[array_index]);
#endif
    array_index++;
  }
  ia[array_index] = row_index;
  ja[array_index] = col_u;
  ar[array_index] = -1;
#if VERBOSE_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
      array_index, ia[array_index],
      ja[array_index],
      ar[array_index]);
#endif

  array_index++;
  row_index ++;

  // Constraint 9: optimize relativity
  int col_r;

  col_r = _lp_add_cols(ats->prob, 1);

  _lp_set_col_name(ats->prob, col_r, "r");
  _lp_set_obj_coef(ats->prob, col_r, R);
  _lp_set_col_bnds(ats->prob, col_r, GLP_LO, 0.0, 0.0);
  _lp_add_rows(ats->prob, c_peers);

  stat->col_r = col_r;
  for (c=1; c<=c_peers; c++)
  {
    _lp_set_row_bnds(ats->prob, row_index, GLP_LO, 0.0, 0.0);
    struct ATS_mechanism *m = peers[c].m_head;
    while (m!=NULL)
    {
      ia[array_index] = row_index;
      ja[array_index] = m->col_index;
      ar[array_index] = 1 / mechanisms[c].peer->f;
#if VERBOSE_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
          array_index,
          ia[array_index],
          ja[array_index],
          ar[array_index]);
#endif
      array_index++;
      m = m->next;
    }
    ia[array_index] = row_index;
    ja[array_index] = col_r;
    ar[array_index] = -1;
#if VERBOSE_ATS
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
        array_index,
        ia[array_index],
        ja[array_index],
        ar[array_index]);
#endif
    array_index++;
    row_index++;
  }

  /* Loading the matrix */
  _lp_load_matrix(ats->prob, array_index-1, ia, ja, ar);

  stat->c_mechs = c_mechs;
  stat->c_peers = c_peers;
  stat->solution = 0;
  stat->valid = GNUNET_YES;

  /* clean up */
  GNUNET_free (ja);
  GNUNET_free (ia);
  GNUNET_free (ar);

  return GNUNET_OK;
}


void ats_delete_problem (struct ATS_Handle * ats)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return;
#endif

#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Deleting problem\n");
#endif
  int c;

  for (c=0; c< (ats->stat).c_mechs; c++)
          GNUNET_free_non_null (ats->mechanisms[c].rc);
  if (ats->mechanisms!=NULL)
  {
    GNUNET_free(ats->mechanisms);
    ats->mechanisms = NULL;
  }

  if (ats->peers!=NULL)
  {
    GNUNET_free(ats->peers);
    ats->peers = NULL;
  }

  if (ats->prob != NULL)
  {
    _lp_delete_prob(ats->prob);
    ats->prob = NULL;
  }

  ats->stat.begin_cr = GNUNET_SYSERR;
  ats->stat.begin_qm = GNUNET_SYSERR;
  ats->stat.c_mechs = 0;
  ats->stat.c_peers = 0;
  ats->stat.end_cr = GNUNET_SYSERR;
  ats->stat.end_qm = GNUNET_SYSERR;
  ats->stat.solution = GNUNET_SYSERR;
  ats->stat.valid = GNUNET_SYSERR;
}

void ats_modify_problem_state (struct ATS_Handle * ats, enum ATS_problem_state s)
{
  if (ats == NULL)
    return;
  switch (s)
  {
  case ATS_NEW :
    ats->stat.recreate_problem = GNUNET_NO;
    ats->stat.modified_quality = GNUNET_NO;
    ats->stat.modified_resources = GNUNET_NO;
    break;
  case ATS_MODIFIED:
    ats->stat.recreate_problem = GNUNET_YES;
    break;
  case ATS_QUALITY_UPDATED :
    ats->stat.modified_quality = GNUNET_YES;
    break;
  case ATS_COST_UPDATED :
    ats->stat.modified_resources = GNUNET_YES;
    break;
  case ATS_QUALITY_COST_UPDATED:
    ats->stat.modified_resources = GNUNET_YES;
    ats->stat.modified_quality = GNUNET_YES;
    break;
  default:
    return;
  }



}

void ats_solve_problem (struct ATS_Handle * ats,
    unsigned int max_it,
    unsigned int  max_dur,
    unsigned int c_peers,
    unsigned int  c_mechs,
    struct ATS_stat *stat)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return;
#endif


  int result = GNUNET_SYSERR;
  int lp_solution = GNUNET_SYSERR;
  int mlp_solution = GNUNET_SYSERR;

  // Solving simplex

  glp_smcp opt_lp;
  _lp_init_smcp(&opt_lp);
#if VERBOSE_ATS
  opt_lp.msg_lev = GLP_MSG_ALL;
#else
  opt_lp.msg_lev = GLP_MSG_OFF;
#endif
  // setting iteration limit
  opt_lp.it_lim = max_it;
  // maximum duration
  opt_lp.tm_lim = max_dur;

  if (ats->stat.recreate_problem == GNUNET_YES)
     opt_lp.presolve = GLP_ON;

  result = _lp_simplex(ats->prob, &opt_lp);
  lp_solution =  _lp_get_status (ats->prob);

  if ((result == GLP_ETMLIM) || (result == GLP_EITLIM))
  {
    ats->stat.valid = GNUNET_NO;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "ATS exceeded time or iteration limit!\n");
    return;
  }

  if (ats_evaluate_results(result, lp_solution, "LP") == GNUNET_YES)
  {
    stat->valid = GNUNET_YES;
  }
  else
  {
    ats->stat.simplex_rerun_required = GNUNET_YES;
    opt_lp.presolve = GLP_ON;
    result = _lp_simplex(ats->prob, &opt_lp);
    lp_solution =  _lp_get_status (ats->prob);

    // TODO: Remove if this does not appear until release
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ""
        "EXECUTED SIMPLEX WITH PRESOLVER! %i \n",
        lp_solution);

    if (ats_evaluate_results(result, lp_solution, "LP") != GNUNET_YES)
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "After execution simplex with presolver: STILL INVALID!\n");
        char * filename;
        GNUNET_asprintf (&filename,
            "ats_mlp_p%i_m%i_%llu.mlp",
            ats->stat.c_peers,
            ats->stat.c_mechs,
            GNUNET_TIME_absolute_get().abs_value);
        _lp_write_lp ((void *)ats->prob, NULL, filename);
        GNUNET_free (filename);
        stat->valid = GNUNET_NO;
        ats->stat.recreate_problem = GNUNET_YES;
        return;
    }
    stat->valid = GNUNET_YES;
  }

  // Solving mlp
  glp_iocp opt_mlp;
  _lp_init_iocp(&opt_mlp);
  // maximum duration
  opt_mlp.tm_lim = max_dur;
  // output level
#if VERBOSE_ATS
  opt_mlp.msg_lev = GLP_MSG_ALL;
#else
  opt_mlp.msg_lev = GLP_MSG_OFF;
#endif

  result = _lp_intopt (ats->prob, &opt_mlp);
  mlp_solution =  _lp_mip_status (ats->prob);
  stat->solution = mlp_solution;

  if (ats_evaluate_results(result, mlp_solution, "MLP") == GNUNET_YES)
  {
      stat->valid = GNUNET_YES;
  }
  else
  {
      // TODO: Remove if this does not appear until release
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "MLP solution for %i peers, %i mechs is invalid: %i\n",
          ats->stat.c_peers,
          ats->stat.c_mechs,
          mlp_solution);
      stat->valid = GNUNET_NO;
  }

#if VERBOSE_ATS
  if (_lp_get_col_prim(ats->prob,2*c_mechs+1) != 1)
  {
  int c;
  for (c=1; c<= available_quality_metrics; c++ )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n",
        _lp_get_col_name(ats->prob,2*c_mechs+3+c),
        _lp_get_col_prim(ats->prob,2*c_mechs+3+c));
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n",
      _lp_get_col_name(ats->prob,2*c_mechs+1),
      _lp_get_col_prim(ats->prob,2*c_mechs+1));
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n",
      _lp_get_col_name(ats->prob,2*c_mechs+2),
      _lp_get_col_prim(ats->prob,2*c_mechs+2));
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s %f\n",
      _lp_get_col_name(ats->prob,2*c_mechs+3),
      _lp_get_col_prim(ats->prob,2*c_mechs+3));
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "objective value:  %f\n",
      _lp_mip_obj_val(ats->prob));
  }
#endif
}


void ats_shutdown (struct ATS_Handle * ats)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return;
#endif

#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "ATS shutdown\n");
#endif
  ats_delete_problem (ats);
  _lp_free_env();

  GNUNET_free (ats);
}

void ats_update_problem_qm (struct ATS_Handle * ats)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return;
#endif

    int array_index;
    int row_index;
    int c, c2;
    int c_q_metrics = available_quality_metrics;

    int *ja = GNUNET_malloc ((1 + ats->stat.c_mechs*2 + 3 +
       available_quality_metrics) * sizeof (int));
    double *ar = GNUNET_malloc ((1 + ats->stat.c_mechs*2 + 3 +
       available_quality_metrics) * sizeof (double));
#if DEBUG_ATS
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Updating problem quality metrics\n");
#endif
    row_index = ats->stat.begin_qm;

    for (c=1; c <= c_q_metrics; c++)
    {
      array_index = 1;
      double value = 1;
#if VERBOSE_ATS
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] \n",row_index);
#endif
        _lp_set_row_bnds(ats->prob, row_index, GLP_FX, 0.0, 0.0);
        for (c2=1; c2<=ats->stat.c_mechs; c2++)
        {
          ja[array_index] = c2;
          GNUNET_assert (ats->mechanisms[c2].addr != NULL);
          GNUNET_assert (ats->mechanisms[c2].peer != NULL);

          if (qm[c-1].atis_index  == GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY)
          {
              double v0 = 0, v1 = 0, v2 = 0;

              v0 = ats->mechanisms[c2].addr->quality[c-1].values[0];
              if (v1 < 1) v0 = 0.1;
              v1 = ats->mechanisms[c2].addr->quality[c-1].values[1];
              if (v1 < 1) v0 = 0.1;
              v2 = ats->mechanisms[c2].addr->quality[c-1].values[2];
              if (v1 < 1) v0 = 0.1;
              value = 100.0 / ((v0 + 2 * v1 + 3 * v2) / 6.0);
              //value = 1;
          }
          if (qm[c-1].atis_index  == GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE)
          {
              double v0 = 0, v1 = 0, v2 = 0;
              v0 = ats->mechanisms[c2].addr->quality[c-1].values[0];
              if (v0 < 1) v0 = 1;
              v1 = ats->mechanisms[c2].addr->quality[c-1].values[1];
              if (v1 < 1) v1 = 1;
              v2 = ats->mechanisms[c2].addr->quality[c-1].values[2];
              if (v2 < 1) v2 = 1;
              value =  (v0 + 2 * v1 + 3 * v2) / 6.0;
              if (value >= 1)
                      value =  (double) 10 / value;
              else
                      value = 10;
          }
          ar[array_index] = (ats->mechanisms[c2].peer->f) * value;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: %s [%i,%i]=%f \n",
              array_index,
              qm[c-1].name,
              row_index,
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
        }
      ja[array_index] = ats->stat.col_qm + c - 1;
      ar[array_index] = -1;

#if VERBOSE_ATS
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
            array_index,
            row_index,
            ja[array_index],
            ar[array_index]);
#endif
      _lp_set_mat_row (ats->prob, row_index, array_index, ja, ar);
      array_index = 1;
      row_index++;
    }
    GNUNET_free_non_null (ja);
    GNUNET_free_non_null (ar);
}


void
ats_calculate_bandwidth_distribution (struct ATS_Handle * ats,
    struct GNUNET_STATISTICS_Handle *stats,
    struct NeighbourList *neighbours)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return;
#endif

    struct GNUNET_TIME_Absolute start;
    struct GNUNET_TIME_Relative creation;
    struct GNUNET_TIME_Relative solving;
    char *text = "unmodified";

    struct GNUNET_TIME_Relative delta = GNUNET_TIME_absolute_get_difference (ats->last,
        GNUNET_TIME_absolute_get());
    if (delta.rel_value < ats->min_delta.rel_value)
    {
#if DEBUG_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_BULK,
          "Minimum time between cycles not reached\n");
#endif
            return;
    }

#if FIXME_WACHS
    int dur;
    if (INT_MAX < ats->max_exec_duration.rel_value)
            dur = INT_MAX;
    else
            dur = (int) ats->max_exec_duration.rel_value;
#endif

    ats->stat.simplex_rerun_required = GNUNET_NO;
    start = GNUNET_TIME_absolute_get();
    if ((ats->stat.recreate_problem == GNUNET_YES) ||
        (ats->prob==NULL) ||
        (ats->stat.valid == GNUNET_NO))
    {
      text = "new";
      ats->stat.recreate_problem = GNUNET_YES;
      ats_delete_problem (ats);
      ats_create_problem (ats,
          neighbours,
          ats->D,
          ats->U,
          ats->R,
          ats->v_b_min,
          ats->v_n_min,
          &ats->stat);
#if DEBUG_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
          "Peers/Addresses were modified... new problem: %i peer, %i mechs\n",
          ats->stat.c_peers,
          ats->stat.c_mechs);
#endif
    }

    else if ((ats->stat.recreate_problem == GNUNET_NO) &&
        (ats->stat.modified_resources == GNUNET_YES) &&
        (ats->stat.valid == GNUNET_YES))
    {
      text = "modified resources";
      ats_update_problem_cr (ats);
    }
    else if ((ats->stat.recreate_problem == GNUNET_NO) &&
        (ats->stat.modified_quality == GNUNET_YES) &&
        (ats->stat.valid == GNUNET_YES))
    {
      text = "modified quality";
      ats_update_problem_qm (ats);
        //ats_update_problem_qm_TEST ();
    }
#if DEBUG_ATS
    else GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Problem is unmodified\n");
#endif

    creation = GNUNET_TIME_absolute_get_difference(start,GNUNET_TIME_absolute_get());
    start = GNUNET_TIME_absolute_get();

    ats->stat.solution = GLP_UNDEF;
    if (ats->stat.valid == GNUNET_YES)
    {
      ats_solve_problem(ats,
          ats->max_iterations,
          ats->max_exec_duration.rel_value,
          ats->stat.c_peers,
          ats->stat.c_mechs,
          &ats->stat);
    }
    solving = GNUNET_TIME_absolute_get_difference(start,GNUNET_TIME_absolute_get());

    if (ats->stat.valid == GNUNET_YES)
    {
      int msg_type = GNUNET_ERROR_TYPE_DEBUG;
#if DEBUG_ATS
      msg_type = GNUNET_ERROR_TYPE_ERROR;
#endif
      GNUNET_log (msg_type,
          "MLP %s: creation time: %llu, execution time: %llu, %i mechanisms, simplex rerun: %s, solution %s\n",
          text,
          creation.rel_value,
          solving.rel_value,
          ats->stat.c_mechs,
          (ats->stat.simplex_rerun_required == GNUNET_NO) ? "NO" : "YES",
          (ats->stat.solution == 5) ? "OPTIMAL" : "INVALID");
      ats->successful_executions ++;
      GNUNET_STATISTICS_set (stats, "# ATS successful executions",
          ats->successful_executions,
          GNUNET_NO);

      if ((ats->stat.recreate_problem == GNUNET_YES) || (ats->prob==NULL))
          GNUNET_STATISTICS_set (stats, "ATS state",ATS_NEW, GNUNET_NO);
      else if ((ats->stat.modified_resources == GNUNET_YES) &&
              (ats->stat.modified_quality == GNUNET_NO))
        GNUNET_STATISTICS_set (stats, "ATS state", ATS_COST_UPDATED, GNUNET_NO);
      else if ((ats->stat.modified_resources == GNUNET_NO) &&
              (ats->stat.modified_quality == GNUNET_YES) &&
              (ats->stat.simplex_rerun_required == GNUNET_NO))
        GNUNET_STATISTICS_set (stats, "ATS state", ATS_QUALITY_UPDATED, GNUNET_NO);
      else if ((ats->stat.modified_resources == GNUNET_YES) &&
              (ats->stat.modified_quality == GNUNET_YES) &&
              (ats->stat.simplex_rerun_required == GNUNET_NO))
        GNUNET_STATISTICS_set (stats, "ATS state", ATS_QUALITY_COST_UPDATED, GNUNET_NO);
      else if (ats->stat.simplex_rerun_required == GNUNET_NO)
        GNUNET_STATISTICS_set (stats, "ATS state", ATS_UNMODIFIED, GNUNET_NO);
    }
    else
    {
      if (ats->stat.c_peers != 0)
      {
        ats->invalid_executions ++;
        GNUNET_STATISTICS_set (stats, "# ATS invalid executions",
            ats->invalid_executions, GNUNET_NO);
      }
      else
      {
        GNUNET_STATISTICS_set (stats, "# ATS successful executions",
            ats->successful_executions, GNUNET_NO);
      }
    }

    GNUNET_STATISTICS_set (stats,
        "ATS duration", solving.rel_value + creation.rel_value, GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "ATS mechanisms", ats->stat.c_mechs, GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "ATS peers", ats->stat.c_peers, GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "ATS solution", ats->stat.solution, GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
        "ATS timestamp", start.abs_value, GNUNET_NO);

    if ((ats->save_mlp == GNUNET_YES) &&
        (ats->stat.c_mechs >= ats->dump_min_peers) &&
        (ats->stat.c_mechs >= ats->dump_min_addr))
    {
        char * filename;
        if (ats->dump_overwrite == GNUNET_NO)
        {
          GNUNET_asprintf (&filename, "ats_mlp_p%i_m%i_%s_%llu.mlp",
              ats->stat.c_peers,
              ats->stat.c_mechs,
              text,
              GNUNET_TIME_absolute_get().abs_value);
          _lp_write_lp ((void *) ats->prob, NULL, filename);
        }
        else
        {
          GNUNET_asprintf (&filename, "ats_mlp_p%i_m%i.mlp",
          ats->stat.c_peers, ats->stat.c_mechs );
          _lp_write_lp ((void *) ats->prob, NULL, filename);
        }
        GNUNET_free (filename);
    }
    if ((ats->save_solution == GNUNET_YES) &&
        (ats->stat.c_mechs >= ats->dump_min_peers) &&
        (ats->stat.c_mechs >= ats->dump_min_addr))
    {
        char * filename;
        if (ats->dump_overwrite == GNUNET_NO)
        {
          GNUNET_asprintf (&filename, "ats_mlp_p%i_m%i_%s_%llu.sol",
              ats->stat.c_peers,
              ats->stat.c_mechs,
              text,
              GNUNET_TIME_absolute_get().abs_value);
          _lp_print_sol (ats->prob, filename);
        }
        else
        {
          GNUNET_asprintf (&filename, "ats_mlp_p%i_m%i.sol",
          ats->stat.c_peers, ats->stat.c_mechs);
          _lp_print_sol (ats->prob, filename);
        }
        GNUNET_free (filename);
    }
    ats->last = GNUNET_TIME_absolute_get();
    ats->stat.recreate_problem = GNUNET_NO;
    ats->stat.modified_resources = GNUNET_NO;
    ats->stat.modified_quality = GNUNET_NO;
}

/**
 * Evaluate the result of the last simplex or mlp solving
 * @param result return value returned by the solver
 * @param solution solution state
 * @param problem mlp or lp
 * @return GNUNET_NO if solution is invalid, GNUNET_YES if solution is
 *      valid
 */

int ats_evaluate_results (int result, int solution, char * problem)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return GNUNET_NO;
#endif

    int cont = GNUNET_NO;
#if DEBUG_ATS || VERBOSE_ATS
    int error_kind = GNUNET_ERROR_TYPE_DEBUG;
#endif
#if VERBOSE_ATS
    error_kind = GNUNET_ERROR_TYPE_ERROR;
#endif
    switch (result) {
    case GNUNET_SYSERR : /* GNUNET problem, not GLPK related */
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s, GLPK solving not executed\n", problem);
#endif
         break;
      case GLP_ESTOP  :    /* search terminated by application */
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s , Search terminated by application\n", problem);
#endif
        break;
      case GLP_EITLIM :    /* iteration limit exceeded */
#if DEBUG_ATS || VERBOSE_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
          "%s Iteration limit exceeded\n", problem);
#endif
        break;
     case GLP_ETMLIM :    /* time limit exceeded */
#if DEBUG_ATS || VERBOSE_ATS
       GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
           "%s Time limit exceeded\n", problem);
#endif
       break;
     case GLP_ENOPFS :    /* no primal feasible solution */
     case GLP_ENODFS :    /* no dual feasible solution */
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s No feasible solution\n", problem);
#endif
        break;
     case GLP_EBADB  :    /* invalid basis */
     case GLP_ESING  :    /* singular matrix */
     case GLP_ECOND  :    /* ill-conditioned matrix */
     case GLP_EBOUND :    /* invalid bounds */
     case GLP_EFAIL  :    /* solver failed */
     case GLP_EOBJLL :    /* objective lower limit reached */
     case GLP_EOBJUL :    /* objective upper limit reached */
     case GLP_EROOT  :    /* root LP optimum not provided */
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s Invalid Input data: %i\n",
            problem, result);
#endif
        break;
     case 0:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s Problem has been solved\n", problem);
#endif
    break;
  }

  switch (solution) {
      case GLP_UNDEF:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s solution is undefined\n", problem);
#endif
        break;
      case GLP_OPT:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s solution is optimal\n", problem);
#endif
        cont=GNUNET_YES;
        break;
      case GLP_FEAS:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind,
            "%s solution is %s feasible, however, its optimality (or non-optimality) has not been proven\n",
            problem, (0==strcmp(problem,"LP")?"":"integer"));
#endif
        cont=GNUNET_YES;
        break;
      case GLP_NOFEAS:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind, "%s problem has no %sfeasible solution\n",
            problem,  (0==strcmp(problem,"LP")?"":"integer "));
#endif
        break;
      case GLP_INFEAS:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind, "%s problem is infeasible \n", problem);
#endif
        break;
      case GLP_UNBND:
#if DEBUG_ATS || VERBOSE_ATS
        GNUNET_log (error_kind, "%s problem is unbounded \n", problem);
#endif
      default:
        break;
  }
return cont;
}

void ats_update_problem_cr (struct ATS_Handle * ats)
{
#if !HAVE_LIBGLPK
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ATS not active\n");
  return;
#endif

    int array_index;
    int row_index;
    int c, c2;
    double ct_max, ct_min;

    int *ja    = GNUNET_malloc ((1 + ats->stat.c_mechs*2 + 3 +
        available_quality_metrics) * sizeof (int));
    double *ar = GNUNET_malloc ((1 + ats->stat.c_mechs*2 + 3 +
        available_quality_metrics) * sizeof (double));

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Updating problem quality metrics\n");
    row_index = ats->stat.begin_cr;
    array_index = 1;

    for (c=0; c<available_ressources; c++)
    {
      ct_max = ressources[c].c_max;
      ct_min = ressources[c].c_min;
#if VERBOSE_ATS
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "bounds [row]=[%i] %f..%f\n",
          row_index,
          ct_min,
          ct_max);
#endif
      _lp_set_row_bnds(ats->prob, row_index, GLP_DB, ct_min, ct_max);
      for (c2=1; c2<=ats->stat.c_mechs; c2++)
      {
          double value = 0;
          GNUNET_assert (ats->mechanisms[c2].addr != NULL);
          GNUNET_assert (ats->mechanisms[c2].peer != NULL);

          ja[array_index] = c2;
          value = ats->mechanisms[c2].addr->ressources[c].c;
          ar[array_index] = value;
#if VERBOSE_ATS
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "[index]=[%i]: [%i,%i]=%f \n",
              array_index,
              row_index,
              ja[array_index],
              ar[array_index]);
#endif
          array_index++;
      }
      _lp_set_mat_row (ats->prob, row_index, array_index, ja, ar);
      row_index ++;
    }
    GNUNET_free_non_null (ja);
    GNUNET_free_non_null (ar);
}

#if 0
static void ats_update_problem_qm_TEST ()
{
    int row_index;
    int c
    int c2;
    int c_old;
    int changed = 0;

    int old_ja[ats->stat.c_mechs + 2];
    double old_ar[ats->stat.c_mechs + 2];

    int *ja    = GNUNET_malloc ((1 + ats->stat.c_mechs*2 + 3 +
        available_quality_metrics) * sizeof (int));
    double *ar = GNUNET_malloc ((1 + ats->stat.c_mechs*2 + 3 +
        available_quality_metrics) * sizeof (double));
#if DEBUG_ATS
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "Updating problem quality metrics TEST\n");
#endif
    if (ats->stat.begin_qm >0)
        row_index = ats->stat.begin_qm;
    else
        return;
    for (c=0; c<available_quality_metrics; c++)
    {
      c_old = _lp_get_mat_row (ats->prob, row_index, old_ja, old_ar);
      _lp_set_row_bnds(ats->prob, row_index, GLP_FX, 0.0, 0.0);
      for (c2=1; c2<=c_old; c2++)
      {
        ja[c2] = old_ja[c2];
        if ((changed < 3) && (c2>2) && (old_ar[c2] != -1))
        {
          ar[c2] = old_ar[c2] + 5 - changed;
          changed ++;
        }
        else
          ar[c2] = old_ar[c2];
#if VERBOSE_ATS
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            "[index]=[%i]: old [%i,%i]=%f  new [%i,%i]=%f\n",
            c2,
            row_index,
            old_ja[c2],
            old_ar[c2],
            row_index,
            ja[c2],
            ar[c2]);
#endif
       }
     _lp_set_mat_row (ats->prob, row_index, c_old, ja, ar);
     row_index ++;
    }
    GNUNET_free_non_null (ja);
    GNUNET_free_non_null (ar);
}
#endif



/* end of transport_ats.c */


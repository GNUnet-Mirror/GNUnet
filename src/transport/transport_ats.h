#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_statistics_service.h"


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

enum ATS_problem_state
{
  /**
   * Problem is new / unmodified
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
   * Problem is modified and needs to be completely recalculated
   * due to e.g. connecting or disconnecting peers
   */
  ATS_UNMODIFIED = 8
};

/*
*  ATS data structures
*/

struct ATS_stat
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

    /**
     * Time of last execution
     */
    struct GNUNET_TIME_Absolute last;
    /**
     * Minimum intervall between two executions
     */
    struct GNUNET_TIME_Relative min_delta;
    /**
     * Regular intervall when execution is triggered
     */
    struct GNUNET_TIME_Relative exec_interval;
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
    void * prob;
#endif

    /**
     * Current state of the GLPK problem
     */
    struct ATS_stat stat;

    /**
     * mechanisms used in current problem
     * needed for problem modification
     */
    struct ATS_mechanism * mechanisms;

    /**
     * peers used in current problem
     * needed for problem modification
     */
    struct ATS_peer * peers;

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
};

struct ATS_mechanism
{
    struct ATS_mechanism * prev;
    struct ATS_mechanism * next;
    struct ForeignAddressList * addr;
    struct TransportPlugin * plugin;
    struct ATS_peer * peer;
    int col_index;
    int     id;
    struct ATS_ressource_cost * rc;
};

struct ATS_peer
{
    int id;
    struct GNUNET_PeerIdentity peer;
    struct NeighbourList * n;
    struct ATS_mechanism * m_head;
    struct ATS_mechanism * m_tail;

    /* preference value f */
    double f;
    int     t;
};

struct ATS_ressource
{
    /* index in ressources array */
    int index;
    /* depending ATSi parameter to calculcate limits */
    int atis_index;
    /* cfg option to load limits */
    char * cfg_param;
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
    char * name;
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

#define available_ressources 3

static struct ATS_ressource ressources[] =
{
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

/*
 * ATS quality metrics
 */

static struct ATS_quality_metric qm[] =
{
  {1, 1028, "QUALITY_NET_DISTANCE"},
  {2, 1034, "QUALITY_NET_DELAY"},
};

#define available_quality_metrics 2

/*
 * ATS functions
 */
struct ATS_Handle *
ats_init (const struct GNUNET_CONFIGURATION_Handle *cfg);

void
ats_shutdown (struct ATS_Handle * ats);

void
ats_delete_problem (struct ATS_Handle * ats);

int
ats_create_problem (struct ATS_Handle * ats,
                    struct NeighbourList *n,
                    double D,
                    double U,
                    double R,
                    int v_b_min,
                    int v_n_min,
                    struct ATS_stat *stat);

void ats_modify_problem_state (struct ATS_Handle * ats,
    enum ATS_problem_state s);

void
ats_calculate_bandwidth_distribution (struct ATS_Handle * ats,
    struct GNUNET_STATISTICS_Handle *stats,
    struct NeighbourList *neighbours);

void
ats_solve_problem (struct ATS_Handle * ats,
    unsigned int max_it,
    unsigned int  max_dur,
    unsigned int c_peers,
    unsigned int  c_mechs,
    struct ATS_stat *stat);

int
ats_evaluate_results (int result,
    int solution,
    char * problem);

void
ats_update_problem_qm (struct ATS_Handle * ats);

void
ats_update_problem_cr (struct ATS_Handle * ats);



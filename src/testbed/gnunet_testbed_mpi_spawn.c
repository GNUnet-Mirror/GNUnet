#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_testbed_service.h"
#include <mpi.h>

/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunet-mpi-test", __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Timeout for resolving IPs
 */
#define RESOLVE_TIMEOUT                         \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Global result
 */
static int ret;

/**
 * The host list
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * Number of hosts in the host list
 */
static unsigned int nhosts;

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  struct GNUNET_OS_Process *proc;
  unsigned long code;
  enum GNUNET_OS_ProcessStatusType proc_status;
  int rank;
  unsigned int host;
  
  if (MPI_SUCCESS != MPI_Comm_rank (MPI_COMM_WORLD, &rank))
  {
    GNUNET_break (0);
    return;
  }
  if (0 != rank)
  {
    ret = GNUNET_OK;
    return;
  }
  PRINTF ("Spawning process\n");
  proc =
      GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL,
                                   NULL, args[0], args);
  if (NULL == proc)
  {
    printf ("Cannot exec\n");
    return;
  }
  do
  {
    (void) sleep (1);
    ret = GNUNET_OS_process_status (proc, &proc_status, &code);
  }
  while (GNUNET_NO == ret);
  GNUNET_assert (GNUNET_NO != ret);
  if (GNUNET_OK == ret)
  {
    if (0 != code)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Child terminated abnormally\n");
      ret = GNUNET_SYSERR;
      GNUNET_break (0);
      return;
    }
  }
  else
  {
    ret = GNUNET_SYSERR;
    GNUNET_break (0);
    return;
  }
  if (0 == (nhosts = GNUNET_TESTBED_hosts_load_from_loadleveler (config, &hosts)))
  {
    GNUNET_break (0);
    ret = GNUNET_SYSERR;
    return;
  }
  for (host = 0; host < nhosts; host++)
    GNUNET_TESTBED_host_destroy (hosts[host]);
  GNUNET_free (hosts);
  hosts = NULL;
  ret = GNUNET_OK;
}


/**
 * Execution start point
 */
int
main (int argc, char *argv[])
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  unsigned int host;
  int rres;
  
  ret = GNUNET_SYSERR;
  if (argc < 2)
  {
    printf ("Need arguments: gnunet-testbed-mpi-spawn <cmd> <cmd_args>");
    return 1;
  }
  if (MPI_SUCCESS != MPI_Init (&argc, &argv))
  {
    GNUNET_break (0);
    return 1;
  }
  rres =
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-testbed-mpi-spawn <cmd> <cmd_args>",
                          _("Spawns cmd after starting my the MPI run-time"),
                          options, &run, NULL);
  (void) MPI_Finalize ();
  if ((GNUNET_OK == rres) && (GNUNET_OK == ret))
    return 0;
  printf ("Something went wrong\n");
  return 1;
}

#include "platform.h"
#include "gnunet_util_lib.h"
#include <mpi.h>

/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                           \
  fprintf (stderr, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Global result
 */
static int ret;


/**
 * Execution start point
 */
int
main (int argc, char *argv[])
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_OS_Process *proc;
  char **argv2;
  unsigned long code;
  enum GNUNET_OS_ProcessStatusType proc_status;
  int rank;
  int chstat;
  unsigned int host;
  unsigned int cnt;
  
  ret = -1;
  if (argc < 2)
  {
    printf ("Need arguments: gnunet-testbed-mpi-spawn <cmd> <cmd_args>");
    return 1;
  }
  if (MPI_SUCCESS != MPI_Init (&argc, &argv))
  {
    GNUNET_break (0);
    return 2;
  }
  if (MPI_SUCCESS != MPI_Comm_rank (MPI_COMM_WORLD, &rank))
  {
    GNUNET_break (0);
    ret = 3;
    goto finalize;
  }
  if (0 != rank)
  {
    ret = 0;
    goto finalize;
  }
  PRINTF ("Spawning process\n");
  argv2 = GNUNET_malloc (sizeof (char *) * (argc - 1));
  for (cnt = 1; cnt < argc; cnt++)
    argv2[cnt - 1] = argv[cnt];
  proc =
      GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL,
                                   NULL, argv2[0], argv2);
  if (NULL == proc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Cannot exec\n");
    ret = 5;
    goto finalize;
  }
  do
  {
    (void) sleep (1);
    chstat = GNUNET_OS_process_status (proc, &proc_status, &code);
  }
  while (GNUNET_NO == chstat);
  if (GNUNET_OK != chstat)
  { 
    ret = 6;
    goto finalize;
  }
  if (0 != code)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Child terminated abnormally\n");
    ret = 50 + (int) code;
    goto finalize;
  }
  ret = 0;
  
 finalize:
  (void) MPI_Finalize ();
  if (0 != ret)
    LOG (GNUNET_ERROR_TYPE_ERROR, "Something went wrong. Error: %d\n", ret);
  return ret;
}

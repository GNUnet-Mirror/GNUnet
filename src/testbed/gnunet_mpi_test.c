#include "platform.h"
#include "gnunet_util_lib.h"
#include <mpi.h>

/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunet-mpi-test", __VA_ARGS__)

int
main (int argc, char *argv[])
{
  char *msg;
  char *filename;
  char **argv2;
  struct GNUNET_OS_Process *proc;
  unsigned long code;
  pid_t pid;
  enum GNUNET_OS_ProcessStatusType proc_status;
  int ntasks;
  int rank;
  int msg_size;
  int ret;
  unsigned int cnt;

  ret = GNUNET_SYSERR;
  if (argc < 2)
  {
    printf ("Need arguments: gnunet-mpi-test <cmd> <cmd_args>");
    return 1;
  }
  if (MPI_SUCCESS != MPI_Init (&argc, &argv))
  {
    GNUNET_break (0);
    return 1;
  }
  if (MPI_SUCCESS != MPI_Comm_size (MPI_COMM_WORLD, &ntasks))
  {
    GNUNET_break (0);
    goto finalize;
  }
  if (MPI_SUCCESS != MPI_Comm_rank (MPI_COMM_WORLD, &rank))
  {
    GNUNET_break (0);
    goto finalize;
  }
  pid = getpid ();
  (void) GNUNET_asprintf (&filename, "%d-%d.mpiout", (int) pid, rank);
  msg_size = GNUNET_asprintf (&msg, "My rank is: %d\n", rank);
  printf ("%s", msg);
  if (msg_size ==
      GNUNET_DISK_fn_write (filename, msg, msg_size,
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_GROUP_READ |
                            GNUNET_DISK_PERM_USER_WRITE |
                            GNUNET_DISK_PERM_GROUP_WRITE))
    ret = GNUNET_OK;
  GNUNET_free (filename);
  GNUNET_free (msg);
  if (GNUNET_OK != ret)
  {
    GNUNET_break (0);
    goto finalize;
  }

  ret = GNUNET_SYSERR;
  argv2 = GNUNET_malloc (sizeof (char *) * (argc));
  for (cnt = 1; cnt < argc; cnt++)
    argv2[cnt - 1] = argv[cnt];
  proc =
      GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL,
                                   NULL, argv2[0], argv2);
  if (NULL == proc)
  {
    printf ("Cannot exec\n");
    GNUNET_free (argv2);
    goto finalize;
  }
  do
  {
    (void) sleep (1);
    ret = GNUNET_OS_process_status (proc, &proc_status, &code);
  }
  while (GNUNET_NO == ret);
  GNUNET_free (argv2);
  GNUNET_assert (GNUNET_NO != ret);
  if (GNUNET_OK == ret)
  {
    if (0 != code)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Child terminated abnormally\n");
      ret = GNUNET_SYSERR;
      GNUNET_break (0);
      goto finalize;
    }
  }
  else
    GNUNET_break (0);

finalize:
  (void) MPI_Finalize ();
  if (GNUNET_OK == ret)
    return 0;
  printf ("Something went wrong\n");
  return 1;
}

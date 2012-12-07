#include "platform.h"
#include "gnunet_util_lib.h"
#include <mpi.h>

int main (int argc, char *argv[])
{
  char *msg;
  char *filename;
  pid_t pid;
  int ntasks;
  int rank;
  int msg_size;
  int ret;

  ret = GNUNET_SYSERR;
  if (MPI_SUCCESS != MPI_Init (&argc, &argv))
    return 1;
  if (MPI_SUCCESS != MPI_Comm_size (MPI_COMM_WORLD, &ntasks))
    goto finalize;
  if (MPI_SUCCESS != MPI_Comm_rank (MPI_COMM_WORLD, &rank))
    goto finalize;
  (void) GNUNET_asprintf (&filename, "%d.mpiout", rank);
  msg_size = GNUNET_asprintf (&msg, "My rank is: %d\n", rank);
  if (msg_size == GNUNET_DISK_fn_write (filename,
                                        msg, msg_size,
                                        GNUNET_DISK_PERM_USER_READ
                                        | GNUNET_DISK_PERM_GROUP_READ
                                        | GNUNET_DISK_PERM_USER_WRITE
                                        | GNUNET_DISK_PERM_GROUP_WRITE))
    ret = GNUNET_OK;
  GNUNET_free (filename);
  GNUNET_free (msg);
 finalize:
  (void) MPI_Finalize ();
  return (GNUNET_OK == ret) ? 0 : 1;
}

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunet-mpi-test", __VA_ARGS__)

int main (int argc, char *argv[])
{
  char *msg;
  char *filename;
  pid_t pid;
  pid_t ppid;
  int rank;
  int msg_size;
  int ret;

  ret = GNUNET_SYSERR;
  rank = 0;
  pid = getpid();
  (void) GNUNET_asprintf (&filename, "%d-%d.mpiout", (int) pid, rank);
  msg_size = GNUNET_asprintf (&msg, "My pid is: %d\n", pid);
  printf ("%s", msg);
  if (msg_size == GNUNET_DISK_fn_write (filename,
                                        msg, msg_size,
                                        GNUNET_DISK_PERM_USER_READ
                                        | GNUNET_DISK_PERM_GROUP_READ
                                        | GNUNET_DISK_PERM_USER_WRITE
                                        | GNUNET_DISK_PERM_GROUP_WRITE))
    ret = GNUNET_OK;
  GNUNET_free (filename);
  GNUNET_free (msg);
  if (GNUNET_OK != ret)
    goto finalize;

  ret = GNUNET_SYSERR;
  ppid = pid;
  pid = fork ();
  if (-1 == pid)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
    goto finalize;
  }
  if (0 == pid)
  {
    /* child code */
    pid = getpid ();
    (void) GNUNET_asprintf (&filename, "%d-%d.mpiout", (int) pid, rank);
    msg_size = GNUNET_asprintf (&msg, "Child of %d\n", (int) ppid);
    printf ("%s", msg);
    if (msg_size == GNUNET_DISK_fn_write (filename,
                                        msg, msg_size,
                                        GNUNET_DISK_PERM_USER_READ
                                        | GNUNET_DISK_PERM_GROUP_READ
                                        | GNUNET_DISK_PERM_USER_WRITE
                                        | GNUNET_DISK_PERM_GROUP_WRITE))
    ret = GNUNET_OK;
    GNUNET_free (filename);
    GNUNET_free (msg);
    return (GNUNET_OK == ret) ? 0 : 1;
  }
  else {
    int status;
    int childpid;

    childpid = waitpid (pid, &status, 0);
    if (childpid != pid)
    {
      GNUNET_break (0);
      goto finalize;
    }
    if (!WIFEXITED (status))
    {
      GNUNET_break (0);
      goto finalize;
    }
    if (0 != WEXITSTATUS (status))
    {
      GNUNET_break (0);
    }
  }
  ret = GNUNET_OK;

 finalize:
  return (GNUNET_OK == ret) ? 0 : 1;
}

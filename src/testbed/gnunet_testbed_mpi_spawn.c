#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
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
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GAI(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gai_strerror(rc)); } while(0)

/**
 * Global result
 */
static int ret;

/**
 * The array of hostnames
 */
static char **hostnames;

/**
 * The array of host's addresses
 */
static char **hostaddrs;

/**
 * The resolution request handles; one per each hostname resolution
 */
struct GNUNET_RESOLVER_RequestHandle **rhs;

/**
 * Number of hosts in the hostname array
 */
static unsigned int nhosts;

/**
 * Number of addresses in the hostaddr array
 */
static unsigned int nhostaddrs;

/**
 * Did we connect to the resolver service
 */
static unsigned int resolver_connected;

/**
 * Task for resolving ips
 */
static GNUNET_SCHEDULER_TaskIdentifier resolve_task_id;


/**
 * Resolves the hostnames array
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
resolve_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct addrinfo hint;
  const struct sockaddr_in *in_addr; 
  struct addrinfo *res;
  char *hostip;
  unsigned int host;
  unsigned int rc;

  resolve_task_id = GNUNET_SCHEDULER_NO_TASK;
  hint.ai_family = AF_INET;	/* IPv4 */
  hint.ai_socktype = 0;
  hint.ai_protocol = 0;
  hint.ai_addrlen = 0;
  hint.ai_addr = NULL;
  hint.ai_canonname = NULL;
  hint.ai_next = NULL;
  hint.ai_flags = AI_NUMERICSERV;
  for (host = 0; host < nhosts; host++)
  {
    res = NULL;
    LOG_DEBUG ("Resolving: %s host\n", hostnames[host]);
    if (0 != (rc = getaddrinfo (hostnames[host], "22", &hint, &res)))
    {
      LOG_GAI (GNUNET_ERROR_TYPE_ERROR, "getaddrinfo", rc);
      ret = GNUNET_SYSERR;
      return;
    }
    GNUNET_assert (NULL != res);
    GNUNET_assert (NULL != res->ai_addr);
    GNUNET_assert (sizeof (struct sockaddr_in) == res->ai_addrlen);
    in_addr = (const struct sockaddr_in *) res->ai_addr;
    hostip = inet_ntoa (in_addr->sin_addr);
    GNUNET_assert (NULL != hostip);
    GNUNET_array_append (hostaddrs, nhostaddrs, GNUNET_strdup (hostip));
    LOG_DEBUG ("%s --> %s\n", hostnames[host], hostaddrs[host]);
    freeaddrinfo (res);
  }
  ret = GNUNET_OK;
}


/**
 * Loads the set of host allocated by the LoadLeveler Job Scheduler.  This
 * function is only available when compiled with support for LoadLeveler and is
 * used for running on the SuperMUC
 *
 * @param hostlist set to the hosts found in the file; caller must free this if
 *          number of hosts returned is greater than 0
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
get_loadleveler_hosts ()
{
  const char *hostfile;
  char *buf;
  char *hostname;
  struct addrinfo *ret;
  struct addrinfo hint;
  ssize_t rsize;
  uint64_t size;
  uint64_t offset;
  enum {
    SCAN,
    SKIP,
    TRIM,
    READHOST
  } pstep;
  unsigned int host;

  if (NULL == (hostfile = getenv ("MP_SAVEHOSTFILE")))
  {
    GNUNET_break (0);
    return 0;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_file_size (hostfile, &size, GNUNET_YES,
                                              GNUNET_YES))
  {
    GNUNET_break (0);
    return 0;
  }
  if (0 == size)
  {
    GNUNET_break (0);
    return 0;
  }
  buf = GNUNET_malloc (size + 1);
  rsize = GNUNET_DISK_fn_read (hostfile, buf, (size_t) size);
  if ( (GNUNET_SYSERR == rsize) || ((ssize_t) size != rsize) )
  {
    GNUNET_free (buf);
    GNUNET_break (0);
    return 0;
  }
  size++;
  offset = 0;
  pstep = SCAN;
  hostname = NULL;
  while (offset < size)
  {
    switch (pstep)
    {
    case SCAN:
      if ('!' == buf[offset])
        pstep = SKIP;
      else 
        pstep = TRIM;
      break;
    case SKIP:
      if ('\n' == buf[offset])
        pstep = SCAN;
      break;
    case TRIM:
      if ('!' == buf[offset])
      {
        pstep = SKIP;
        break;
      }
      if ( (' ' == buf[offset]) 
           || ('\t' == buf[offset])
           || ('\r' == buf[offset]) )
        pstep = TRIM;
      else
      {
        pstep = READHOST;
        hostname = &buf[offset];        
      }
      break;
    case READHOST:
      if (isspace (buf[offset]))
      {
        buf[offset] = '\0';
        for (host = 0; host < nhosts; host++)
          if (0 == strcmp (hostnames[host], hostname))
            break;
        if (host == nhosts)
        {
          LOG_DEBUG ("Adding host: %s\n", hostname);
          hostname = GNUNET_strdup (hostname);
          GNUNET_array_append (hostnames, nhosts, hostname);
        }
        else
          LOG_DEBUG ("Not adding host %s as it is already included\n", hostname);
        hostname = NULL;
        pstep = SCAN;
      }
      break;
    }
    offset++;
  }
  GNUNET_free_non_null (buf);
  return nhosts;
}


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
  int msg_size;
  
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
  if (0 == get_loadleveler_hosts())
  {
    GNUNET_break (0);
    ret = GNUNET_SYSERR;
    return;
  }
  resolve_task_id = GNUNET_SCHEDULER_add_now (&resolve_task, NULL);
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
  for (host = 0; host < nhosts; host++)
    GNUNET_free (hostnames[host]);
  for (host = 0; host < nhostaddrs; host++)
    GNUNET_free (hostaddrs[host]);
  GNUNET_free_non_null (hostnames);
  GNUNET_free_non_null (hostaddrs);
  if ((GNUNET_OK == rres) && (GNUNET_OK == ret))
    return 0;
  printf ("Something went wrong\n");
  return 1;
}

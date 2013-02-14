/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2011 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/os_priority.c
 * @brief Methods to set process priority
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_os_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_crypto_lib.h"
#include "disk.h"
#include <unistr.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

#define GNUNET_OS_CONTROL_PIPE "GNUNET_OS_CONTROL_PIPE"


struct GNUNET_OS_Process
{
  /**
   * PID of the process.
   */
  pid_t pid;

#if WINDOWS
  /**
   * Process handle.
   */
  HANDLE handle;
#endif

  /**
   * Pipe we use to signal the process (if used).
   */
  struct GNUNET_DISK_FileHandle *control_pipe;

  /**
   * Name of the pipe, NULL for none.
   */
  char *childpipename;
};


/**
 * Handle for 'this' process.
 */
static struct GNUNET_OS_Process current_process;


/* MinGW version of named pipe API */
#ifdef MINGW
/**
 * Creates a named pipe/FIFO and opens it
 *
 * @param fn pointer to the name of the named pipe or to NULL,
 *           possibly updated to the new name (or free'd)
 * @param flags open flags
 * @param perm access permissions
 * @return pipe handle on success, NULL on error
 */
static struct GNUNET_DISK_FileHandle *
npipe_create (char **fn, enum GNUNET_DISK_OpenFlags flags,
	      enum GNUNET_DISK_AccessPermissions perm)
{
  struct GNUNET_DISK_FileHandle *ret;
  HANDLE h = NULL;
  DWORD openMode;
  char *name;

  openMode = 0;
  if (flags & GNUNET_DISK_OPEN_READWRITE)
    openMode = PIPE_ACCESS_DUPLEX;
  else if (flags & GNUNET_DISK_OPEN_READ)
    openMode = PIPE_ACCESS_INBOUND;
  else if (flags & GNUNET_DISK_OPEN_WRITE)
    openMode = PIPE_ACCESS_OUTBOUND;
  if (flags & GNUNET_DISK_OPEN_FAILIFEXISTS)
    openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

  while (NULL == h)
  {
    DWORD error_code;

    name = NULL;
    if (NULL != *fn)
    {
      GNUNET_asprintf (&name, "\\\\.\\pipe\\%.246s", fn);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Trying to create an instance of named pipe `%s'\n", name);
      /* 1) This might work just fine with UTF-8 strings as it is.
       * 2) This is only used by GNUnet itself, and only with latin names.
       */
      h = CreateNamedPipe (name, openMode | FILE_FLAG_OVERLAPPED,
                           PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 2, 1, 1, 0,
                           NULL);
    }
    else
    {
      GNUNET_asprintf (fn, "\\\\.\\pipe\\gnunet-%llu",
                       GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                 UINT64_MAX));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Trying to create unique named pipe `%s'\n",
           *fn);
      h = CreateNamedPipe (*fn,
                           openMode | FILE_FLAG_OVERLAPPED |
                           FILE_FLAG_FIRST_PIPE_INSTANCE,
                           PIPE_TYPE_BYTE | PIPE_READMODE_BYTE, 2, 1, 1, 0,
                           NULL);
    }
    error_code = GetLastError ();
    GNUNET_free_non_null (name);
    /* don't re-set name to NULL yet */
    if (INVALID_HANDLE_VALUE == h)
    {
      SetErrnoFromWinError (error_code);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Pipe creation have failed because of %d, errno is %d\n", error_code,
           errno);
      if (NULL != *fn)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Pipe was to be unique, considering re-creation\n");
        GNUNET_free (*fn);
        *fn = NULL;
        if ( (ERROR_ACCESS_DENIED != error_code) && (ERROR_PIPE_BUSY != error_code) )        
          return NULL;        
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Pipe name was not unique, trying again\n");
        h = NULL;
      }
      else
        return NULL;
    }
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_DISK_FileHandle));
  ret->h = h;
  ret->type = GNUNET_DISK_HANLDE_TYPE_PIPE;
  ret->oOverlapRead = GNUNET_malloc (sizeof (OVERLAPPED));
  ret->oOverlapWrite = GNUNET_malloc (sizeof (OVERLAPPED));
  ret->oOverlapRead->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  ret->oOverlapWrite->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  return ret;
}


/**
 * Opens already existing named pipe/FIFO
 *
 * @param fn name of an existing named pipe
 * @param flags open flags
 * @return pipe handle on success, NULL on error
 */
static struct GNUNET_DISK_FileHandle *
npipe_open (const char *fn, enum GNUNET_DISK_OpenFlags flags)
{
  struct GNUNET_DISK_FileHandle *ret;
  HANDLE h;
  DWORD openMode;

  openMode = 0;
  if (flags & GNUNET_DISK_OPEN_READWRITE)
    openMode = GENERIC_WRITE | GENERIC_READ;
  else if (flags & GNUNET_DISK_OPEN_READ)
    openMode = GENERIC_READ;
  else if (flags & GNUNET_DISK_OPEN_WRITE)
    openMode = GENERIC_WRITE;

  h = CreateFile (fn, openMode, 0, NULL, OPEN_EXISTING,
                  FILE_FLAG_OVERLAPPED | FILE_READ_ATTRIBUTES, NULL);
  if (INVALID_HANDLE_VALUE == h)
  {
    SetErrnoFromWinError (GetLastError ());
    return NULL;
  }

  ret = GNUNET_malloc (sizeof (struct GNUNET_DISK_FileHandle));
  ret->h = h;
  ret->type = GNUNET_DISK_HANLDE_TYPE_PIPE;
  ret->oOverlapRead = GNUNET_malloc (sizeof (OVERLAPPED));
  ret->oOverlapWrite = GNUNET_malloc (sizeof (OVERLAPPED));
  ret->oOverlapRead->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  ret->oOverlapWrite->hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);

  return ret;
}

#else
/* UNIX version of named-pipe API */

/**
 * Clean up a named pipe and the directory it was placed in.
 *
 * @param fn name of the pipe
 */
static void
cleanup_npipe (const char *fn)
{
  char *dn;
  char *dp;

  if (0 != unlink (fn))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
  dn = GNUNET_strdup (fn);
  dp = dirname (dn);
  if (0 != rmdir (dp))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "rmdir", dp);
  GNUNET_free (dn);  
}


/**
 * Setup a named pipe.
 *
 * @param fn where to store the name of the new pipe,
 *           if *fn is non-null, the name of the pipe to setup
 * @return GNUNET_OK on success
 */
static int
npipe_setup (char **fn)
{
  if (NULL == *fn)
  {
    /* FIXME: hardwired '/tmp' path... is bad */
    char dir[] = "/tmp/gnunet-pipe-XXXXXX"; 

    if (NULL == mkdtemp (dir))
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "mkdtemp");
      return GNUNET_SYSERR;
    }
    GNUNET_asprintf (fn, "%s/child-control", dir);
  }
  if (-1 == mkfifo (*fn, S_IRUSR | S_IWUSR))
    return GNUNET_SYSERR;  
  return GNUNET_OK;
}


/**
 * Open an existing named pipe.
 *
 * @param fn name of the file
 * @param flags flags to use
 * @return NULL on error
 */
static struct GNUNET_DISK_FileHandle *
npipe_open (const char *fn,
	    enum GNUNET_DISK_OpenFlags flags)
{
  struct GNUNET_DISK_FileHandle *ret;
  int fd;
  struct timespec req;
  int i;

  /* 200 * 5ms = 1s at most */
  for (i=0;i<200;i++) 
  {
    fd = open (fn, O_NONBLOCK | ((flags == GNUNET_DISK_OPEN_READ) ? O_RDONLY : O_WRONLY));
    if ( (-1 != fd) || (9 == i) || (flags == GNUNET_DISK_OPEN_READ)) 
      break;
    /* as this is for killing a child process via pipe and it is conceivable that
       the child process simply didn't finish starting yet, we do some sleeping
       (which is obviously usually not allowed).  We can't select on the FD as
       'open' fails, and we probably shouldn't just "ignore" the error, so wait
       and retry a few times is likely the best method; our process API doesn't 
       support continuations, so we need to sleep directly... */
    req.tv_sec = 0;
    req.tv_nsec = 5000000; /* 5ms */
    (void) nanosleep (&req, NULL);
  } 
  if (-1 == fd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		(flags == GNUNET_DISK_OPEN_READ) 
		? _("Failed to open named pipe `%s' for reading: %s\n")
		: _("Failed to open named pipe `%s' for writing: %s\n"),
		fn,
		STRERROR (errno));
    return NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_DISK_FileHandle));
  ret->fd = fd;
  return ret;
}
#endif


/**
 * This handler is called when there are control data to be read on the pipe
 *
 * @param cls the 'struct GNUNET_DISK_FileHandle' of the control pipe
 * @param tc scheduler context
 */
static void
parent_control_handler (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;
  char *pipe_name;
  char sig;
  ssize_t ret;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "`%s' invoked because of %d\n", __FUNCTION__,
       tc->reason);
  if (0 != (tc->reason &
	    (GNUNET_SCHEDULER_REASON_SHUTDOWN | GNUNET_SCHEDULER_REASON_TIMEOUT)))
  {
    GNUNET_DISK_file_close (control_pipe);
    control_pipe = NULL;
    return;
  }
  ret = GNUNET_DISK_file_read (control_pipe, &sig, sizeof (sig));
  if (sizeof (sig) != ret)
  {
    if (-1 == ret)
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "GNUNET_DISK_file_read");
    LOG (GNUNET_ERROR_TYPE_WARNING, "Closing control pipe\n");
    GNUNET_DISK_file_close (control_pipe);
    control_pipe = NULL;
    return;
  }
  pipe_name = getenv (GNUNET_OS_CONTROL_PIPE);
  GNUNET_assert ( (NULL == pipe_name) || (strlen (pipe_name) <= 0) );
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got control code %d from parent via pipe %s\n", sig, pipe_name);
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				  control_pipe, &parent_control_handler,
				  control_pipe);
  raise ((int) sig);
}


/**
 * Task that connects this process to its parent via pipe;
 * essentially, the parent control handler will read signal numbers
 * from the 'GNUNET_OS_CONTROL_PIPE' (as given in an environment
 * variable) and raise those signals.
 *
 * @param cls closure (unused)
 * @param tc scheduler context (unused)
 */
void
GNUNET_OS_install_parent_control_handler (void *cls,
                                          const struct
                                          GNUNET_SCHEDULER_TaskContext *tc)
{
  const char *env_buf;
  struct GNUNET_DISK_FileHandle *control_pipe;

  env_buf = getenv (GNUNET_OS_CONTROL_PIPE);
  if ( (NULL == env_buf) || (strlen (env_buf) <= 0) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Not installing a handler because $%s is empty\n",
         GNUNET_OS_CONTROL_PIPE);
    putenv ("GNUNET_OS_CONTROL_PIPE=");
    return;
  }
  control_pipe =
    npipe_open (env_buf, GNUNET_DISK_OPEN_READ);
  if (NULL == control_pipe)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", env_buf);
    putenv ("GNUNET_OS_CONTROL_PIPE=");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding parent control handler pipe `%s' to the scheduler\n", env_buf);
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, control_pipe,
                                  &parent_control_handler, control_pipe);
  putenv ("GNUNET_OS_CONTROL_PIPE=");
}


/**
 * Get process structure for current process
 *
 * The pointer it returns points to static memory location and must not be
 * deallocated/closed
 *
 * @return pointer to the process sturcutre for this process
 */
struct GNUNET_OS_Process *
GNUNET_OS_process_current ()
{
#if WINDOWS
  current_process.pid = GetCurrentProcessId ();
  current_process.handle = GetCurrentProcess ();
#else
  current_process.pid = 0;
#endif
  return &current_process;
}


/**
 * Sends a signal to the process
 *
 * @param proc pointer to process structure
 * @param sig signal
 * @return 0 on success, -1 on error
 */
int
GNUNET_OS_process_kill (struct GNUNET_OS_Process *proc, int sig)
{
  int ret;
  char csig;

  csig = (char) sig;
#if !WINDOWS
  if ( (NULL == proc->control_pipe) &&
       (NULL != proc->childpipename) )
    proc->control_pipe = npipe_open (proc->childpipename,
				     GNUNET_DISK_OPEN_WRITE);
#endif
  if (NULL != proc->control_pipe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending signal %d to pid: %u via pipe\n", sig, proc->pid);
    ret = GNUNET_DISK_file_write (proc->control_pipe, &csig, sizeof (csig));
    if (sizeof (csig) == ret)
      return 0;
  }
  /* pipe failed or non-existent, try other methods */
  switch (sig)
  {
#if !WINDOWS
  case SIGHUP:
#endif
  case SIGINT:
  case SIGKILL:
  case SIGTERM:
#if WINDOWS && !defined(__CYGWIN__)
    {
      DWORD exitcode;
      int must_kill = GNUNET_YES;
      if (0 != GetExitCodeProcess (proc->handle, &exitcode))
        must_kill = (exitcode == STILL_ACTIVE) ? GNUNET_YES : GNUNET_NO;
      if (GNUNET_YES == must_kill)
        if (0 == SafeTerminateProcess (proc->handle, 0, 0))
        {
          DWORD error_code = GetLastError ();
          if ((error_code != WAIT_TIMEOUT) && (error_code != ERROR_PROCESS_ABORTED))
          {
            LOG ((error_code == ERROR_ACCESS_DENIED) ?
                GNUNET_ERROR_TYPE_INFO : GNUNET_ERROR_TYPE_WARNING,
                "SafeTermiateProcess failed with code %lu\n", error_code);
            /* The problem here is that a process that is already dying
             * might cause SafeTerminateProcess to fail with
             * ERROR_ACCESS_DENIED, but the process WILL die eventually.
             * If we really had a permissions problem, hanging up (which
             * is what will happen in process_wait() in that case) is
             * a valid option.
             */
            if (ERROR_ACCESS_DENIED == error_code)
            {
              errno = 0;
            }
            else
            {
              SetErrnoFromWinError (error_code);
              return -1;
            }
          }
        }
    }
    return 0;
#else
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending signal %d to pid: %u via system call\n", sig, proc->pid);
    return PLIBC_KILL (proc->pid, sig);
#endif
  default:
#if WINDOWS
    errno = EINVAL;
    return -1;
#else
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending signal %d to pid: %u via system call\n", sig, proc->pid);
    return PLIBC_KILL (proc->pid, sig);
#endif    
  }
}

/**
 * Get the pid of the process in question
 *
 * @param proc the process to get the pid of
 *
 * @return the current process id
 */
pid_t
GNUNET_OS_process_get_pid (struct GNUNET_OS_Process * proc)
{
  return proc->pid;
}


/**
 * Cleans up process structure contents (OS-dependent) and deallocates it
 *
 * @param proc pointer to process structure
 */
void
GNUNET_OS_process_destroy (struct GNUNET_OS_Process *proc)
{
  if (NULL != proc->control_pipe)
    GNUNET_DISK_file_close (proc->control_pipe);
// FIXME NILS
#ifdef WINDOWS
  if (proc->handle != NULL)
    CloseHandle (proc->handle);
#endif
  if (NULL != proc->childpipename)
  {
#if !WINDOWS
    cleanup_npipe (proc->childpipename);
#endif
    GNUNET_free (proc->childpipename);
  }
  GNUNET_free (proc);
}

// FIXME NILS
#if WINDOWS
#include "gnunet_signal_lib.h"

extern GNUNET_SIGNAL_Handler w32_sigchld_handler;

/**
 * Make seaspider happy.
 */
#define DWORD_WINAPI DWORD WINAPI

/**
 * @brief Waits for a process to terminate and invokes the SIGCHLD handler
 * @param proc pointer to process structure
 */
static DWORD_WINAPI
child_wait_thread (void *arg)
{
  struct GNUNET_OS_Process *proc = (struct GNUNET_OS_Process *) arg;

  WaitForSingleObject (proc->handle, INFINITE);

  if (w32_sigchld_handler)
    w32_sigchld_handler ();

  return 0;
}
#endif


/**
 * Set process priority
 *
 * @param proc pointer to process structure
 * @param prio priority value
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_OS_set_process_priority (struct GNUNET_OS_Process *proc,
                                enum GNUNET_SCHEDULER_Priority prio)
{
  int rprio;

  GNUNET_assert (prio < GNUNET_SCHEDULER_PRIORITY_COUNT);
  if (GNUNET_SCHEDULER_PRIORITY_KEEP == prio)
    return GNUNET_OK;

  /* convert to MINGW/Unix values */
  switch (prio)
  {
  case GNUNET_SCHEDULER_PRIORITY_UI:
  case GNUNET_SCHEDULER_PRIORITY_URGENT:
#ifdef MINGW
    rprio = HIGH_PRIORITY_CLASS;
#else
    rprio = 0;
#endif
    break;

  case GNUNET_SCHEDULER_PRIORITY_HIGH:
#ifdef MINGW
    rprio = ABOVE_NORMAL_PRIORITY_CLASS;
#else
    rprio = 5;
#endif
    break;

  case GNUNET_SCHEDULER_PRIORITY_DEFAULT:
#ifdef MINGW
    rprio = NORMAL_PRIORITY_CLASS;
#else
    rprio = 7;
#endif
    break;

  case GNUNET_SCHEDULER_PRIORITY_BACKGROUND:
#ifdef MINGW
    rprio = BELOW_NORMAL_PRIORITY_CLASS;
#else
    rprio = 10;
#endif
    break;

  case GNUNET_SCHEDULER_PRIORITY_IDLE:
#ifdef MINGW
    rprio = IDLE_PRIORITY_CLASS;
#else
    rprio = 19;
#endif
    break;
  default:
    GNUNET_assert (0);
    return GNUNET_SYSERR;
  }

  /* Set process priority */
#ifdef MINGW
  {
    HANDLE h = proc->handle;

    GNUNET_assert (h != NULL);
    SetPriorityClass (h, rprio);
  }
#elif LINUX
  pid_t pid;

  pid = proc->pid;
  if ((0 == pid) || (pid == getpid ()))
  {
    int have = nice (0);
    int delta = rprio - have;

    errno = 0;
    if ((delta != 0) && (rprio == nice (delta)) && (errno != 0))
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK, "nice");
      return GNUNET_SYSERR;
    }
  }
  else
  {
    if (0 != setpriority (PRIO_PROCESS, pid, rprio))
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                    "setpriority");
      return GNUNET_SYSERR;
    }
  }
#else
  LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
       "Priority management not availabe for this platform\n");
#endif
  return GNUNET_OK;
}


#if MINGW
static char *
CreateCustomEnvTable (char **vars)
{
  char *win32_env_table;
  char *ptr;
  char **var_ptr;
  char *result;
  char *result_ptr;
  size_t tablesize = 0;
  size_t items_count = 0;
  size_t n_found = 0;
  size_t n_var;
  char *index = NULL;
  size_t c;
  size_t var_len;
  char *var;
  char *val;

  win32_env_table = GetEnvironmentStringsA ();
  if (NULL == win32_env_table)
    return NULL;
  for (c = 0, var_ptr = vars; *var_ptr; var_ptr += 2, c++) ;
  n_var = c;
  index = GNUNET_malloc (sizeof (char *) * n_var);
  for (c = 0; c < n_var; c++)
    index[c] = 0;
  for (items_count = 0, ptr = win32_env_table; ptr[0] != 0; items_count++)
  {
    size_t len = strlen (ptr);
    int found = 0;

    for (var_ptr = vars; *var_ptr; var_ptr++)
    {
      var = *var_ptr++;
      val = *var_ptr;
      var_len = strlen (var);
      if (strncmp (var, ptr, var_len) == 0)
      {
        found = 1;
        index[c] = 1;
        tablesize += var_len + strlen (val) + 1;
        break;
      }
    }
    if (!found)
      tablesize += len + 1;
    ptr += len + 1;
  }
  for (n_found = 0, c = 0, var_ptr = vars; *var_ptr; var_ptr++, c++)
  {
    var = *var_ptr++;
    val = *var_ptr;
    if (index[c] != 1)
      n_found += strlen (var) + strlen (val) + 1;
  }
  result = GNUNET_malloc (tablesize + n_found + 1);
  for (result_ptr = result, ptr = win32_env_table; ptr[0] != 0;)
  {
    size_t len = strlen (ptr);
    int found = 0;

    for (c = 0, var_ptr = vars; *var_ptr; var_ptr++, c++)
    {
      var = *var_ptr++;
      val = *var_ptr;
      var_len = strlen (var);
      if (strncmp (var, ptr, var_len) == 0)
      {
        found = 1;
        break;
      }
    }
    if (!found)
    {
      strcpy (result_ptr, ptr);
      result_ptr += len + 1;
    }
    else
    {
      strcpy (result_ptr, var);
      result_ptr += var_len;
      strcpy (result_ptr, val);
      result_ptr += strlen (val) + 1;
    }
    ptr += len + 1;
  }
  for (c = 0, var_ptr = vars; *var_ptr; var_ptr++, c++)
  {
    var = *var_ptr++;
    val = *var_ptr;
    var_len = strlen (var);
    if (index[c] != 1)
    {
      strcpy (result_ptr, var);
      result_ptr += var_len;
      strcpy (result_ptr, val);
      result_ptr += strlen (val) + 1;
    }
  }
  FreeEnvironmentStrings (win32_env_table);
  GNUNET_free (index);
  *result_ptr = 0;
  return result;
}

#else

/**
 * Open '/dev/null' and make the result the given
 * file descriptor.
 *
 * @param target_fd desired FD to point to /dev/null
 * @param flags open flags (O_RDONLY, O_WRONLY)
 */
static void
open_dev_null (int target_fd,
	       int flags)
{
  int fd;

  fd = open ("/dev/null", flags);
  if (-1 == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", "/dev/null");
    return;
  }
  if (fd == target_fd)
    return;
  if (-1 == dup2 (fd, target_fd))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "dup2");
    (void) close (fd);
    return;
  }
  GNUNET_break (0 == close (fd));
}
#endif


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags controlling which
 *        std handles of the parent are inherited by the child.
 *        pipe_stdin and pipe_stdout take priority over std_inheritance
 *        (when they are non-NULL).
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process
 * @return process ID of the new process, -1 on error
 */
static struct GNUNET_OS_Process *
start_process (int pipe_control,
               enum GNUNET_OS_InheritStdioFlags std_inheritance,
	       struct GNUNET_DISK_PipeHandle *pipe_stdin,
	       struct GNUNET_DISK_PipeHandle *pipe_stdout,
	       const SOCKTYPE *lsocks,
	       const char *filename,
	       char *const argv[])
{
#ifndef MINGW
  pid_t ret;
  char lpid[16];
  char fds[16];
  struct GNUNET_OS_Process *gnunet_proc;
  char *childpipename = NULL;
  int i;
  int j;
  int k;
  int tgt;
  int flags;
  int *lscp;
  unsigned int ls;
  int fd_stdout_write;
  int fd_stdout_read;
  int fd_stdin_read;
  int fd_stdin_write;

  if (GNUNET_SYSERR == GNUNET_OS_check_helper_binary (filename))
    return NULL; /* not executable */
  if ( (GNUNET_YES == pipe_control) &&
       (GNUNET_OK != npipe_setup (&childpipename)) )
  {
    GNUNET_free (childpipename);
    return NULL;
  }
  if (NULL != pipe_stdout)
  {
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
						      (pipe_stdout,
						       GNUNET_DISK_PIPE_END_WRITE),
						      &fd_stdout_write, sizeof (int)));
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
						      (pipe_stdout, GNUNET_DISK_PIPE_END_READ),
						      &fd_stdout_read, sizeof (int)));
  }
  if (NULL != pipe_stdin)
  {
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
						      (pipe_stdin, GNUNET_DISK_PIPE_END_READ),
						      &fd_stdin_read, sizeof (int)));
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
						      (pipe_stdin, GNUNET_DISK_PIPE_END_WRITE),
						      &fd_stdin_write, sizeof (int)));
  }
  lscp = NULL;
  ls = 0;
  if (NULL != lsocks)
  {
    i = 0;
    while (-1 != (k = lsocks[i++]))
      GNUNET_array_append (lscp, ls, k);
    GNUNET_array_append (lscp, ls, -1);
  }
#if DARWIN
  /* see https://gnunet.org/vfork */
  ret = vfork ();
#else
  ret = fork ();
#endif
  if (-1 == ret)
  {
    int eno = errno;

    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fork");
    GNUNET_free_non_null (childpipename);
    GNUNET_array_grow (lscp, ls, 0);
    errno = eno;
    return NULL;
  }
  if (0 != ret)
  {
    gnunet_proc = GNUNET_malloc (sizeof (struct GNUNET_OS_Process));
    gnunet_proc->pid = ret;
    gnunet_proc->childpipename = childpipename;  
    GNUNET_array_grow (lscp, ls, 0);
    return gnunet_proc;
  }
  if (NULL != childpipename)
  {
    setenv (GNUNET_OS_CONTROL_PIPE, childpipename, 1);
#ifndef DARWIN
    /* due to vfork, we must NOT free memory on DARWIN! */
    GNUNET_free (childpipename);
#endif
  }
  if (NULL != pipe_stdin)
  {
    GNUNET_break (0 == close (fd_stdin_write));
    if (-1 == dup2 (fd_stdin_read, 0))
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "dup2");
    GNUNET_break (0 == close (fd_stdin_read));
  }
  else if (0 == (std_inheritance & GNUNET_OS_INHERIT_STD_IN))
  {
    GNUNET_break (0 == close (0));
    open_dev_null (0, O_RDONLY);
  }
  if (NULL != pipe_stdout)
  {
    GNUNET_break (0 == close (fd_stdout_read));
    if (-1 == dup2 (fd_stdout_write, 1))
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "dup2");
    GNUNET_break (0 == close (fd_stdout_write));
  }
  else if (0 == (std_inheritance & GNUNET_OS_INHERIT_STD_OUT))
  {
    GNUNET_break (0 == close (1));
    open_dev_null (1, O_WRONLY);
  }
  if (0 == (std_inheritance & GNUNET_OS_INHERIT_STD_ERR))
  {
    GNUNET_break (0 == close (2));
    open_dev_null (2, O_WRONLY);
  }
  if (NULL != lscp)
  {
    /* read systemd documentation... */
    GNUNET_snprintf (lpid, sizeof (lpid), "%u", getpid ());
    setenv ("LISTEN_PID", lpid, 1);
    i = 0;
    tgt = 3;
    while (-1 != lscp[i])
    {
      j = i + 1;
      while (-1 != lscp[j])
      {
        if (lscp[j] == tgt)
        {
          /* dup away */
          k = dup (lscp[j]);
          GNUNET_assert (-1 != k);
          GNUNET_assert (0 == close (lscp[j]));
          lscp[j] = k;
          break;
        }
        j++;
      }
      if (lscp[i] != tgt)
      {
        /* Bury any existing FD, no matter what; they should all be closed
         * on exec anyway and the important onces have been dup'ed away */
        (void) close (tgt);
        GNUNET_assert (-1 != dup2 (lscp[i], tgt));
      }
      /* unset close-on-exec flag */
      flags = fcntl (tgt, F_GETFD);
      GNUNET_assert (flags >= 0);
      flags &= ~FD_CLOEXEC;
      fflush (stderr);
      (void) fcntl (tgt, F_SETFD, flags);
      tgt++;
      i++;
    }
    GNUNET_snprintf (fds, sizeof (fds), "%u", i);
    setenv ("LISTEN_FDS", fds, 1);
  }
#ifndef DARWIN
  /* due to vfork, we must NOT free memory on DARWIN! */
  GNUNET_array_grow (lscp, ls, 0);
#endif
  execvp (filename, argv);
  LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  struct GNUNET_DISK_FileHandle *control_pipe;
  char *childpipename = NULL;
  char **arg;
  char **non_const_argv;
  unsigned int cmdlen;
  char *cmd;
  char *idx;
  STARTUPINFOW start;
  PROCESS_INFORMATION proc;
  int argcount = 0;
  struct GNUNET_OS_Process *gnunet_proc;
  char path[MAX_PATH + 1];
  char *our_env[5] = { NULL, NULL, NULL, NULL, NULL };
  char *env_block = NULL;
  char *pathbuf;
  DWORD pathbuf_len;
  DWORD alloc_len;
  char *self_prefix;
  char *bindir;
  char *libdir;
  char *ptr;
  char *non_const_filename;
  char win_path[MAX_PATH + 1];
  struct GNUNET_DISK_PipeHandle *lsocks_pipe;
  const struct GNUNET_DISK_FileHandle *lsocks_write_fd;
  HANDLE lsocks_read;
  HANDLE lsocks_write;
  wchar_t *wpath;
  wchar_t *wcmd;
  size_t wpath_len;
  size_t wcmd_len;
  int env_off;
  int fail;
  long lRet;
  HANDLE stdin_handle;
  HANDLE stdout_handle;
  HANDLE stdih, stdoh, stdeh;
  DWORD stdif, stdof, stdef;
  BOOL bresult;
  DWORD error_code;

  if (GNUNET_SYSERR == GNUNET_OS_check_helper_binary (filename))
    return NULL; /* not executable */
 
  /* Search in prefix dir (hopefully - the directory from which
   * the current module was loaded), bindir and libdir, then in PATH
   */
  self_prefix = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_SELF_PREFIX);
  bindir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_BINDIR);
  libdir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBDIR);

  pathbuf_len = GetEnvironmentVariableA ("PATH", (char *) &pathbuf, 0);

  alloc_len =
      pathbuf_len + 1 + strlen (self_prefix) + 1 + strlen (bindir) + 1 +
      strlen (libdir);

  pathbuf = GNUNET_malloc (alloc_len * sizeof (char));

  ptr = pathbuf;
  ptr += sprintf (pathbuf, "%s;%s;%s;", self_prefix, bindir, libdir);
  GNUNET_free (self_prefix);
  GNUNET_free (bindir);
  GNUNET_free (libdir);

  alloc_len = GetEnvironmentVariableA ("PATH", ptr, pathbuf_len);
  if (alloc_len != pathbuf_len - 1)
  {
    GNUNET_free (pathbuf);
    errno = ENOSYS;             /* PATH changed on the fly. What kind of error is that? */
    return NULL;
  }

  cmdlen = strlen (filename);
  if ( (cmdlen < 5) || (0 != strcmp (&filename[cmdlen - 4], ".exe")) )
    GNUNET_asprintf (&non_const_filename, "%s.exe", filename);
  else
    GNUNET_asprintf (&non_const_filename, "%s", filename);

  /* It could be in POSIX form, convert it to a DOS path early on */
  if (ERROR_SUCCESS != (lRet = plibc_conv_to_win_path (non_const_filename, win_path)))
  {
    SetErrnoFromWinError (lRet);
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "plibc_conv_to_win_path",
                       non_const_filename);
    GNUNET_free (non_const_filename);
    GNUNET_free (pathbuf);
    return NULL;
  }
  GNUNET_free (non_const_filename);
  non_const_filename = GNUNET_strdup (win_path);
   /* Check that this is the full path. If it isn't, search. */
  /* FIXME: convert it to wchar_t and use SearchPathW?
   * Remember: arguments to _start_process() are technically in UTF-8...
   */
  if (non_const_filename[1] == ':')
    snprintf (path, sizeof (path) / sizeof (char), "%s", non_const_filename);
  else if (!SearchPathA
           (pathbuf, non_const_filename, NULL, sizeof (path) / sizeof (char),
            path, NULL))
  {
    SetErrnoFromWinError (GetLastError ());
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "SearchPath",
                       non_const_filename);
    GNUNET_free (non_const_filename);
    GNUNET_free (pathbuf);
    return NULL;
  }
  GNUNET_free (pathbuf);
  GNUNET_free (non_const_filename);

  /* Count the number of arguments */
  arg = (char **) argv;
  while (*arg)
  {
    arg++;
    argcount++;
  }

  /* Allocate a copy argv */
  non_const_argv = GNUNET_malloc (sizeof (char *) * (argcount + 1));

  /* Copy all argv strings */
  argcount = 0;
  arg = (char **) argv;
  while (*arg)
  {
    if (arg == argv)
      non_const_argv[argcount] = GNUNET_strdup (path);
    else
      non_const_argv[argcount] = GNUNET_strdup (*arg);
    arg++;
    argcount++;
  }
  non_const_argv[argcount] = NULL;

  /* Count cmd len */
  cmdlen = 1;
  arg = non_const_argv;
  while (*arg)
  {
    cmdlen = cmdlen + strlen (*arg) + 4;
    arg++;
  }

  /* Allocate and create cmd */
  cmd = idx = GNUNET_malloc (sizeof (char) * cmdlen);
  arg = non_const_argv;
  while (*arg)
  {
    char arg_last_char = (*arg)[strlen (*arg) - 1];
    idx += sprintf (idx, "\"%s%s\"%s", *arg,
        arg_last_char == '\\' ? "\\" : "", *(arg + 1) ? " " : "");
    arg++;
  }

  while (argcount > 0)
    GNUNET_free (non_const_argv[--argcount]);
  GNUNET_free (non_const_argv);

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);
  if ((pipe_stdin != NULL) || (pipe_stdout != NULL) || (std_inheritance != 0))
    start.dwFlags |= STARTF_USESTDHANDLES;

  stdih = GetStdHandle (STD_INPUT_HANDLE);
  GetHandleInformation (stdih, &stdif);
  if (pipe_stdin != NULL)
  {
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdin, GNUNET_DISK_PIPE_END_READ),
                                       &stdin_handle, sizeof (HANDLE));
    start.hStdInput = stdin_handle;
  }
  else if (stdih)
  {
    if (std_inheritance & GNUNET_OS_INHERIT_STD_IN)
    {
      SetHandleInformation (stdih, HANDLE_FLAG_INHERIT, 1);
      if (pipe_stdin == NULL)
        start.hStdInput = stdih;
    }
    else
      SetHandleInformation (stdih, HANDLE_FLAG_INHERIT, 0);
  }
    

  stdoh = GetStdHandle (STD_OUTPUT_HANDLE);
  GetHandleInformation (stdoh, &stdof);
  if (NULL != pipe_stdout)
  {
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdout,
                                        GNUNET_DISK_PIPE_END_WRITE),
                                       &stdout_handle, sizeof (HANDLE));
    start.hStdOutput = stdout_handle;
  }
  else if (stdoh)
  {
    if (std_inheritance & GNUNET_OS_INHERIT_STD_OUT)
    {
      SetHandleInformation (stdoh, HANDLE_FLAG_INHERIT, 1);
      if (pipe_stdout == NULL)
        start.hStdOutput = stdoh;
    }
    else
      SetHandleInformation (stdoh, HANDLE_FLAG_INHERIT, 0);
  }

  stdeh = GetStdHandle (STD_ERROR_HANDLE);
  GetHandleInformation (stdeh, &stdef);
  if (stdeh)
  {
    if (std_inheritance & GNUNET_OS_INHERIT_STD_ERR)
    {
      SetHandleInformation (stdeh, HANDLE_FLAG_INHERIT, 1);
      start.hStdError = stdeh;
    }
    else
      SetHandleInformation (stdeh, HANDLE_FLAG_INHERIT, 0);
  }

  if (GNUNET_YES == pipe_control)
  {
    control_pipe =
      npipe_create (&childpipename, GNUNET_DISK_OPEN_WRITE,
		    GNUNET_DISK_PERM_USER_READ |
		    GNUNET_DISK_PERM_USER_WRITE);
    if (control_pipe == NULL)
    {
      GNUNET_free (cmd);
      GNUNET_free (path);
      return NULL;
    }
  }
  else
    control_pipe = NULL;
  if (lsocks != NULL && lsocks[0] != INVALID_SOCKET)
  {
    lsocks_pipe = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_YES, GNUNET_NO);

    if (lsocks_pipe == NULL)
    {
      GNUNET_free (cmd);
      GNUNET_free (path);
      GNUNET_DISK_pipe_close (lsocks_pipe);
      return NULL;
    }
    lsocks_write_fd = GNUNET_DISK_pipe_handle (lsocks_pipe,
        GNUNET_DISK_PIPE_END_WRITE);
    GNUNET_DISK_internal_file_handle_ (lsocks_write_fd,
                                       &lsocks_write, sizeof (HANDLE));
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (lsocks_pipe, GNUNET_DISK_PIPE_END_READ),
                                       &lsocks_read, sizeof (HANDLE));
  }

  env_off = 0;
  if (NULL != childpipename)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Opened the parent end of the pipe `%s'\n",
	 childpipename);
    GNUNET_asprintf (&our_env[env_off++], "%s=", GNUNET_OS_CONTROL_PIPE);
    GNUNET_asprintf (&our_env[env_off++], "%s", childpipename);
    GNUNET_free (childpipename);
  }
  if ( (lsocks != NULL) && (lsocks[0] != INVALID_SOCKET))
  {
    /*This will tell the child that we're going to send lsocks over the pipe*/
    GNUNET_asprintf (&our_env[env_off++], "%s=", "GNUNET_OS_READ_LSOCKS");
    GNUNET_asprintf (&our_env[env_off++], "%lu", lsocks_read);
  }
  our_env[env_off++] = NULL;
  env_block = CreateCustomEnvTable (our_env);
  while (0 > env_off)
    GNUNET_free_non_null (our_env[--env_off]);

  wpath_len = 0;
  if (NULL == (wpath = u8_to_u16 ((uint8_t *) path, 1 + strlen (path), NULL, &wpath_len)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Failed to convert `%s' from UTF-8 to UTF-16: %d\n", path, errno);
    GNUNET_free (env_block);
    GNUNET_free (cmd);
    return NULL;
  }

  wcmd_len = 0;
  if (NULL == (wcmd = u8_to_u16 ((uint8_t *) cmd, 1 + strlen (cmd), NULL, &wcmd_len)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Failed to convert `%s' from UTF-8 to UTF-16: %d\n", cmd, errno);
    GNUNET_free (env_block);
    GNUNET_free (cmd);
    free (wpath);
    return NULL;
  }

  bresult = CreateProcessW (wpath, wcmd, NULL, NULL, TRUE,
       DETACHED_PROCESS | CREATE_SUSPENDED, env_block, NULL, &start, &proc);
  error_code = GetLastError ();

  if ((NULL == pipe_stdin) && (stdih))
    SetHandleInformation (stdih, HANDLE_FLAG_INHERIT, stdif);
    

  if ((NULL == pipe_stdout) && (stdoh))
    SetHandleInformation (stdoh, HANDLE_FLAG_INHERIT, stdof);

  if (stdeh)
    SetHandleInformation (stdeh, HANDLE_FLAG_INHERIT, stdef);

  GNUNET_free (env_block);
  GNUNET_free (cmd);
  free (wpath);
  free (wcmd);

  if (!bresult)
  {
    SetErrnoFromWinError (error_code);
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "CreateProcess");
    if (NULL != control_pipe)
      GNUNET_DISK_file_close (control_pipe);
    if (NULL != lsocks)
      GNUNET_DISK_pipe_close (lsocks_pipe);
    return NULL;
  }

  gnunet_proc = GNUNET_malloc (sizeof (struct GNUNET_OS_Process));
  gnunet_proc->pid = proc.dwProcessId;
  gnunet_proc->handle = proc.hProcess;
  gnunet_proc->control_pipe = control_pipe;

  CreateThread (NULL, 64000, &child_wait_thread, (void *) gnunet_proc, 0, NULL);

  ResumeThread (proc.hThread);
  CloseHandle (proc.hThread);

  if ( (NULL == lsocks) || (INVALID_SOCKET == lsocks[0]) )
    return gnunet_proc;

  GNUNET_DISK_pipe_close_end (lsocks_pipe, GNUNET_DISK_PIPE_END_READ);

  /* This is a replacement for "goto error" that doesn't use goto */
  fail = 1;
  do
  {
    ssize_t wrote;
    uint64_t size;
    uint64_t count;
    unsigned int i;

    /* Tell the number of sockets */
    for (count = 0; lsocks && lsocks[count] != INVALID_SOCKET; count++);

    wrote = GNUNET_DISK_file_write (lsocks_write_fd, &count, sizeof (count));
    if (sizeof (count) != wrote)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		  "Failed to write %u count bytes to the child: %u\n",
		  sizeof (count), GetLastError ());
      break;
    }
    for (i = 0; lsocks && lsocks[i] != INVALID_SOCKET; i++)
    {
      WSAPROTOCOL_INFOA pi;
      /* Get a socket duplication info */
      if (SOCKET_ERROR == WSADuplicateSocketA (lsocks[i], gnunet_proc->pid, &pi))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to duplicate an socket[%llu]: %u\n", i, 
		    GetLastError ());
        break;
      }
      /* Synchronous I/O is not nice, but we can't schedule this:
       * lsocks will be closed/freed by the caller soon, and until
       * the child creates a duplicate, closing a socket here will
       * close it for good.
       */
      /* Send the size of the structure
       * (the child might be built with different headers...)
       */
      size = sizeof (pi);
      wrote = GNUNET_DISK_file_write (lsocks_write_fd, &size, sizeof (size));
      if (sizeof (size) != wrote)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to write %u size[%llu] bytes to the child: %u\n", 
		    sizeof (size), i, GetLastError ());
        break;
      }
      /* Finally! Send the data */
      wrote = GNUNET_DISK_file_write (lsocks_write_fd, &pi, sizeof (pi));
      if (sizeof (pi) != wrote)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		    "Failed to write %u socket[%llu] bytes to the child: %u\n", 
		    sizeof (pi), i, GetLastError ());
        break;
      }
    }
    /* This will block us until the child makes a final read or closes
     * the pipe (hence no 'wrote' check), since we have to wait for it
     * to duplicate the last socket, before we return and start closing
     * our own copies)
     */
    wrote = GNUNET_DISK_file_write (lsocks_write_fd, &count, sizeof (count));
    fail = 0;
  }
  while (fail);

  GNUNET_DISK_file_sync (lsocks_write_fd);
  GNUNET_DISK_pipe_close (lsocks_pipe);

  if (fail)
  {
    /* If we can't pass on the socket(s), the child will block forever,
     * better put it out of its misery.
     */
    SafeTerminateProcess (gnunet_proc->handle, 0, 0);
    CloseHandle (gnunet_proc->handle);
    if (NULL != gnunet_proc->control_pipe)
      GNUNET_DISK_file_close (gnunet_proc->control_pipe);
    GNUNET_free (gnunet_proc);
    return NULL;
  }
  return gnunet_proc;
#endif
}




/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param argv NULL-terminated array of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_vap (int pipe_control,
                             enum GNUNET_OS_InheritStdioFlags std_inheritance,
			     struct GNUNET_DISK_PipeHandle *pipe_stdin,
			     struct GNUNET_DISK_PipeHandle *pipe_stdout,
			     const char *filename, 
			     char *const argv[])
{
  return start_process (pipe_control,
                        std_inheritance,
			pipe_stdin,
			pipe_stdout,
			NULL,
			filename,
			argv);
}


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param va NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_va (int pipe_control,
                            enum GNUNET_OS_InheritStdioFlags std_inheritance,
			    struct GNUNET_DISK_PipeHandle *pipe_stdin,
                            struct GNUNET_DISK_PipeHandle *pipe_stdout,
                            const char *filename, va_list va)
{
  struct GNUNET_OS_Process *ret;
  va_list ap;
  char **argv;
  int argc;

  argc = 0;
  va_copy (ap, va);
  while (NULL != va_arg (ap, char *))
    argc++;
  va_end (ap);
  argv = GNUNET_malloc (sizeof (char *) * (argc + 1));
  argc = 0;
  va_copy (ap, va);
  while (NULL != (argv[argc] = va_arg (ap, char *)))
    argc++;
  va_end (ap);
  ret = GNUNET_OS_start_process_vap (pipe_control,
                                     std_inheritance,
				     pipe_stdin,
				     pipe_stdout,
				     filename,
				     argv);
  GNUNET_free (argv);
  return ret;
}


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process (int pipe_control,
                         enum GNUNET_OS_InheritStdioFlags std_inheritance,
			 struct GNUNET_DISK_PipeHandle *pipe_stdin,
                         struct GNUNET_DISK_PipeHandle *pipe_stdout,
                         const char *filename, ...)
{
  struct GNUNET_OS_Process *ret;
  va_list ap;

  va_start (ap, filename);
  ret = GNUNET_OS_start_process_va (pipe_control, std_inheritance, pipe_stdin,
				    pipe_stdout, filename, ap);
  va_end (ap);
  return ret;
}


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags controlling which
 *        std handles of the parent are inherited by the child.
 *        pipe_stdin and pipe_stdout take priority over std_inheritance
 *        (when they are non-NULL).
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process
 * @return process ID of the new process, -1 on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_v (int pipe_control,
                           enum GNUNET_OS_InheritStdioFlags std_inheritance,
			   const SOCKTYPE *lsocks,
                           const char *filename,
                           char *const argv[])
{
  return start_process (pipe_control,
                        std_inheritance,
			NULL,
			NULL,
			lsocks,
			filename,
			argv);
}


/**
 * Retrieve the status of a process, waiting on him if dead.
 * Nonblocking version.
 * 
 * @param proc process ID
 * @param type status type
 * @param code return code/signal number
 * @return GNUNET_OK on success, GNUNET_NO if the process is still running, GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_status (struct GNUNET_OS_Process *proc,
                          enum GNUNET_OS_ProcessStatusType *type,
                          unsigned long *code)
{
#ifndef MINGW
  int status;
  int ret;

  GNUNET_assert (0 != proc);
  ret = waitpid (proc->pid, &status, WNOHANG);
  if (ret < 0)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    return GNUNET_SYSERR;
  }
  if (0 == ret)
  {
    *type = GNUNET_OS_PROCESS_RUNNING;
    *code = 0;
    return GNUNET_NO;
  }
  if (proc->pid != ret)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    return GNUNET_SYSERR;
  }
  if (WIFEXITED (status))
  {
    *type = GNUNET_OS_PROCESS_EXITED;
    *code = WEXITSTATUS (status);
  }
  else if (WIFSIGNALED (status))
  {
    *type = GNUNET_OS_PROCESS_SIGNALED;
    *code = WTERMSIG (status);
  }
  else if (WIFSTOPPED (status))
  {
    *type = GNUNET_OS_PROCESS_SIGNALED;
    *code = WSTOPSIG (status);
  }
#ifdef WIFCONTINUED
  else if (WIFCONTINUED (status))
  {
    *type = GNUNET_OS_PROCESS_RUNNING;
    *code = 0;
  }
#endif
  else
  {
    *type = GNUNET_OS_PROCESS_UNKNOWN;
    *code = 0;
  }
#else
  HANDLE h;
  DWORD c, error_code, ret;

  h = proc->handle;
  ret = proc->pid;
  if (h == NULL || ret == 0)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid process information {%d, %08X}\n",
         ret, h);
    return GNUNET_SYSERR;
  }
  if (h == NULL)
    h = GetCurrentProcess ();

  SetLastError (0);
  ret = GetExitCodeProcess (h, &c);
  error_code = GetLastError ();
  if (ret == 0 || error_code != NO_ERROR)
  {
    SetErrnoFromWinError (error_code);
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "GetExitCodeProcess");
    return GNUNET_SYSERR;
  }
  if (STILL_ACTIVE == c)
  {
    *type = GNUNET_OS_PROCESS_RUNNING;
    *code = 0;
    return GNUNET_NO;
  }
  *type = GNUNET_OS_PROCESS_EXITED;
  *code = c;
#endif

  return GNUNET_OK;
}


/**
 * Wait for a process
 *
 * @param proc pointer to process structure
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_wait (struct GNUNET_OS_Process *proc)
{
#ifndef MINGW
  pid_t pid = proc->pid;
  pid_t ret;

  while ( (pid != (ret = waitpid (pid, NULL, 0))) &&
	  (EINTR == errno) ) ;
  if (pid != ret) 
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
#else
  HANDLE h;

  h = proc->handle;
  if (NULL == h)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid process information {%d, %08X}\n",
         proc->pid, h);
    return GNUNET_SYSERR;
  }
  if (NULL == h)
    h = GetCurrentProcess ();

  if (WAIT_OBJECT_0 != WaitForSingleObject (h, INFINITE))
  {
    SetErrnoFromWinError (GetLastError ());
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
#endif
}


/**
 * Handle to a command.
 */
struct GNUNET_OS_CommandHandle
{

  /**
   * Process handle.
   */
  struct GNUNET_OS_Process *eip;

  /**
   * Handle to the output pipe.
   */
  struct GNUNET_DISK_PipeHandle *opipe;

  /**
   * Read-end of output pipe.
   */
  const struct GNUNET_DISK_FileHandle *r;

  /**
   * Function to call on each line of output.
   */
  GNUNET_OS_LineProcessor proc;

  /**
   * Closure for 'proc'.
   */
  void *proc_cls;

  /**
   * Buffer for the output.
   */
  char buf[1024];

  /**
   * Task reading from pipe.
   */
  GNUNET_SCHEDULER_TaskIdentifier rtask;

  /**
   * When to time out.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Current read offset in buf.
   */
  size_t off;
};


/**
 * Stop/kill a command.  Must ONLY be called either from
 * the callback after 'NULL' was passed for 'line' *OR*
 * from an independent task (not within the line processor).
 *
 * @param cmd handle to the process
 */
void
GNUNET_OS_command_stop (struct GNUNET_OS_CommandHandle *cmd)
{
  if (NULL != cmd->proc)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != cmd->rtask);
    GNUNET_SCHEDULER_cancel (cmd->rtask);
  }
  (void) GNUNET_OS_process_kill (cmd->eip, SIGKILL);
  GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (cmd->eip));
  GNUNET_OS_process_destroy (cmd->eip);
  GNUNET_DISK_pipe_close (cmd->opipe);
  GNUNET_free (cmd);
}


/**
 * Read from the process and call the line processor.
 *
 * @param cls the 'struct GNUNET_OS_CommandHandle'
 * @param tc scheduler context
 */
static void
cmd_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_OS_CommandHandle *cmd = cls;
  GNUNET_OS_LineProcessor proc;
  char *end;
  ssize_t ret;

  cmd->rtask = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES != GNUNET_NETWORK_fdset_handle_isset (tc->read_ready, cmd->r))
  {
    /* timeout, shutdown, etc. */
    proc = cmd->proc;
    cmd->proc = NULL;
    proc (cmd->proc_cls, NULL);
    return;
  }
  ret =
      GNUNET_DISK_file_read (cmd->r, &cmd->buf[cmd->off],
                             sizeof (cmd->buf) - cmd->off);
  if (ret <= 0)
  {
    if ((cmd->off > 0) && (cmd->off < sizeof (cmd->buf)))
    {
      cmd->buf[cmd->off] = '\0';
      cmd->proc (cmd->proc_cls, cmd->buf);
    }
    proc = cmd->proc;
    cmd->proc = NULL;
    proc (cmd->proc_cls, NULL);
    return;
  }
  end = memchr (&cmd->buf[cmd->off], '\n', ret);
  cmd->off += ret;
  while (NULL != end)
  {
    *end = '\0';
    cmd->proc (cmd->proc_cls, cmd->buf);
    memmove (cmd->buf, end + 1, cmd->off - (end + 1 - cmd->buf));
    cmd->off -= (end + 1 - cmd->buf);
    end = memchr (cmd->buf, '\n', cmd->off);
  }
  cmd->rtask =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_absolute_get_remaining
                                      (cmd->timeout), cmd->r, &cmd_read, cmd);
}


/**
 * Run the given command line and call the given function
 * for each line of the output.
 *
 * @param proc function to call for each line of the output
 * @param proc_cls closure for proc
 * @param timeout when to time out
 * @param binary command to run
 * @param ... arguments to command
 * @return NULL on error
 */
struct GNUNET_OS_CommandHandle *
GNUNET_OS_command_run (GNUNET_OS_LineProcessor proc, void *proc_cls,
                       struct GNUNET_TIME_Relative timeout, const char *binary,
                       ...)
{
  struct GNUNET_OS_CommandHandle *cmd;
  struct GNUNET_OS_Process *eip;
  struct GNUNET_DISK_PipeHandle *opipe;
  va_list ap;

  opipe = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if (NULL == opipe)
    return NULL;
  va_start (ap, binary);
  /* redirect stdout, don't inherit stderr/stdin */
  eip = GNUNET_OS_start_process_va (GNUNET_NO, 0, NULL, opipe, binary, ap);
  va_end (ap);
  if (NULL == eip)
  {
    GNUNET_DISK_pipe_close (opipe);
    return NULL;
  }
  GNUNET_DISK_pipe_close_end (opipe, GNUNET_DISK_PIPE_END_WRITE);
  cmd = GNUNET_malloc (sizeof (struct GNUNET_OS_CommandHandle));
  cmd->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  cmd->eip = eip;
  cmd->opipe = opipe;
  cmd->proc = proc;
  cmd->proc_cls = proc_cls;
  cmd->r = GNUNET_DISK_pipe_handle (opipe, GNUNET_DISK_PIPE_END_READ);
  cmd->rtask = GNUNET_SCHEDULER_add_read_file (timeout, cmd->r, &cmd_read, cmd);
  return cmd;
}


/* end of os_priority.c */

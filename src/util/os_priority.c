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
#include "disk.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

#define GNUNET_OS_CONTROL_PIPE "GNUNET_OS_CONTROL_PIPE"

struct GNUNET_OS_Process
{
  pid_t pid;
#if WINDOWS
  HANDLE handle;
#endif
  int sig;
  struct GNUNET_DISK_FileHandle *control_pipe;
};

static struct GNUNET_OS_Process current_process;


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
  struct GNUNET_DISK_FileHandle *control_pipe =
      (struct GNUNET_DISK_FileHandle *) cls;
  int sig;

#if DEBUG_OS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "`%s' invoked because of %d\n", __FUNCTION__,
       tc->reason);
#endif
  if (tc->reason &
      (GNUNET_SCHEDULER_REASON_SHUTDOWN | GNUNET_SCHEDULER_REASON_TIMEOUT |
       GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    GNUNET_DISK_npipe_close (control_pipe);
  }
  else
  {
    if (GNUNET_DISK_file_read (control_pipe, &sig, sizeof (sig)) !=
        sizeof (sig))
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "GNUNET_DISK_file_read");
      GNUNET_DISK_npipe_close (control_pipe);
    }
    else
    {
#if DEBUG_OS
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Got control code %d from parent\n", sig);
#endif
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      control_pipe, &parent_control_handler,
                                      control_pipe);
      raise (sig);
    }
  }
}


/**
 * Task that connects this process to its parent via pipe
 */
void
GNUNET_OS_install_parent_control_handler (void *cls,
                                          const struct
                                          GNUNET_SCHEDULER_TaskContext *tc)
{
  const char *env_buf;
  struct GNUNET_DISK_FileHandle *control_pipe;

  env_buf = getenv (GNUNET_OS_CONTROL_PIPE);
  if ((env_buf == NULL) || (strlen (env_buf) <= 0))
  {
    LOG (GNUNET_ERROR_TYPE_INFO, _("Not installing a handler because $%s=%s\n"),
         GNUNET_OS_CONTROL_PIPE, env_buf);
    return;
  }
  control_pipe =
      GNUNET_DISK_npipe_open (env_buf, GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  if (control_pipe == NULL)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", env_buf);
    return;
  }
#if DEBUG_OS
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding parent control handler pipe `%s' to the scheduler\n", env_buf);
#endif
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, control_pipe,
                                  &parent_control_handler, control_pipe);
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


int
GNUNET_OS_process_kill (struct GNUNET_OS_Process *proc, int sig)
{
#if ENABLE_WINDOWS_WORKAROUNDS
  int res = 0;
  int ret = 0;

  ret = GNUNET_DISK_file_write (proc->control_pipe, &sig, sizeof (sig));
  if (ret != sizeof (sig))
  {
    if (errno == ECOMM)
    {
      /* Child process is not controllable via pipe */
#if DEBUG_OS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Child process is not controllable, will kill it directly\n");
#endif
    }
    else if (errno == EPIPE)
    {
#if DEBUG_OS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Failed to write into control pipe, because pipe is invalid (the child is most likely dead)\n");
#endif
    }
    else
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Failed to write into control pipe , errno is %d\n", errno);
#if WINDOWS && !defined(__CYGWIN__)
    TerminateProcess (proc->handle, 0);
#else
    PLIBC_KILL (proc->pid, sig);
#endif
  }
  else
  {
#if DEBUG_OS
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Wrote control code into control pipe, now waiting\n");
#endif

#if WINDOWS
    /* Give it 3 seconds to die, then kill it in a nice Windows-specific way */
    if (WaitForSingleObject (proc->handle, 3000) != WAIT_OBJECT_0)
      TerminateProcess (proc->handle, 0);
    res = 0;
#else
    struct GNUNET_NETWORK_FDSet *rfds;
    struct GNUNET_NETWORK_FDSet *efds;

    rfds = GNUNET_NETWORK_fdset_create ();
    efds = GNUNET_NETWORK_fdset_create ();

    GNUNET_NETWORK_fdset_handle_set (rfds, proc->control_pipe);
    GNUNET_NETWORK_fdset_handle_set (efds, proc->control_pipe);

    /* Ndurner thought this up, and i have no idea what it does.
     * There's have never been any code to answer the shutdown call
     * (write a single int into the pipe, so that this function can read it).
     * On *nix select() will probably tell that pipe is ready
     * for reading, once the other process shuts down,
     * but the read () call will fail, triggering a kill ()
     * on the pid that is already dead. This will probably result in non-0
     * return from kill(), and therefore from this function.
     */
    while (1)
    {
      ret =
          GNUNET_NETWORK_socket_select (rfds, NULL, efds,
                                        GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_relative_get_unit (),
                                         5000));

      if (ret < 1 ||
          GNUNET_NETWORK_fdset_handle_isset (efds, proc->control_pipe))
      {
        /* Just to be sure */
        PLIBC_KILL (proc->pid, sig);
        res = 0;
        break;
      }
      else
      {
        if (GNUNET_DISK_file_read (proc->control_pipe, &ret, sizeof (ret)) !=
            GNUNET_OK)
          res = PLIBC_KILL (proc->pid, sig);

        /* Child signaled shutdown is in progress */
        continue;
      }
    }
#endif
  }

  return res;
#else
  return kill (proc->pid, sig);
#endif
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


void
GNUNET_OS_process_close (struct GNUNET_OS_Process *proc)
{
#if ENABLE_WINDOWS_WORKAROUNDS
  if (proc->control_pipe)
    GNUNET_DISK_npipe_close (proc->control_pipe);
#endif
// FIXME NILS
#ifdef WINDOWS
  if (proc->handle != NULL)
    CloseHandle (proc->handle);
#endif
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
ChildWaitThread (void *arg)
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
  if (prio == GNUNET_SCHEDULER_PRIORITY_KEEP)
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
#if DEBUG_OS
  LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
       "Priority management not availabe for this platform\n");
#endif
#endif
  return GNUNET_OK;
}

#if MINGW
static char *
CreateCustomEnvTable (char **vars)
{
  char *win32_env_table, *ptr, **var_ptr, *result, *result_ptr;
  size_t tablesize = 0;
  size_t items_count = 0;
  size_t n_found = 0, n_var;
  char *index = NULL;
  size_t c;
  size_t var_len;
  char *var;
  char *val;

  win32_env_table = GetEnvironmentStringsA ();
  if (win32_env_table == NULL)
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
#endif


/**
 * Start a process.
 *
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param va NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_va (struct GNUNET_DISK_PipeHandle *pipe_stdin,
                            struct GNUNET_DISK_PipeHandle *pipe_stdout,
                            const char *filename, va_list va)
{
  va_list ap;

#if ENABLE_WINDOWS_WORKAROUNDS
  char *childpipename = NULL;
  struct GNUNET_DISK_FileHandle *control_pipe = NULL;
#endif
  struct GNUNET_OS_Process *gnunet_proc = NULL;

#ifndef MINGW
  pid_t ret;
  char **argv;
  int argc;
  int fd_stdout_write;
  int fd_stdout_read;
  int fd_stdin_read;
  int fd_stdin_write;

#if ENABLE_WINDOWS_WORKAROUNDS
  control_pipe =
      GNUNET_DISK_npipe_create (&childpipename, GNUNET_DISK_OPEN_WRITE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
  if (control_pipe == NULL)
    return NULL;
#endif

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
  if (pipe_stdout != NULL)
  {
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdout,
                                        GNUNET_DISK_PIPE_END_WRITE),
                                       &fd_stdout_write, sizeof (int));
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdout, GNUNET_DISK_PIPE_END_READ),
                                       &fd_stdout_read, sizeof (int));
  }
  if (pipe_stdin != NULL)
  {
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdin, GNUNET_DISK_PIPE_END_READ),
                                       &fd_stdin_read, sizeof (int));
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdin, GNUNET_DISK_PIPE_END_WRITE),
                                       &fd_stdin_write, sizeof (int));
  }

  ret = fork ();
  if (ret != 0)
  {
    if (ret == -1)
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fork");
#if ENABLE_WINDOWS_WORKAROUNDS
      GNUNET_DISK_npipe_close (control_pipe);
#endif
    }
    else
    {
      gnunet_proc = GNUNET_malloc (sizeof (struct GNUNET_OS_Process));
      gnunet_proc->pid = ret;
#if ENABLE_WINDOWS_WORKAROUNDS
      gnunet_proc->control_pipe = control_pipe;
#endif
    }
    GNUNET_free (argv);
#if ENABLE_WINDOWS_WORKAROUNDS
    GNUNET_free (childpipename);
#endif
    return gnunet_proc;
  }

#if ENABLE_WINDOWS_WORKAROUNDS
  setenv (GNUNET_OS_CONTROL_PIPE, childpipename, 1);
  GNUNET_free (childpipename);
#endif

  if (pipe_stdout != NULL)
  {
    GNUNET_break (0 == close (fd_stdout_read));
    if (-1 == dup2 (fd_stdout_write, 1))
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "dup2");
    GNUNET_break (0 == close (fd_stdout_write));
  }

  if (pipe_stdin != NULL)
  {

    GNUNET_break (0 == close (fd_stdin_write));
    if (-1 == dup2 (fd_stdin_read, 0))
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "dup2");
    GNUNET_break (0 == close (fd_stdin_read));
  }
  execvp (filename, argv);
  LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  char *arg;
  unsigned int cmdlen;
  char *cmd, *idx;
  STARTUPINFO start;
  PROCESS_INFORMATION proc;

  HANDLE stdin_handle;
  HANDLE stdout_handle;

  char path[MAX_PATH + 1];

  char *our_env[3] = { NULL, NULL, NULL };
  char *env_block = NULL;
  char *pathbuf;
  DWORD pathbuf_len, alloc_len;
  char *self_prefix;
  char *bindir;
  char *libdir;
  char *ptr;
  char *non_const_filename;

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
  GNUNET_assert (alloc_len == (pathbuf_len - 1));

  cmdlen = strlen (filename);
  if (cmdlen < 5 || strcmp (&filename[cmdlen - 4], ".exe") != 0)
    GNUNET_asprintf (&non_const_filename, "%s.exe", filename);
  else
    GNUNET_asprintf (&non_const_filename, "%s", filename);

  /* Check that this is the full path. If it isn't, search. */
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

  cmdlen = 0;
  va_copy (ap, va);
  while (NULL != (arg = va_arg (ap, char *)))
  {
    if (cmdlen == 0)
      cmdlen = cmdlen + strlen (path) + 3;
    else
      cmdlen = cmdlen + strlen (arg) + 3;
  }
  va_end (ap);

  cmd = idx = GNUNET_malloc (sizeof (char) * (cmdlen + 1));
  va_copy (ap, va);
  while (NULL != (arg = va_arg (ap, char *)))
  {
    if (idx == cmd)
      idx += sprintf (idx, "\"%s\" ", path);
    else
      idx += sprintf (idx, "\"%s\" ", arg);
  }
  va_end (ap);

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  if ((pipe_stdin != NULL) || (pipe_stdout != NULL))
    start.dwFlags |= STARTF_USESTDHANDLES;

  if (pipe_stdin != NULL)
  {
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdin, GNUNET_DISK_PIPE_END_READ),
                                       &stdin_handle, sizeof (HANDLE));
    start.hStdInput = stdin_handle;
  }

  if (pipe_stdout != NULL)
  {
    GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle
                                       (pipe_stdout,
                                        GNUNET_DISK_PIPE_END_WRITE),
                                       &stdout_handle, sizeof (HANDLE));
    start.hStdOutput = stdout_handle;
  }

  control_pipe =
      GNUNET_DISK_npipe_create (&childpipename, GNUNET_DISK_OPEN_WRITE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
  if (control_pipe == NULL)
  {
    GNUNET_free (cmd);
    GNUNET_free (path);
    return NULL;
  }

#if DEBUG_OS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Opened the parent end of the pipe `%s'\n",
       childpipename);
#endif

  GNUNET_asprintf (&our_env[0], "%s=", GNUNET_OS_CONTROL_PIPE);
  GNUNET_asprintf (&our_env[1], "%s", childpipename);
  our_env[2] = NULL;
  env_block = CreateCustomEnvTable (our_env);
  GNUNET_free (our_env[0]);
  GNUNET_free (our_env[1]);

  if (!CreateProcessA
      (path, cmd, NULL, NULL, TRUE, DETACHED_PROCESS | CREATE_SUSPENDED,
       env_block, NULL, &start, &proc))
  {
    SetErrnoFromWinError (GetLastError ());
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "CreateProcess", path);
    GNUNET_free (env_block);
    GNUNET_free (cmd);
    return NULL;
  }

  GNUNET_free (env_block);

  gnunet_proc = GNUNET_malloc (sizeof (struct GNUNET_OS_Process));
  gnunet_proc->pid = proc.dwProcessId;
  gnunet_proc->handle = proc.hProcess;
  gnunet_proc->control_pipe = control_pipe;

  CreateThread (NULL, 64000, ChildWaitThread, (void *) gnunet_proc, 0, NULL);

  ResumeThread (proc.hThread);
  CloseHandle (proc.hThread);

  GNUNET_free (cmd);

  return gnunet_proc;
#endif
}


/**
 * Start a process.
 *
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 *
 * @return pointer to process structure of the new process, NULL on error
 *
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process (struct GNUNET_DISK_PipeHandle *pipe_stdin,
                         struct GNUNET_DISK_PipeHandle *pipe_stdout,
                         const char *filename, ...)
{
  struct GNUNET_OS_Process *ret;
  va_list ap;

  va_start (ap, filename);
  ret = GNUNET_OS_start_process_va (pipe_stdin, pipe_stdout, filename, ap);
  va_end (ap);
  return ret;
}


/**
 * Start a process.
 *
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process
 * @return process ID of the new process, -1 on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_v (const int *lsocks, const char *filename,
                           char *const argv[])
{
#if ENABLE_WINDOWS_WORKAROUNDS
  struct GNUNET_DISK_FileHandle *control_pipe = NULL;
  char *childpipename = NULL;
#endif

#ifndef MINGW
  pid_t ret;
  char lpid[16];
  char fds[16];
  struct GNUNET_OS_Process *gnunet_proc = NULL;
  int i;
  int j;
  int k;
  int tgt;
  int flags;
  int *lscp;
  unsigned int ls;

#if ENABLE_WINDOWS_WORKAROUNDS
  control_pipe =
      GNUNET_DISK_npipe_create (&childpipename, GNUNET_DISK_OPEN_WRITE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
  if (control_pipe == NULL)
    return NULL;
#endif

  lscp = NULL;
  ls = 0;
  if (lsocks != NULL)
  {
    i = 0;
    while (-1 != (k = lsocks[i++]))
      GNUNET_array_append (lscp, ls, k);
    GNUNET_array_append (lscp, ls, -1);
  }
  ret = fork ();
  if (ret != 0)
  {
    if (ret == -1)
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fork");
#if ENABLE_WINDOWS_WORKAROUNDS
      GNUNET_DISK_npipe_close (control_pipe);
#endif
    }
    else
    {
      gnunet_proc = GNUNET_malloc (sizeof (struct GNUNET_OS_Process));
      gnunet_proc->pid = ret;
#if ENABLE_WINDOWS_WORKAROUNDS
      gnunet_proc->control_pipe = control_pipe;

#endif
    }
    GNUNET_array_grow (lscp, ls, 0);
#if ENABLE_WINDOWS_WORKAROUNDS
    GNUNET_free (childpipename);
#endif
    return gnunet_proc;
  }

#if ENABLE_WINDOWS_WORKAROUNDS
  setenv (GNUNET_OS_CONTROL_PIPE, childpipename, 1);
  GNUNET_free (childpipename);
#endif

  if (lscp != NULL)
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
  GNUNET_array_grow (lscp, ls, 0);
  execvp (filename, argv);
  LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  char **arg, **non_const_argv;
  unsigned int cmdlen;
  char *cmd, *idx;
  STARTUPINFO start;
  PROCESS_INFORMATION proc;
  int argcount = 0;
  struct GNUNET_OS_Process *gnunet_proc = NULL;

  char path[MAX_PATH + 1];

  char *our_env[3] = { NULL, NULL, NULL };
  char *env_block = NULL;
  char *pathbuf;
  DWORD pathbuf_len, alloc_len;
  char *self_prefix;
  char *bindir;
  char *libdir;
  char *ptr;
  char *non_const_filename;

  GNUNET_assert (lsocks == NULL);

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
  if (cmdlen < 5 || strcmp (&filename[cmdlen - 4], ".exe") != 0)
    GNUNET_asprintf (&non_const_filename, "%s.exe", filename);
  else
    GNUNET_asprintf (&non_const_filename, "%s", filename);

  /* Check that this is the full path. If it isn't, search. */
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
    cmdlen = cmdlen + strlen (*arg) + 3;
    arg++;
  }

  /* Allocate and create cmd */
  cmd = idx = GNUNET_malloc (sizeof (char) * cmdlen);
  arg = non_const_argv;
  while (*arg)
  {
    idx += sprintf (idx, "\"%s\" ", *arg);
    arg++;
  }

  while (argcount > 0)
    GNUNET_free (non_const_argv[--argcount]);
  GNUNET_free (non_const_argv);

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  control_pipe =
      GNUNET_DISK_npipe_create (&childpipename, GNUNET_DISK_OPEN_WRITE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
  if (control_pipe == NULL)
  {
    GNUNET_free (cmd);
    GNUNET_free (path);
    return NULL;
  }

#if DEBUG_OS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Opened the parent end of the pipe `%s'\n",
       childpipename);
#endif

  GNUNET_asprintf (&our_env[0], "%s=", GNUNET_OS_CONTROL_PIPE);
  GNUNET_asprintf (&our_env[1], "%s", childpipename);
  our_env[2] = NULL;
  env_block = CreateCustomEnvTable (our_env);
  GNUNET_free (our_env[0]);
  GNUNET_free (our_env[1]);

  if (!CreateProcess
      (path, cmd, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_SUSPENDED,
       env_block, NULL, &start, &proc))
  {
    SetErrnoFromWinError (GetLastError ());
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "CreateProcess");
    GNUNET_free (env_block);
    GNUNET_free (cmd);
    return NULL;
  }

  GNUNET_free (env_block);

  gnunet_proc = GNUNET_malloc (sizeof (struct GNUNET_OS_Process));
  gnunet_proc->pid = proc.dwProcessId;
  gnunet_proc->handle = proc.hProcess;
  gnunet_proc->control_pipe = control_pipe;

  CreateThread (NULL, 64000, ChildWaitThread, (void *) gnunet_proc, 0, NULL);

  ResumeThread (proc.hThread);
  CloseHandle (proc.hThread);
  GNUNET_free (cmd);

  return gnunet_proc;
#endif
}


/**
 * Retrieve the status of a process
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
 * @param proc pointer to process structure
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_wait (struct GNUNET_OS_Process *proc)
{

#ifndef MINGW
  pid_t pid = proc->pid;

  if (pid != waitpid (pid, NULL, 0))
    return GNUNET_SYSERR;
  return GNUNET_OK;
#else
  HANDLE h;
  int ret;

  h = proc->handle;
  if (NULL == h)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid process information {%d, %08X}\n",
         proc->pid, h);
    return GNUNET_SYSERR;
  }
  if (h == NULL)
    h = GetCurrentProcess ();

  if (WAIT_OBJECT_0 != WaitForSingleObject (h, INFINITE))
  {
    SetErrnoFromWinError (GetLastError ());
    ret = GNUNET_SYSERR;
  }
  else
    ret = GNUNET_OK;

  return ret;
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

  if (cmd->proc != NULL)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != cmd->rtask);
    GNUNET_SCHEDULER_cancel (cmd->rtask);
  }
  (void) GNUNET_OS_process_kill (cmd->eip, SIGKILL);
  GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (cmd->eip));
  GNUNET_OS_process_close (cmd->eip);
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
  while (end != NULL)
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

  opipe = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if (NULL == opipe)
    return NULL;
  va_start (ap, binary);
  eip = GNUNET_OS_start_process_va (NULL, opipe, binary, ap);
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

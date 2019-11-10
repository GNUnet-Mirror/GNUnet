/*
     This file is part of GNUnet
     Copyright (C) 2002, 2003, 2004, 2005, 2006, 2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/os_priority.c
 * @brief Methods to set process priority
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"
#include <unistr.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-os-priority", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
  GNUNET_log_from_strerror (kind, "util-os-priority", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
  GNUNET_log_from_strerror_file (kind, "util-os-priority", syscall, filename)

#define GNUNET_OS_CONTROL_PIPE "GNUNET_OS_CONTROL_PIPE"


struct GNUNET_OS_Process
{
  /**
   * PID of the process.
   */
  pid_t pid;


  /**
   * Pipe we use to signal the process.
   * NULL if unused, or if process was deemed uncontrollable.
   */
  struct GNUNET_DISK_FileHandle *control_pipe;
};


/**
 * Handle for 'this' process.
 */
static struct GNUNET_OS_Process current_process;

/**
 * Handle for the #parent_control_handler() Task.
 */
static struct GNUNET_SCHEDULER_Task *pch;

/**
 * Handle for the #shutdown_pch() Task.
 */
static struct GNUNET_SCHEDULER_Task *spch;


/**
 * This handler is called on shutdown to remove the #pch.
 *
 * @param cls the `struct GNUNET_DISK_FileHandle` of the control pipe
 */
static void
shutdown_pch (void *cls)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;

  GNUNET_SCHEDULER_cancel (pch);
  pch = NULL;
  GNUNET_DISK_file_close (control_pipe);
  control_pipe = NULL;
}


/**
 * This handler is called when there are control data to be read on the pipe
 *
 * @param cls the `struct GNUNET_DISK_FileHandle` of the control pipe
 */
static void
parent_control_handler (void *cls)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;
  char sig;
  char *pipe_fd;
  ssize_t ret;

  pch = NULL;
  ret = GNUNET_DISK_file_read (control_pipe, &sig, sizeof(sig));
  if (sizeof(sig) != ret)
  {
    if (-1 == ret)
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "GNUNET_DISK_file_read");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Closing control pipe\n");
    GNUNET_DISK_file_close (control_pipe);
    control_pipe = NULL;
    GNUNET_SCHEDULER_cancel (spch);
    spch = NULL;
    return;
  }
  pipe_fd = getenv (GNUNET_OS_CONTROL_PIPE);
  GNUNET_assert ((NULL == pipe_fd) || (strlen (pipe_fd) <= 0));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got control code %d from parent via pipe %s\n",
       sig,
       pipe_fd);
  pch = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        control_pipe,
                                        &parent_control_handler,
                                        control_pipe);
  GNUNET_SIGNAL_raise ((int) sig);
}


/**
 * Task that connects this process to its parent via pipe;
 * essentially, the parent control handler will read signal numbers
 * from the #GNUNET_OS_CONTROL_PIPE (as given in an environment
 * variable) and raise those signals.
 *
 * @param cls closure (unused)
 */
void
GNUNET_OS_install_parent_control_handler (void *cls)
{
  const char *env_buf;
  char *env_buf_end;
  struct GNUNET_DISK_FileHandle *control_pipe;
  uint64_t pipe_fd;

  (void) cls;
  if (NULL != pch)
  {
    /* already done, we've been called twice... */
    GNUNET_break (0);
    return;
  }
  env_buf = getenv (GNUNET_OS_CONTROL_PIPE);
  if ((NULL == env_buf) || (strlen (env_buf) <= 0))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not installing a handler because $%s is empty\n",
         GNUNET_OS_CONTROL_PIPE);
    putenv (GNUNET_OS_CONTROL_PIPE "=");
    return;
  }
  errno = 0;
  pipe_fd = strtoull (env_buf, &env_buf_end, 16);
  if ((0 != errno) || (env_buf == env_buf_end))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "strtoull", env_buf);
    putenv (GNUNET_OS_CONTROL_PIPE "=");
    return;
  }
  if (pipe_fd >= FD_SETSIZE)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "GNUNET_OS_CONTROL_PIPE `%s' contains garbage?\n",
         env_buf);
    putenv (GNUNET_OS_CONTROL_PIPE "=");
    return;
  }

  control_pipe = GNUNET_DISK_get_handle_from_int_fd ((int) pipe_fd);

  if (NULL == control_pipe)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", env_buf);
    putenv (GNUNET_OS_CONTROL_PIPE "=");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding parent control handler pipe `%s' to the scheduler\n",
       env_buf);
  pch = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        control_pipe,
                                        &parent_control_handler,
                                        control_pipe);
  spch = GNUNET_SCHEDULER_add_shutdown (&shutdown_pch, control_pipe);
  putenv (GNUNET_OS_CONTROL_PIPE "=");
}


/**
 * Get process structure for current process
 *
 * The pointer it returns points to static memory location and must
 * not be deallocated/closed.
 *
 * @return pointer to the process sturcutre for this process
 */
struct GNUNET_OS_Process *
GNUNET_OS_process_current ()
{
  current_process.pid = 0;
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
  if (NULL != proc->control_pipe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending signal %d to pid: %u via pipe\n",
         sig,
         proc->pid);
    ret = GNUNET_DISK_file_write (proc->control_pipe, &csig, sizeof(csig));
    if (sizeof(csig) == ret)
      return 0;
  }
  /* pipe failed or non-existent, try other methods */
  switch (sig)
  {
  case SIGHUP:
  case SIGINT:
  case SIGKILL:
  case SIGTERM:
#if (SIGTERM != GNUNET_TERM_SIG)
  case GNUNET_TERM_SIG:
#endif
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending signal %d to pid: %u via system call\n",
         sig,
         proc->pid);
    return kill (proc->pid, sig);
  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending signal %d to pid: %u via system call\n",
         sig,
         proc->pid);
    return kill (proc->pid, sig);
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
GNUNET_OS_process_get_pid (struct GNUNET_OS_Process *proc)
{
  return proc->pid;
}


/**
 * Cleans up process structure contents (OS-dependent) and deallocates
 * it.
 *
 * @param proc pointer to process structure
 */
void
GNUNET_OS_process_destroy (struct GNUNET_OS_Process *proc)
{
  if (NULL != proc->control_pipe)
    GNUNET_DISK_file_close (proc->control_pipe);

  GNUNET_free (proc);
}


/**
 * Open '/dev/null' and make the result the given
 * file descriptor.
 *
 * @param target_fd desired FD to point to /dev/null
 * @param flags open flags (O_RDONLY, O_WRONLY)
 */
static void
open_dev_null (int target_fd, int flags)
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
 * @param pipe_stderr pipe to use for stderr for child process (or NULL)
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
               struct GNUNET_DISK_PipeHandle *pipe_stderr,
               const int *lsocks,
               const char *filename,
               char *const argv[])
{
  pid_t ret;
  char fds[16];
  struct GNUNET_OS_Process *gnunet_proc;
  struct GNUNET_DISK_FileHandle *childpipe_read;
  struct GNUNET_DISK_FileHandle *childpipe_write;
  int childpipe_read_fd;
  int i;
  int j;
  int k;
  int tgt;
  int flags;
  int *lscp;
  unsigned int ls;
  int fd_stdout_write;
  int fd_stdout_read;
  int fd_stderr_write;
  int fd_stderr_read;
  int fd_stdin_read;
  int fd_stdin_write;

  if (GNUNET_SYSERR ==
      GNUNET_OS_check_helper_binary (filename, GNUNET_NO, NULL))
    return NULL; /* not executable */
  if (GNUNET_YES == pipe_control)
  {
    struct GNUNET_DISK_PipeHandle *childpipe;
    int dup_childpipe_read_fd = -1;

    childpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_YES, GNUNET_NO);
    if (NULL == childpipe)
      return NULL;
    childpipe_read =
      GNUNET_DISK_pipe_detach_end (childpipe, GNUNET_DISK_PIPE_END_READ);
    childpipe_write =
      GNUNET_DISK_pipe_detach_end (childpipe, GNUNET_DISK_PIPE_END_WRITE);
    GNUNET_DISK_pipe_close (childpipe);
    if ((NULL == childpipe_read) || (NULL == childpipe_write) ||
        (GNUNET_OK != GNUNET_DISK_internal_file_handle_ (childpipe_read,
                                                         &childpipe_read_fd,
                                                         sizeof(int))) ||
        (-1 == (dup_childpipe_read_fd = dup (childpipe_read_fd))))
    {
      if (NULL != childpipe_read)
        GNUNET_DISK_file_close (childpipe_read);
      if (NULL != childpipe_write)
        GNUNET_DISK_file_close (childpipe_write);
      if (0 <= dup_childpipe_read_fd)
        close (dup_childpipe_read_fd);
      return NULL;
    }
    childpipe_read_fd = dup_childpipe_read_fd;
    GNUNET_DISK_file_close (childpipe_read);
  }
  else
  {
    childpipe_write = NULL;
    childpipe_read_fd = -1;
  }
  if (NULL != pipe_stdin)
  {
    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_DISK_internal_file_handle_ (
        GNUNET_DISK_pipe_handle (pipe_stdin, GNUNET_DISK_PIPE_END_READ),
        &fd_stdin_read,
        sizeof(int)));
    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_DISK_internal_file_handle_ (
        GNUNET_DISK_pipe_handle (pipe_stdin, GNUNET_DISK_PIPE_END_WRITE),
        &fd_stdin_write,
        sizeof(int)));
  }
  if (NULL != pipe_stdout)
  {
    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_DISK_internal_file_handle_ (
        GNUNET_DISK_pipe_handle (pipe_stdout, GNUNET_DISK_PIPE_END_WRITE),
        &fd_stdout_write,
        sizeof(int)));
    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_DISK_internal_file_handle_ (
        GNUNET_DISK_pipe_handle (pipe_stdout, GNUNET_DISK_PIPE_END_READ),
        &fd_stdout_read,
        sizeof(int)));
  }
  if (NULL != pipe_stderr)
  {
    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_DISK_internal_file_handle_ (
        GNUNET_DISK_pipe_handle (pipe_stderr, GNUNET_DISK_PIPE_END_READ),
        &fd_stderr_read,
        sizeof(int)));
    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_DISK_internal_file_handle_ (
        GNUNET_DISK_pipe_handle (pipe_stderr, GNUNET_DISK_PIPE_END_WRITE),
        &fd_stderr_write,
        sizeof(int)));
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
  /* see https://web.archive.org/web/20150924082249/gnunet.org/vfork */
  ret = vfork ();
#else
  ret = fork ();
#endif
  if (-1 == ret)
  {
    int eno = errno;
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fork");
    GNUNET_array_grow (lscp, ls, 0);
    if (NULL != childpipe_write)
      GNUNET_DISK_file_close (childpipe_write);
    if (0 <= childpipe_read_fd)
      close (childpipe_read_fd);
    errno = eno;
    return NULL;
  }
  if (0 != ret)
  {
    unsetenv (GNUNET_OS_CONTROL_PIPE);
    gnunet_proc = GNUNET_new (struct GNUNET_OS_Process);
    gnunet_proc->pid = ret;
    gnunet_proc->control_pipe = childpipe_write;
    if (GNUNET_YES == pipe_control)
    {
      close (childpipe_read_fd);
    }
    GNUNET_array_grow (lscp, ls, 0);
    return gnunet_proc;
  }
  if (0 <= childpipe_read_fd)
  {
    char fdbuf[100];
#ifndef DARWIN
    /* due to vfork, we must NOT free memory on DARWIN! */
    GNUNET_DISK_file_close (childpipe_write);
#endif
    snprintf (fdbuf, 100, "%x", childpipe_read_fd);
    setenv (GNUNET_OS_CONTROL_PIPE, fdbuf, 1);
  }
  else
    unsetenv (GNUNET_OS_CONTROL_PIPE);
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
  if (NULL != pipe_stderr)
  {
    GNUNET_break (0 == close (fd_stderr_read));
    if (-1 == dup2 (fd_stderr_write, 2))
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "dup2");
    GNUNET_break (0 == close (fd_stderr_write));
  }
  else if (0 == (std_inheritance & GNUNET_OS_INHERIT_STD_ERR))
  {
    GNUNET_break (0 == close (2));
    open_dev_null (2, O_WRONLY);
  }
  if (NULL != lscp)
  {
    /* read systemd documentation... */
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
    GNUNET_snprintf (fds, sizeof(fds), "%u", i);
    setenv ("LISTEN_FDS", fds, 1);
  }
#ifndef DARWIN
  /* due to vfork, we must NOT free memory on DARWIN! */
  GNUNET_array_grow (lscp, ls, 0);
#endif
  execvp (filename, argv);
  LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
}


/**
 * Start a process.
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param pipe_stderr pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param argv NULL-terminated array of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_vap (int pipe_control,
                             enum GNUNET_OS_InheritStdioFlags std_inheritance,
                             struct GNUNET_DISK_PipeHandle *pipe_stdin,
                             struct GNUNET_DISK_PipeHandle *pipe_stdout,
                             struct GNUNET_DISK_PipeHandle *pipe_stderr,
                             const char *filename,
                             char *const argv[])
{
  return start_process (pipe_control,
                        std_inheritance,
                        pipe_stdin,
                        pipe_stdout,
                        pipe_stderr,
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
 * @param pipe_stderr pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param va NULL-terminated list of arguments to the process
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_va (int pipe_control,
                            enum GNUNET_OS_InheritStdioFlags std_inheritance,
                            struct GNUNET_DISK_PipeHandle *pipe_stdin,
                            struct GNUNET_DISK_PipeHandle *pipe_stdout,
                            struct GNUNET_DISK_PipeHandle *pipe_stderr,
                            const char *filename,
                            va_list va)
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
  argv = GNUNET_malloc (sizeof(char *) * (argc + 1));
  argc = 0;
  va_copy (ap, va);
  while (NULL != (argv[argc] = va_arg (ap, char *)))
    argc++;
  va_end (ap);
  ret = GNUNET_OS_start_process_vap (pipe_control,
                                     std_inheritance,
                                     pipe_stdin,
                                     pipe_stdout,
                                     pipe_stderr,
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
                         struct GNUNET_DISK_PipeHandle *pipe_stderr,
                         const char *filename,
                         ...)
{
  struct GNUNET_OS_Process *ret;
  va_list ap;

  va_start (ap, filename);
  ret = GNUNET_OS_start_process_va (pipe_control,
                                    std_inheritance,
                                    pipe_stdin,
                                    pipe_stdout,
                                    pipe_stderr,
                                    filename,
                                    ap);
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
                           const int *lsocks,
                           const char *filename,
                           char *const argv[])
{
  return start_process (pipe_control,
                        std_inheritance,
                        NULL,
                        NULL,
                        NULL,
                        lsocks,
                        filename,
                        argv);
}


/**
 * Start a process.  This function is similar to the GNUNET_OS_start_process_*
 * except that the filename and arguments can have whole strings which contain
 * the arguments.  These arguments are to be separated by spaces and are parsed
 * in the order they appear.  Arguments containing spaces can be used by
 * quoting them with @em ".
 *
 * @param pipe_control should a pipe be used to send signals to the child?
 * @param std_inheritance a set of GNUNET_OS_INHERIT_STD_* flags
 * @param lsocks array of listen sockets to dup systemd-style (or NULL);
 *         must be NULL on platforms where dup is not supported
 * @param filename name of the binary.  It is valid to have the arguments
 *         in this string when they are separated by spaces.
 * @param ... more arguments.  Should be of type `char *`.  It is valid
 *         to have the arguments in these strings when they are separated by
 *         spaces.  The last argument MUST be NULL.
 * @return pointer to process structure of the new process, NULL on error
 */
struct GNUNET_OS_Process *
GNUNET_OS_start_process_s (int pipe_control,
                           unsigned int std_inheritance,
                           const int *lsocks,
                           const char *filename,
                           ...)
{
  va_list ap;
  char **argv;
  unsigned int argv_size;
  const char *arg;
  const char *rpos;
  char *pos;
  char *cp;
  const char *last;
  struct GNUNET_OS_Process *proc;
  char *binary_path;
  int quote_on;
  unsigned int i;
  size_t len;

  argv_size = 1;
  va_start (ap, filename);
  arg = filename;
  last = NULL;
  do
  {
    rpos = arg;
    quote_on = 0;
    while ('\0' != *rpos)
    {
      if ('"' == *rpos)
      {
        if (1 == quote_on)
          quote_on = 0;
        else
          quote_on = 1;
      }
      if ((' ' == *rpos) && (0 == quote_on))
      {
        if (NULL != last)
          argv_size++;
        last = NULL;
        rpos++;
        while (' ' == *rpos)
          rpos++;
      }
      if ((NULL == last) && ('\0' != *rpos))     // FIXME: == or !=?
        last = rpos;
      if ('\0' != *rpos)
        rpos++;
    }
    if (NULL != last)
      argv_size++;
  }
  while (NULL != (arg = (va_arg (ap, const char *))));
  va_end (ap);

  argv = GNUNET_malloc (argv_size * sizeof(char *));
  argv_size = 0;
  va_start (ap, filename);
  arg = filename;
  last = NULL;
  do
  {
    cp = GNUNET_strdup (arg);
    quote_on = 0;
    pos = cp;
    while ('\0' != *pos)
    {
      if ('"' == *pos)
      {
        if (1 == quote_on)
          quote_on = 0;
        else
          quote_on = 1;
      }
      if ((' ' == *pos) && (0 == quote_on))
      {
        *pos = '\0';
        if (NULL != last)
          argv[argv_size++] = GNUNET_strdup (last);
        last = NULL;
        pos++;
        while (' ' == *pos)
          pos++;
      }
      if ((NULL == last) && ('\0' != *pos))     // FIXME: == or !=?
        last = pos;
      if ('\0' != *pos)
        pos++;
    }
    if (NULL != last)
      argv[argv_size++] = GNUNET_strdup (last);
    last = NULL;
    GNUNET_free (cp);
  }
  while (NULL != (arg = (va_arg (ap, const char *))));
  va_end (ap);
  argv[argv_size] = NULL;

  for (i = 0; i < argv_size; i++)
  {
    len = strlen (argv[i]);
    if ((argv[i][0] == '"') && (argv[i][len - 1] == '"'))
    {
      memmove (&argv[i][0], &argv[i][1], len - 2);
      argv[i][len - 2] = '\0';
    }
  }
  binary_path = argv[0];
  proc = GNUNET_OS_start_process_v (pipe_control,
                                    std_inheritance,
                                    lsocks,
                                    binary_path,
                                    argv);
  while (argv_size > 0)
    GNUNET_free (argv[--argv_size]);
  GNUNET_free (argv);
  return proc;
}


/**
 * Retrieve the status of a process, waiting on it if dead.
 * Nonblocking version.
 *
 * @param proc process ID
 * @param type status type
 * @param code return code/signal number
 * @param options WNOHANG if non-blocking is desired
 * @return #GNUNET_OK on success, #GNUNET_NO if the process is still running, #GNUNET_SYSERR otherwise
 */
static int
process_status (struct GNUNET_OS_Process *proc,
                enum GNUNET_OS_ProcessStatusType *type,
                unsigned long *code,
                int options)
{
  int status;
  int ret;

  GNUNET_assert (0 != proc);
  ret = waitpid (proc->pid, &status, options);
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

  return GNUNET_OK;
}


/**
 * Retrieve the status of a process, waiting on it if dead.
 * Nonblocking version.
 *
 * @param proc process ID
 * @param type status type
 * @param code return code/signal number
 * @return #GNUNET_OK on success, #GNUNET_NO if the process is still running, #GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_status (struct GNUNET_OS_Process *proc,
                          enum GNUNET_OS_ProcessStatusType *type,
                          unsigned long *code)
{
  return process_status (proc, type, code, WNOHANG);
}


/**
 * Retrieve the status of a process, waiting on it if dead.
 * Blocking version.
 *
 * @param proc pointer to process structure
 * @param type status type
 * @param code return code/signal number
 * @return #GNUNET_OK on success, #GNUNET_NO if the process is still running, #GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_wait_status (struct GNUNET_OS_Process *proc,
                               enum GNUNET_OS_ProcessStatusType *type,
                               unsigned long *code)
{
  return process_status (proc, type, code, 0);
}


/**
 * Wait for a process to terminate. The return code is discarded.
 * You must not use #GNUNET_OS_process_status() on the same process
 * after calling this function!  This function is blocking and should
 * thus only be used if the child process is known to have terminated
 * or to terminate very soon.
 *
 * @param proc pointer to process structure
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_wait (struct GNUNET_OS_Process *proc)
{
  pid_t pid = proc->pid;
  pid_t ret;

  while ((pid != (ret = waitpid (pid, NULL, 0))) && (EINTR == errno))
    ;
  if (pid != ret)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "waitpid");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Buffer for the output.
   */
  char buf[1024];

  /**
   * Task reading from pipe.
   */
  struct GNUNET_SCHEDULER_Task *rtask;

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
    GNUNET_assert (NULL != cmd->rtask);
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
 * @param cls the `struct GNUNET_OS_CommandHandle *`
 */
static void
cmd_read (void *cls)
{
  struct GNUNET_OS_CommandHandle *cmd = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;
  GNUNET_OS_LineProcessor proc;
  char *end;
  ssize_t ret;

  cmd->rtask = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if (GNUNET_YES != GNUNET_NETWORK_fdset_handle_isset (tc->read_ready, cmd->r))
  {
    /* timeout */
    proc = cmd->proc;
    cmd->proc = NULL;
    proc (cmd->proc_cls, NULL);
    return;
  }
  ret = GNUNET_DISK_file_read (cmd->r,
                               &cmd->buf[cmd->off],
                               sizeof(cmd->buf) - cmd->off);
  if (ret <= 0)
  {
    if ((cmd->off > 0) && (cmd->off < sizeof(cmd->buf)))
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
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_absolute_get_remaining (
                                      cmd->timeout),
                                    cmd->r,
                                    &cmd_read,
                                    cmd);
}


/**
 * Run the given command line and call the given function
 * for each line of the output.
 *
 * @param proc function to call for each line of the output
 * @param proc_cls closure for @a proc
 * @param timeout when to time out
 * @param binary command to run
 * @param ... arguments to command
 * @return NULL on error
 */
struct GNUNET_OS_CommandHandle *
GNUNET_OS_command_run (GNUNET_OS_LineProcessor proc,
                       void *proc_cls,
                       struct GNUNET_TIME_Relative timeout,
                       const char *binary,
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
  eip =
    GNUNET_OS_start_process_va (GNUNET_NO, 0, NULL, opipe, NULL, binary, ap);
  va_end (ap);
  if (NULL == eip)
  {
    GNUNET_DISK_pipe_close (opipe);
    return NULL;
  }
  GNUNET_DISK_pipe_close_end (opipe, GNUNET_DISK_PIPE_END_WRITE);
  cmd = GNUNET_new (struct GNUNET_OS_CommandHandle);
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

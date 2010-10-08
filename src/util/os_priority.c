/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "disk.h"

#if WINDOWS
#include "gnunet_signal_lib.h"

extern GNUNET_SIGNAL_Handler w32_sigchld_handler;

/**
 * @brief Waits for a process to terminate and invokes the SIGCHLD handler
 * @param h handle to the process
 */
static DWORD WINAPI
ChildWaitThread (HANDLE h)
{
  WaitForSingleObject (h, INFINITE);

  if (w32_sigchld_handler)
    w32_sigchld_handler ();

  CloseHandle (h);
  return 0;
}
#endif

/**
 * Set process priority
 *
 * @param proc id of the process
 * @param prio priority value
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_OS_set_process_priority (pid_t proc,
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
  SetPriorityClass (GetCurrentProcess (), rprio);
#elif LINUX 
  if ( (0 == proc) ||
       (proc == getpid () ) )
    {
      int have = nice (0);
      int delta = rprio - have;
      errno = 0;
      if ( (delta != 0) &&
	   (rprio == nice (delta)) && 
	   (errno != 0) )
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING |
                               GNUNET_ERROR_TYPE_BULK, "nice");
          return GNUNET_SYSERR;
        }
    }
  else
    {
      if (0 != setpriority (PRIO_PROCESS, proc, rprio))

        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING |
                               GNUNET_ERROR_TYPE_BULK, "setpriority");
          return GNUNET_SYSERR;
        }
    }
#else
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
	      "Priority management not availabe for this platform\n");
#endif
  return GNUNET_OK;
}

/**
 * Start a process.
 *
 * @param pipe_stdin pipe to use to send input to child process (or NULL)
 * @param pipe_stdout pipe to use to get output from child process (or NULL)
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 * @return process ID of the new process, -1 on error
 */
pid_t
GNUNET_OS_start_process (struct GNUNET_DISK_PipeHandle *pipe_stdin, 
			 struct GNUNET_DISK_PipeHandle *pipe_stdout,
			 const char *filename, ...)
{
  /* FIXME:  Make this work on windows!!! */
  va_list ap;

#ifndef MINGW
  pid_t ret;
  char **argv;
  int argc;
  int fd_stdout_write;
  int fd_stdout_read;
  int fd_stdin_read;
  int fd_stdin_write;

  argc = 0;
  va_start (ap, filename);
  while (NULL != va_arg (ap, char *))
      argc++;
  va_end (ap);
  argv = GNUNET_malloc (sizeof (char *) * (argc + 1));
  argc = 0;
  va_start (ap, filename);
  while (NULL != (argv[argc] = va_arg (ap, char *)))
    argc++;
  va_end (ap);
  if (pipe_stdout != NULL)
    {
      GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(pipe_stdout, GNUNET_DISK_PIPE_END_WRITE), &fd_stdout_write, sizeof (int));
      GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(pipe_stdout, GNUNET_DISK_PIPE_END_READ), &fd_stdout_read, sizeof (int));
    }
  if (pipe_stdin != NULL)
    {
      GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(pipe_stdin, GNUNET_DISK_PIPE_END_READ), &fd_stdin_read, sizeof (int));
      GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(pipe_stdin, GNUNET_DISK_PIPE_END_WRITE), &fd_stdin_write, sizeof (int));
    }

#if HAVE_WORKING_VFORK
  ret = vfork ();
#else
  ret = fork ();
#endif
  if (ret != 0)
    {
      if (ret == -1)
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
        }
      else
        {

#if HAVE_WORKING_VFORK
          /* let's hope vfork actually works; for some extreme cases (including
             a testcase) we need 'execvp' to have run before we return, since
             we may send a signal to the process next and we don't want it
             to be caught by OUR signal handler (but either by the default
             handler or the actual handler as installed by the process itself). */
#else
          /* let's give the child process a chance to run execvp, 1s should
             be plenty in practice */
          if (pipe_stdout != NULL)
            GNUNET_DISK_pipe_close_end(pipe_stdout, GNUNET_DISK_PIPE_END_WRITE);
          if (pipe_stdin != NULL)
            GNUNET_DISK_pipe_close_end(pipe_stdin, GNUNET_DISK_PIPE_END_READ);
          sleep (1);
#endif
        }
      GNUNET_free (argv);
      return ret;
    }

  if (pipe_stdout != NULL)
    {
      GNUNET_break (0 == close (fd_stdout_read));
      if (-1 == dup2(fd_stdout_write, 1))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "dup2");	
      GNUNET_break (0 == close (fd_stdout_write));
    }

  if (pipe_stdin != NULL)
    {

      GNUNET_break (0 == close (fd_stdin_write));
      if (-1 == dup2(fd_stdin_read, 0))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "dup2");	
      GNUNET_break (0 == close (fd_stdin_read));
    }
  execvp (filename, argv);
  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  char *arg;
  unsigned int cmdlen;
  char *cmd, *idx;
  int findresult;
  STARTUPINFO start;
  PROCESS_INFORMATION proc;

  HANDLE stdin_handle;
  HANDLE stdout_handle;

  char path[MAX_PATH + 1];

  cmdlen = 0;
  va_start (ap, filename);
  while (NULL != (arg = va_arg (ap, char *)))
      cmdlen = cmdlen + strlen (arg) + 3;
  va_end (ap);

  cmd = idx = GNUNET_malloc (sizeof (char) * (cmdlen + 1));
  va_start (ap, filename);
  while (NULL != (arg = va_arg (ap, char *)))
      idx += sprintf (idx, "\"%s\" ", arg);
  va_end (ap);

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  if ((pipe_stdin != NULL) || (pipe_stdout != NULL))
    start.dwFlags |= STARTF_USESTDHANDLES;

  if (pipe_stdin != NULL)
    {
      GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(pipe_stdin, GNUNET_DISK_PIPE_END_READ), &stdin_handle, sizeof (HANDLE));
      start.hStdInput = stdin_handle;
    }

  if (pipe_stdout != NULL)
    {
      GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(pipe_stdout, GNUNET_DISK_PIPE_END_WRITE), &stdout_handle, sizeof (HANDLE));
      start.hStdOutput = stdout_handle;
    }

  findresult = (int) FindExecutableA (filename, NULL, path);
  if (findresult <= 32) 
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "FindExecutable", filename);
      return -1;
    }

  if (!CreateProcessA
      (path, cmd, NULL, NULL, TRUE, DETACHED_PROCESS, NULL, NULL, &start,
       &proc))
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "CreateProcess", path);
      return -1;
    }

  CreateThread (NULL, 64000, ChildWaitThread, proc.hProcess, 0, NULL);

  CloseHandle (proc.hThread);

  GNUNET_free (cmd);

  return proc.dwProcessId;
#endif

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
pid_t
GNUNET_OS_start_process_v (const int *lsocks,
			   const char *filename, char *const argv[])
{
#ifndef MINGW
  pid_t ret;
  char lpid[16];
  char fds[16];
  int i;
  int j;
  int k;
  int tgt;
  int flags;
  int *lscp;
  unsigned int ls;    

  lscp = NULL;
  ls = 0;
  if (lsocks != NULL)
    {
      i = 0;
      while (-1 != (k = lsocks[i++]))
	{
	  flags = fcntl (k, F_GETFD);
	  GNUNET_assert (flags >= 0);
	  flags &= ~FD_CLOEXEC;
	  (void) fcntl (k, F_SETFD, flags);
	  GNUNET_array_append (lscp, ls, k);
	}
      GNUNET_array_append (lscp, ls, -1);
    }
#if HAVE_WORKING_VFORK
  ret = vfork ();
#else
  ret = fork ();
#endif
  if (ret != 0)
    {
      if (ret == -1)
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
        }
      else
        {
#if HAVE_WORKING_VFORK
          /* let's hope vfork actually works; for some extreme cases (including
             a testcase) we need 'execvp' to have run before we return, since
             we may send a signal to the process next and we don't want it
             to be caught by OUR signal handler (but either by the default
             handler or the actual handler as installed by the process itself). */
#else
          /* let's give the child process a chance to run execvp, 1s should
             be plenty in practice */
          sleep (1);
#endif
        }
      GNUNET_array_grow (lscp, ls, 0);
      return ret;
    }
  if (lscp != NULL)
    {
      /* read systemd documentation... */
      GNUNET_snprintf (lpid, sizeof (lpid), "%u", getpid());
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
		 on exec anyway and the important onces have been dup'ed away */
	      (void) close (tgt);	      
	      GNUNET_assert (-1 != dup2 (lscp[i], tgt));
	    }
	  /* set close-on-exec flag */
	  flags = fcntl (tgt, F_GETFD);
	  GNUNET_assert (flags >= 0);
	  flags &= ~FD_CLOEXEC;
	  (void) fcntl (tgt, F_SETFD, flags);
	  tgt++;
	  i++;
	}
      GNUNET_snprintf (fds, sizeof (fds), "%u", i);
      setenv ("LISTEN_FDS", fds, 1); 
    }
  GNUNET_array_grow (lscp, ls, 0);
  execvp (filename, argv);
  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  char **arg, **non_const_argv;
  unsigned int cmdlen;
  char *cmd, *idx;
  STARTUPINFO start;
  PROCESS_INFORMATION proc;
  int argcount = 0;
  char *non_const_filename = NULL;
  int filenamelen = 0;

  GNUNET_assert (lsocks == NULL);
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
      non_const_argv[argcount] = GNUNET_strdup (*arg);
      arg++;
      argcount++;
    }
  non_const_argv[argcount] = NULL;

  /* Fix .exe extension */
  filenamelen = strlen (filename);
  if (filenamelen <= 4 || stricmp (&filename[filenamelen - 4], ".exe") != 0)
  {
    non_const_filename = GNUNET_malloc (sizeof (char) * (filenamelen + 4 + 1));
    non_const_filename = strcpy (non_const_filename, non_const_argv[0]);
    strcat (non_const_filename, ".exe");
    GNUNET_free (non_const_argv[0]);
    non_const_argv[0] = non_const_filename;
  }
  else
    non_const_filename = non_const_argv[0];

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

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  if (!CreateProcess
      (non_const_filename, cmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &start,
       &proc))
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
      return -1;
    }

  CreateThread (NULL, 64000, ChildWaitThread, proc.hProcess, 0, NULL);

  CloseHandle (proc.hThread);
  GNUNET_free (cmd);

  while (argcount > 0)
    GNUNET_free (non_const_argv[--argcount]);
  GNUNET_free (non_const_argv);

  return proc.dwProcessId;
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
GNUNET_OS_process_status (pid_t proc, enum GNUNET_OS_ProcessStatusType *type,
                          unsigned long *code)
{
#ifndef MINGW
  int status;
  int ret;

  GNUNET_assert (0 != proc);
  ret = waitpid (proc, &status, WNOHANG);
  if (ret < 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
      return GNUNET_SYSERR;
    }
  if (0 == ret)
    {
      *type = GNUNET_OS_PROCESS_RUNNING;
      *code = 0;
      return GNUNET_NO;
    }
  if (proc != ret)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
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
  DWORD c;

  h = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, proc);
  if (INVALID_HANDLE_VALUE == h)
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "OpenProcess");
      return GNUNET_SYSERR;
    }

  c = GetExitCodeProcess ((HANDLE) proc, &c);
  if (STILL_ACTIVE == c)
    {
      *type = GNUNET_OS_PROCESS_RUNNING;
      *code = 0;
      CloseHandle (h);
      return GNUNET_NO;
    }
  *type = GNUNET_OS_PROCESS_EXITED;
  *code = c;
  CloseHandle (h);
#endif

  return GNUNET_OK;
}

/**
 * Wait for a process
 * @param proc process ID to wait for
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_OS_process_wait (pid_t proc)
{
#ifndef MINGW
  if (proc != waitpid (proc, NULL, 0))
    return GNUNET_SYSERR;

  return GNUNET_OK;
#else
  HANDLE h;
  int ret;

  h = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, proc);
  if (INVALID_HANDLE_VALUE == h)
    {
      SetErrnoFromWinError (GetLastError ());
      return GNUNET_SYSERR;
    }

  if (WAIT_OBJECT_0 != WaitForSingleObject (h, INFINITE))
    {
      SetErrnoFromWinError (GetLastError ());
      ret = GNUNET_SYSERR;
    }
  else
    ret = GNUNET_OK;

  CloseHandle (h);

  return ret;
#endif
}


/* end of os_priority.c */

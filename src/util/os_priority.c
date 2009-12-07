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
  int rprio = 0;

  GNUNET_assert (prio < GNUNET_SCHEDULER_PRIORITY_COUNT);
  if (prio == GNUNET_SCHEDULER_PRIORITY_KEEP)
    return GNUNET_OK;
  /* convert to MINGW/Unix values */
  switch (prio)
    {
    case GNUNET_SCHEDULER_PRIORITY_DEFAULT:
#ifdef MINGW
      rprio = NORMAL_PRIORITY_CLASS;
#else
      rprio = 0;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_HIGH:
#ifdef MINGW
      rprio = ABOVE_NORMAL_PRIORITY_CLASS;
#else
      rprio = -5;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_BACKGROUND:
#ifdef MINGW
      rprio = BELOW_NORMAL_PRIORITY_CLASS;
#else
      rprio = 10;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_UI:
    case GNUNET_SCHEDULER_PRIORITY_URGENT:
#ifdef MINGW
      rprio = HIGH_PRIORITY_CLASS;
#else
      rprio = -10;
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
#else
  if (proc == getpid ())
    {
      errno = 0;
      if ((-1 == nice (rprio)) && (errno != 0))
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
#endif
  return GNUNET_OK;
}


/**
 * Start a process.
 *
 * @param filename name of the binary
 * @param ... NULL-terminated list of arguments to the process
 * @return process ID of the new process, -1 on error
 */
pid_t
GNUNET_OS_start_process (const char *filename, ...)
{
  va_list ap;

#ifndef MINGW
  pid_t ret;
  char **argv;
  int argc;

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
      return ret;
    }
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
  execvp (filename, argv);
  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  char *arg;
  unsigned int cmdlen;
  char *cmd, *idx;
  STARTUPINFO start;
  PROCESS_INFORMATION proc;
  char *fn;
  int len;

  cmdlen = 0;
  va_start (ap, filename);
  while (NULL != (arg = va_arg (ap, char *)))
      cmdlen = cmdlen + strlen (arg) + 3;
  va_end (ap);

  cmd = idx = GNUNET_malloc (sizeof (char) * cmdlen);
  va_start (ap, filename);
  while (NULL != (arg = va_arg (ap, char *)))
      idx += sprintf (idx, "\"%s\" ", arg);
  va_end (ap);

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  len = strlen (filename);
  if (strnicmp (filename + len - 4, ".exe", 4) == 0)
    fn = filename;
  else
    GNUNET_asprintf (&fn, "%s.exe", filename);

  if (!CreateProcess
      (fn, cmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &start,
       &proc))
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "CreateProcess", fn);
      return -1;
    }
  if (fn != filename)
    GNUNET_free (fn);
  CloseHandle (proc.hProcess);
  CloseHandle (proc.hThread);

  GNUNET_free (cmd);

  return proc.dwProcessId;
#endif
}




/**
 * Start a process.
 *
 * @param filename name of the binary
 * @param argv NULL-terminated list of arguments to the process
 * @return process ID of the new process, -1 on error
 */
pid_t
GNUNET_OS_start_process_v (const char *filename, char *const argv[])
{
#ifndef MINGW
  pid_t ret;

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
      return ret;
    }
  execvp (filename, argv);
  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  _exit (1);
#else
  char **arg;
  unsigned int cmdlen;
  char *cmd, *idx;
  STARTUPINFO start;
  PROCESS_INFORMATION proc;

  cmdlen = 0;
  arg = argv;
  while (*arg)
    {
      cmdlen = cmdlen + strlen (*arg) + 3;
      arg++;
    }

  cmd = idx = GNUNET_malloc (sizeof (char) * cmdlen);
  arg = argv;
  while (*arg)
    {
      idx += sprintf (idx, "\"%s\" ", *arg);
      arg++;
    }

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  if (!CreateProcess
      (filename, cmd, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &start,
       &proc))
    {
      SetErrnoFromWinError (GetLastError ());
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
      return -1;
    }
  CloseHandle (proc.hProcess);
  CloseHandle (proc.hThread);

  GNUNET_free (cmd);

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

  c = GetExitCodeProcess (proc, &c);
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
  DWORD c;
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

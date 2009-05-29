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
 * @file util/os/priority.c
 * @brief Methods to set process priority
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_os_lib.h"

/**
 * Set our process priority
 */
int
GNUNET_OS_set_process_priority (pid_t proc,
                                enum GNUNET_SCHEDULER_Priority eprio)
{
  int prio = 0;

  GNUNET_assert (eprio < GNUNET_SCHEDULER_PRIORITY_COUNT);
  if (eprio == GNUNET_SCHEDULER_PRIORITY_KEEP)
    return GNUNET_OK;
  /* convert to MINGW/Unix values */
  switch (eprio)
    {
    case GNUNET_SCHEDULER_PRIORITY_DEFAULT:
#ifdef MINGW
      prio = NORMAL_PRIORITY_CLASS;
#else
      prio = 0;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_HIGH:
#ifdef MINGW
      prio = ABOVE_NORMAL_PRIORITY_CLASS;
#else
      prio = -5;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_BACKGROUND:
#ifdef MINGW
      prio = BELOW_NORMAL_PRIORITY_CLASS;
#else
      prio = 10;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_UI:
    case GNUNET_SCHEDULER_PRIORITY_URGENT:
#ifdef MINGW
      prio = HIGH_PRIORITY_CLASS;
#else
      prio = -10;
#endif
      break;
    case GNUNET_SCHEDULER_PRIORITY_IDLE:
#ifdef MINGW
      prio = IDLE_PRIORITY_CLASS;
#else
      prio = 19;
#endif
      break;
    default:
      GNUNET_assert (0);
      return GNUNET_SYSERR;
    }
  /* Set process priority */
#ifdef MINGW
  SetPriorityClass (GetCurrentProcess (), prio);
#else
  if (proc == getpid ())
    {
      errno = 0;
      if ((-1 == nice (prio)) && (errno != 0))
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING |
                               GNUNET_ERROR_TYPE_BULK, "nice");
          return GNUNET_SYSERR;
        }
    }
  else
    {
      if (0 != setpriority (PRIO_PROCESS, proc, prio))

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
  pid_t ret;
  char **argv;
  va_list ap;
  int argc;

  ret = fork ();
  if (ret != 0)
    {
      if (ret == -1)
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
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
  exit (1);
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
  pid_t ret;

  ret = fork ();
  if (ret != 0)
    {
      if (ret == -1)
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
      return ret;
    }
  execvp (filename, argv);
  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "execvp", filename);
  exit (1);
}






/* end of os_priority.c */

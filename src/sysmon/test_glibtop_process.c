/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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
 * @file sysmon/test_glibtop_process.c
 * @brief a brief test for glibtop
 * @author Matthias Wachs
 */

#include "platform.h"

#include <glibtop.h>
#include <glibtop/proclist.h>
#include <glibtop/procstate.h>
#include <glibtop/procargs.h>
#include <glibtop/procmem.h>
#include <glibtop/proctime.h>

static int ret;

static void print_pids(guint64 which, guint64 arg)
{
    pid_t *pids = NULL;
    unsigned i;
    glibtop_proclist proc_list;
    glibtop_proc_args proc_args;
    glibtop_proc_mem proc_mem;
    glibtop_proc_time proc_time;
    char *argss;

    /* get process list */
    pids = glibtop_get_proclist(&proc_list, which, arg);
    if (NULL == pids)
    {
      fprintf (stderr, "Could not retrieve process list!\n");
      ret = 1;
      return;
    }

    printf("Found %lu processes\n", (unsigned long) proc_list.number);
    for (i = 0; i < proc_list.number; ++i)
    {
        printf("PID %u:\n", pids[i]);

        /* get process args */
        argss = glibtop_get_proc_args (&proc_args, pids[i], 1024);
        if (NULL == argss)
        {
          fprintf (stderr, "Could not retrieve process args!\n");
          ret = 1;
          return;
        }
        printf ("\targument string: %s\n", argss);
        g_free (argss);

        /* get memory info */
        glibtop_get_proc_mem (&proc_mem, pids[i]);
        printf ("\tMemory information:\n");
        printf ("\t%-50s: %llu\n", "total # of pages of memory", (long long unsigned int) proc_mem.size);
        printf ("\t%-50s: %llu\n", "number of pages of virtual memory", (long long unsigned int) proc_mem.vsize);
        printf ("\t%-50s: %llu\n", "number of resident set", (long long unsigned int) proc_mem.resident);
        printf ("\t%-50s: %llu\n", "number of pages of shared (mmap'd) memory", (long long unsigned int) proc_mem.share);
        printf ("\t%-50s: %llu\n", "resident set size", (long long unsigned int) proc_mem.rss);

        /* get time info */
        glibtop_get_proc_time (&proc_time, pids[i]);
        printf ("\tTime information:\n");
        printf ("\t%-50s: %llu\n", "real time accumulated by process", (long long unsigned int) proc_time.rtime);
        printf ("\t%-50s: %llu\n", "user-mode CPU time accumulated by process", (long long unsigned int) proc_time.utime);
        printf ("\t%-50s: %llu\n", "kernel-mode CPU time accumulated by process", (long long unsigned int) proc_time.stime);
    }

    if (NULL != pids)
    {
      g_free(pids);
      pids = NULL;
    }
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  if (NULL == glibtop_init())
  {
    fprintf (stderr, "Could not init gliptop!\n");
    return 1;
  }

  /* Print all processes */
  print_pids(GLIBTOP_KERN_PROC_ALL, 0);

  glibtop_close();
  return ret;
}

/* end of test_glibtop_process.c */


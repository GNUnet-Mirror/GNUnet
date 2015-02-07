/*
     This file is part of GNUnet.
     Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_cpustatus.c
 * @brief calls to determine current CPU load
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 * @author Igor Wronsky
 * @author Alex Harper (OS X portion)
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-testbed_meminfo.h"

#if SOLARIS
#if HAVE_KSTAT_H
#include <kstat.h>
#endif
#if HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif
#if SOMEBSD
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif

#ifdef OSX
#include <mach/mach.h>

static processor_cpu_load_info_t prev_cpu_load;
#endif
#ifdef WINDOWS
#include <winternl.h>
#endif

#define DEBUG_STATUSCALLS GNUNET_NO

#ifdef LINUX
static FILE *proc_stat;
#endif

/**
 * Current CPU load, as percentage of CPU cycles not idle or
 * blocked on IO.
 */
static int currentCPULoad;

static double agedCPULoad = -1;

/**
 * Current IO load, as percentage of CPU cycles blocked on IO.
 */
static int currentIOLoad;

static double agedIOLoad = -1;


/**
 * hanlde to the file to write the load statistics to
 */
struct GNUNET_BIO_WriteHandle *bw;

struct GNUNET_SCHEDULER_Task * sample_load_task_id;


#ifdef OSX
static int
initMachCpuStats ()
{
  unsigned int cpu_count;
  processor_cpu_load_info_t cpu_load;
  mach_msg_type_number_t cpu_msg_count;
  kern_return_t kret;
  int i, j;

  kret = host_processor_info (mach_host_self (),
                              PROCESSOR_CPU_LOAD_INFO,
                              &cpu_count,
                              (processor_info_array_t *) & cpu_load,
                              &cpu_msg_count);
  if (kret != KERN_SUCCESS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "host_processor_info failed.");
      return GNUNET_SYSERR;
    }
  prev_cpu_load = GNUNET_malloc (cpu_count * sizeof (*prev_cpu_load));
  for (i = 0; i < cpu_count; i++)
    {
      for (j = 0; j < CPU_STATE_MAX; j++)
        {
          prev_cpu_load[i].cpu_ticks[j] = cpu_load[i].cpu_ticks[j];
        }
    }
  vm_deallocate (mach_task_self (),
                 (vm_address_t) cpu_load,
                 (vm_size_t) (cpu_msg_count * sizeof (*cpu_load)));
  return GNUNET_OK;
}
#endif

/**
 * Update the currentCPU and currentIO load (and on Linux, memory) values.
 *
 * Before its first invocation the method initStatusCalls() must be called.
 * If there is an error the method returns -1.
 */
static int
updateUsage ()
{
  currentIOLoad = -1;
  currentCPULoad = -1;
#ifdef LINUX
  /* under linux, first try %idle/usage using /proc/stat;
     if that does not work, disable /proc/stat for the future
     by closing the file and use the next-best method. */
  if (proc_stat != NULL)
    {
      static unsigned long long last_cpu_results[5] = { 0, 0, 0, 0, 0 };
      static int have_last_cpu = GNUNET_NO;
      int ret;
      char line[256];
      unsigned long long user_read, system_read, nice_read, idle_read,
        iowait_read;
      unsigned long long user, system, nice, idle, iowait;
      unsigned long long usage_time = 0, total_time = 1;

      /* Get the first line with the data */
      rewind (proc_stat);
      fflush (proc_stat);
      if (NULL == fgets (line, 256, proc_stat))
        {
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                    "fgets", "/proc/stat");
          proc_stat = NULL;     /* don't try again */
        }
      else
        {
          iowait_read = 0;
          ret = sscanf (line, "%*s %llu %llu %llu %llu %llu",
                        &user_read,
                        &system_read, &nice_read, &idle_read, &iowait_read);
          if (ret < 4)
            {
              GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                        "fgets-sscanf", "/proc/stat");
              fclose (proc_stat);
              proc_stat = NULL; /* don't try again */
              have_last_cpu = GNUNET_NO;
            }
          else
            {
              /* Store the current usage */
              user = user_read - last_cpu_results[0];
              system = system_read - last_cpu_results[1];
              nice = nice_read - last_cpu_results[2];
              idle = idle_read - last_cpu_results[3];
              iowait = iowait_read - last_cpu_results[4];
              /* Calculate the % usage */
              usage_time = user + system + nice;
              total_time = usage_time + idle + iowait;
              if ((total_time > 0) && (have_last_cpu == GNUNET_YES))
                {
                  currentCPULoad = (int) (100L * usage_time / total_time);
                  if (ret > 4)
                    currentIOLoad = (int) (100L * iowait / total_time);
                  else
                    currentIOLoad = -1; /* 2.4 kernel */
                }
              /* Store the values for the next calculation */
              last_cpu_results[0] = user_read;
              last_cpu_results[1] = system_read;
              last_cpu_results[2] = nice_read;
              last_cpu_results[3] = idle_read;
              last_cpu_results[4] = iowait_read;
              have_last_cpu = GNUNET_YES;
              return GNUNET_OK;
            }
        }
    }
#endif

#ifdef OSX
  {
    unsigned int cpu_count;
    processor_cpu_load_info_t cpu_load;
    mach_msg_type_number_t cpu_msg_count;
    unsigned long long t_sys, t_user, t_nice, t_idle, t_total;
    unsigned long long t_idle_all, t_total_all;
    kern_return_t kret;
    int i, j;

    t_idle_all = t_total_all = 0;
    kret = host_processor_info (mach_host_self (), PROCESSOR_CPU_LOAD_INFO,
                                &cpu_count,
                                (processor_info_array_t *) & cpu_load,
                                &cpu_msg_count);
    if (kret == KERN_SUCCESS)
      {
        for (i = 0; i < cpu_count; i++)
          {
            if (cpu_load[i].cpu_ticks[CPU_STATE_SYSTEM] >=
                prev_cpu_load[i].cpu_ticks[CPU_STATE_SYSTEM])
              {
                t_sys = cpu_load[i].cpu_ticks[CPU_STATE_SYSTEM] -
                  prev_cpu_load[i].cpu_ticks[CPU_STATE_SYSTEM];
              }
            else
              {
                t_sys = cpu_load[i].cpu_ticks[CPU_STATE_SYSTEM] +
                  (ULONG_MAX - prev_cpu_load[i].cpu_ticks[CPU_STATE_SYSTEM] +
                   1);
              }

            if (cpu_load[i].cpu_ticks[CPU_STATE_USER] >=
                prev_cpu_load[i].cpu_ticks[CPU_STATE_USER])
              {
                t_user = cpu_load[i].cpu_ticks[CPU_STATE_USER] -
                  prev_cpu_load[i].cpu_ticks[CPU_STATE_USER];
              }
            else
              {
                t_user = cpu_load[i].cpu_ticks[CPU_STATE_USER] +
                  (ULONG_MAX - prev_cpu_load[i].cpu_ticks[CPU_STATE_USER] +
                   1);
              }

            if (cpu_load[i].cpu_ticks[CPU_STATE_NICE] >=
                prev_cpu_load[i].cpu_ticks[CPU_STATE_NICE])
              {
                t_nice = cpu_load[i].cpu_ticks[CPU_STATE_NICE] -
                  prev_cpu_load[i].cpu_ticks[CPU_STATE_NICE];
              }
            else
              {
                t_nice = cpu_load[i].cpu_ticks[CPU_STATE_NICE] +
                  (ULONG_MAX - prev_cpu_load[i].cpu_ticks[CPU_STATE_NICE] +
                   1);
              }

            if (cpu_load[i].cpu_ticks[CPU_STATE_IDLE] >=
                prev_cpu_load[i].cpu_ticks[CPU_STATE_IDLE])
              {
                t_idle = cpu_load[i].cpu_ticks[CPU_STATE_IDLE] -
                  prev_cpu_load[i].cpu_ticks[CPU_STATE_IDLE];
              }
            else
              {
                t_idle = cpu_load[i].cpu_ticks[CPU_STATE_IDLE] +
                  (ULONG_MAX - prev_cpu_load[i].cpu_ticks[CPU_STATE_IDLE] +
                   1);
              }
            t_total = t_sys + t_user + t_nice + t_idle;
            t_idle_all += t_idle;
            t_total_all += t_total;
          }
        for (i = 0; i < cpu_count; i++)
          {
            for (j = 0; j < CPU_STATE_MAX; j++)
              {
                prev_cpu_load[i].cpu_ticks[j] = cpu_load[i].cpu_ticks[j];
              }
          }
        if (t_total_all > 0)
          currentCPULoad = 100 - (100 * t_idle_all) / t_total_all;
        else
          currentCPULoad = -1;
        vm_deallocate (mach_task_self (),
                       (vm_address_t) cpu_load,
                       (vm_size_t) (cpu_msg_count * sizeof (*cpu_load)));
        currentIOLoad = -1;     /* FIXME-OSX! */
        return GNUNET_OK;
      }
    else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "host_processor_info failed.");
        return GNUNET_SYSERR;
      }
  }
#endif
  /* try kstat (Solaris only) */
#if SOLARIS && HAVE_KSTAT_H && HAVE_SYS_SYSINFO_H
  {
    static long long last_idlecount;
    static long long last_totalcount;
    static int kstat_once;      /* if open fails, don't keep
                                   trying */
    kstat_ctl_t *kc;
    kstat_t *khelper;
    long long idlecount;
    long long totalcount;
    long long deltaidle;
    long long deltatotal;

    if (kstat_once == 1)
      goto ABORT_KSTAT;
    kc = kstat_open ();
    if (kc == NULL)
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kstat_close");
        goto ABORT_KSTAT;
      }

    idlecount = 0;
    totalcount = 0;
    for (khelper = kc->kc_chain; khelper != NULL; khelper = khelper->ks_next)
      {
        cpu_stat_t stats;

        if (0 != strncmp (khelper->ks_name, "cpu_stat", strlen ("cpu_stat")))
          continue;
        if (khelper->ks_data_size > sizeof (cpu_stat_t))
          continue;             /* better save then sorry! */
        if (-1 != kstat_read (kc, khelper, &stats))
          {
            idlecount += stats.cpu_sysinfo.cpu[CPU_IDLE];
            totalcount
              += stats.cpu_sysinfo.cpu[CPU_IDLE] +
              stats.cpu_sysinfo.cpu[CPU_USER] +
              stats.cpu_sysinfo.cpu[CPU_KERNEL] +
              stats.cpu_sysinfo.cpu[CPU_WAIT];
          }
      }
    if (0 != kstat_close (kc))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kstat_close");
    if ((idlecount == 0) && (totalcount == 0))
      goto ABORT_KSTAT;         /* no stats found => abort */
    deltaidle = idlecount - last_idlecount;
    deltatotal = totalcount - last_totalcount;
    if ((deltatotal > 0) && (last_totalcount > 0))
      {
        currentCPULoad = (unsigned int) (100.0 * deltaidle / deltatotal);
        if (currentCPULoad > 100)
          currentCPULoad = 100; /* odd */
        if (currentCPULoad < 0)
          currentCPULoad = 0;   /* odd */
        currentCPULoad = 100 - currentCPULoad;  /* computed idle-load before! */
      }
    else
      currentCPULoad = -1;
    currentIOLoad = -1;         /* FIXME-SOLARIS! */
    last_idlecount = idlecount;
    last_totalcount = totalcount;
    return GNUNET_OK;
  ABORT_KSTAT:
    kstat_once = 1;             /* failed, don't try again */
    return GNUNET_SYSERR;
  }
#endif

  /* insert methods better than getloadavg for
     other platforms HERE! */

  /* ok, maybe we have getloadavg on this platform */
#if HAVE_GETLOADAVG
  {
    static int warnOnce = 0;
    double loadavg;
    if (1 != getloadavg (&loadavg, 1))
      {
        /* only warn once, if there is a problem with
           getloadavg, we're going to hit it frequently... */
        if (warnOnce == 0)
          {
            warnOnce = 1;
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "getloadavg");
          }
        return GNUNET_SYSERR;
      }
    else
      {
        /* success with getloadavg */
        currentCPULoad = (int) (100 * loadavg);
        currentIOLoad = -1;     /* FIXME */
        return GNUNET_OK;
      }
  }
#endif

#if MINGW
  /* Win NT? */
  if (GNNtQuerySystemInformation)
    {
      static double dLastKernel;
      static double dLastIdle;
      static double dLastUser;
      double dKernel;
      double dIdle;
      double dUser;
      double dDiffKernel;
      double dDiffIdle;
      double dDiffUser;
      SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION theInfo;

      if (GNNtQuerySystemInformation (SystemProcessorPerformanceInformation,
                                      &theInfo,
                                      sizeof (theInfo), NULL) == NO_ERROR)
        {
          /* PORT-ME MINGW: Multi-processor? */
          dKernel = Li2Double (theInfo.KernelTime);
          dIdle = Li2Double (theInfo.IdleTime);
          dUser = Li2Double (theInfo.UserTime);
          dDiffKernel = dKernel - dLastKernel;
          dDiffIdle = dIdle - dLastIdle;
          dDiffUser = dUser - dLastUser;

          if (((dDiffKernel + dDiffUser) > 0) &&
              (dLastIdle + dLastKernel + dLastUser > 0))
            currentCPULoad =
              100.0 - (dDiffIdle / (dDiffKernel + dDiffUser)) * 100.0;
          else
            currentCPULoad = -1;        /* don't know (yet) */

          dLastKernel = dKernel;
          dLastIdle = dIdle;
          dLastUser = dUser;

          currentIOLoad = -1;   /* FIXME-MINGW */
          return GNUNET_OK;
        }
      else
        {
          /* only warn once, if there is a problem with
             NtQuery..., we're going to hit it frequently... */
          static int once;
          if (once == 0)
            {
              once = 1;
              GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                          "Cannot query the CPU usage (Windows NT).\n");
            }
          return GNUNET_SYSERR;
        }
    }
  else
    {                           /* Win 9x */
      HKEY hKey;
      DWORD dwDataSize, dwType, dwDummy;

      /* Start query */
      if (RegOpenKeyEx (HKEY_DYN_DATA,
                        "PerfStats\\StartSrv",
                        0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        {
          /* only warn once */
          static int once = 0;
          if (once == 0)
            {
              once = 1;
              GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                          "Cannot query the CPU usage (Win 9x)\n");
            }
        }

      RegOpenKeyEx (HKEY_DYN_DATA,
                    "PerfStats\\StartStat", 0, KEY_ALL_ACCESS, &hKey);
      dwDataSize = sizeof (dwDummy);
      RegQueryValueEx (hKey,
                       "KERNEL\\CPUUsage",
                       NULL, &dwType, (LPBYTE) & dwDummy, &dwDataSize);
      RegCloseKey (hKey);

      /* Get CPU usage */
      RegOpenKeyEx (HKEY_DYN_DATA,
                    "PerfStats\\StatData", 0, KEY_ALL_ACCESS, &hKey);
      dwDataSize = sizeof (currentCPULoad);
      RegQueryValueEx (hKey,
                       "KERNEL\\CPUUsage",
                       NULL, &dwType, (LPBYTE) & currentCPULoad, &dwDataSize);
      RegCloseKey (hKey);
      currentIOLoad = -1;       /* FIXME-MINGW! */

      /* Stop query */
      RegOpenKeyEx (HKEY_DYN_DATA,
                    "PerfStats\\StopStat", 0, KEY_ALL_ACCESS, &hKey);
      RegOpenKeyEx (HKEY_DYN_DATA,
                    "PerfStats\\StopSrv", 0, KEY_ALL_ACCESS, &hKey);
      dwDataSize = sizeof (dwDummy);
      RegQueryValueEx (hKey,
                       "KERNEL\\CPUUsage",
                       NULL, &dwType, (LPBYTE) & dwDummy, &dwDataSize);
      RegCloseKey (hKey);

      return GNUNET_OK;
    }
#endif

  /* loadaverage not defined and no platform
     specific alternative defined
     => default: error
   */
  return GNUNET_SYSERR;
}


/**
 * Update load values (if enough time has expired),
 * including computation of averages.  Code assumes
 * that lock has already been obtained.
 */
static void
updateAgedLoad ()
{
  static struct GNUNET_TIME_Absolute lastCall;
  struct GNUNET_TIME_Relative age;

  age = GNUNET_TIME_absolute_get_duration (lastCall);
  if ( (agedCPULoad == -1)
       || (age.rel_value_us > 500000) )
    {
      /* use smoothing, but do NOT update lastRet at frequencies higher
         than 500ms; this makes the smoothing (mostly) independent from
         the frequency at which getCPULoad is called (and we don't spend
         more time measuring CPU than actually computing something). */
      lastCall = GNUNET_TIME_absolute_get ();
      updateUsage ();
      if (currentCPULoad == -1)
        {
          agedCPULoad = -1;
        }
      else
        {
          if (agedCPULoad == -1)
            {
              agedCPULoad = currentCPULoad;
            }
          else
            {
              /* for CPU, we don't do the 'fast increase' since CPU is much
                 more jitterish to begin with */
              agedCPULoad = (agedCPULoad * 31 + currentCPULoad) / 32;
            }
        }
      if (currentIOLoad == -1)
        {
          agedIOLoad = -1;
        }
      else
        {
          if (agedIOLoad == -1)
            {
              agedIOLoad = currentIOLoad;
            }
          else
            {
              /* for IO, we don't do the 'fast increase' since IO is much
                 more jitterish to begin with */
              agedIOLoad = (agedIOLoad * 31 + currentIOLoad) / 32;
            }
        }
    }
}

/**
 * Get the load of the CPU relative to what is allowed.
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
static int
cpu_get_load ()
{
  updateAgedLoad ();
  return (int) agedCPULoad;
}


/**
 * Get the load of the CPU relative to what is allowed.
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
static int
disk_get_load ()
{
  updateAgedLoad ();
  return (int) agedIOLoad;
}

/**
 * Get the percentage of memory used
 *
 * @return the percentage of memory used
 */
static unsigned int
mem_get_usage ()
{
  double percentage;

  meminfo ();
  percentage = ( ((double) kb_main_used) / ((double) kb_main_total) * 100.0 );
  return (unsigned int) percentage;
}


#ifdef LINUX
#include <dirent.h>
/**
 * Returns the number of processes
 *
 * @return the number of processes
 */
static unsigned int
get_nproc ()
{
  DIR *dir;
  struct dirent *ent;
  unsigned int nproc;

  dir = opendir ("/proc");
  if (NULL == dir)
    return 0;
  nproc = 0;
  while (NULL != (ent = readdir (dir)))
  {
    if((*ent->d_name > '0') && (*ent->d_name <= '9'))
      nproc++;
  }
  closedir (dir);
  return nproc;
}
#endif


static void
sample_load_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute now;
  char *str;
  int nbs;
  int ld_cpu;
  int ld_disk;
  unsigned int mem_usage;
  unsigned int nproc;

  sample_load_task_id = NULL;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  ld_cpu = cpu_get_load ();
  ld_disk = disk_get_load ();
  if ( (-1 == ld_cpu) || (-1 == ld_disk) )
    goto reschedule;
  mem_usage = mem_get_usage ();
#ifdef LINUX
  nproc = get_nproc ();
#else
  nproc = 0;
#endif
  now = GNUNET_TIME_absolute_get ();
  nbs = GNUNET_asprintf (&str, "%llu %d %d %u %u\n", now.abs_value_us / 1000LL / 1000LL,
                         ld_cpu, ld_disk, mem_usage, nproc);
  if (0 < nbs)
  {
    GNUNET_BIO_write (bw, str, nbs);
  }
  else
    GNUNET_break (0);
  GNUNET_free (str);

 reschedule:
  sample_load_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &sample_load_task, NULL);
}


/**
 * Initialize logging CPU and IO statisticfs.  Checks the configuration for
 * "STATS_DIR" and logs to a file in that directory.  The file is name is
 * generated from the hostname and the process's PID.
 */
void
GST_stats_init (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *hostname;
  char *stats_dir;
  char *fn;
  size_t len;

#if MINGW
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Load statistics logging now available for windows\n");
  return;                       /* No logging on windows for now :( */
#endif

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "testbed",
                                               "STATS_DIR", &stats_dir))
    return;
  len = GNUNET_OS_get_hostname_max_length ();
  hostname = GNUNET_malloc (len);
  if (0 != gethostname  (hostname, len))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "gethostname");
    GNUNET_free (stats_dir);
    GNUNET_free (hostname);
    return;
  }
  fn = NULL;
  (void) GNUNET_asprintf (&fn, "%s/%.*s-%jd.dat", stats_dir, len,
                          hostname, (intmax_t) getpid());
  GNUNET_free (stats_dir);
  GNUNET_free (hostname);
  if (NULL == (bw = GNUNET_BIO_write_open (fn)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Cannot open %s for writing load statistics.  "
                  "Not logging load statistics\n"), fn);
    GNUNET_free (fn);
    return;
  }
  GNUNET_free (fn);
  sample_load_task_id = GNUNET_SCHEDULER_add_now (&sample_load_task, NULL);
#ifdef LINUX
  proc_stat = fopen ("/proc/stat", "r");
  if (NULL == proc_stat)
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "fopen", "/proc/stat");
#elif OSX
  initMachCpuStats ();
#endif
  updateUsage ();               /* initialize */

}


/**
 * Shutdown the status calls module.
 */
void
GST_stats_destroy ()
{
#if MINGW
  return;
#endif
  if (NULL == bw)
    return;
#ifdef LINUX
  if (proc_stat != NULL)
    {
      fclose (proc_stat);
      proc_stat = NULL;
    }
#elif OSX
  GNUNET_free_non_null (prev_cpu_load);
#endif
  if (NULL != sample_load_task_id)
  {
    GNUNET_SCHEDULER_cancel (sample_load_task_id);
    sample_load_task_id = NULL;
  }
  GNUNET_break (GNUNET_OK == GNUNET_BIO_write_close (bw));
  bw = NULL;
}

/* end of cpustatus.c */

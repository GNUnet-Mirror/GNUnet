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
 * @file sysmon/gnunet-service-sysmon.c
 * @brief system monitoring service, can use libgtop to retrieve system information
 * in a plattform independent way
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#if HAVE_LIBGTOP
#include <glibtop.h>
#include <glibtop/proclist.h>
#include <glibtop/procstate.h>
#include <glibtop/procargs.h>
#include <glibtop/procmem.h>
#include <glibtop/proctime.h>
#include <glibtop/netlist.h>
#include <glibtop/netload.h>
#endif


enum operation
{
  o_internal,
  o_ligbtop,
  o_command
};


enum type
{
  t_static,
  t_continous
};

#define V_NUMERIC_STR "numeric"
#define V_STRING_STR "string"

enum value
{
  v_numeric,
  v_string
};

/**
 * A system property to monitor
 */
struct SysmonProperty
{
  /**
   * Next element in in the DLL
   */
  struct SysmonProperty *next;

  /**
   * Previous element in in the DLL
   */
  struct SysmonProperty *prev;

	struct SysmonGtopProcProperty *gtop_proc_head;
	struct SysmonGtopProcProperty *gtop_proc_tail;

  /**
   * Description used for statistics valuesd
   */
  char * desc;

  /**
   * Type
   */
  int type;

  /**
   * Value type
   */
  int value_type;

  /**
   * Execution interval
   */
  struct GNUNET_TIME_Relative interval;

  /**
   * Command
   */
  char * cmd;

  /**
   * Command arguments
   */
  char * cmd_args;

  /**
   * Command execution handle
   */
  void * cmd_exec_handle;

  /**
   * Numerical value
   */
  uint64_t num_val;

  /**
   * String value
   */
  char * str_val;

  /**
   * Task id
   */
  GNUNET_SCHEDULER_TaskIdentifier task_id;

  /**
   * Task handle
   */
  GNUNET_SCHEDULER_Task task;

  /**
   * Task closure
   */
  void *task_cls;
};

/**
 * A system property to monitor
 */
struct SysmonGtopProcProperty
{
	struct SysmonGtopProcProperty *prev;
	struct SysmonGtopProcProperty *next;
	char * srv;
	char * binary;
};


/**
 * Final status code.
 */
static int ret;

/**
 * Configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Statistics handle
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Shutdown task
 */
GNUNET_SCHEDULER_TaskIdentifier end_task;

struct SysmonProperty *sp_head;
struct SysmonProperty *sp_tail;

struct SysmonGtopProcProperty *pp_head;
struct SysmonGtopProcProperty *pp_tail;

static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SysmonProperty *sp;
  struct SysmonProperty *next;
	struct SysmonGtopProcProperty *gt_cur;
	struct SysmonGtopProcProperty *gt_next;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sysdaemon stopping ... \n");
  end_task = GNUNET_SCHEDULER_NO_TASK;

  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }

  next = sp_head;
  while (NULL != (sp = next))
  {
  		next = sp->next;
  		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping `%s' \n", sp->desc);
      GNUNET_CONTAINER_DLL_remove (sp_head, sp_tail, sp);
      if (GNUNET_SCHEDULER_NO_TASK != sp->task_id)
      {
        GNUNET_SCHEDULER_cancel (sp->task_id);
        sp->task_id = GNUNET_SCHEDULER_NO_TASK;
      }
      GNUNET_free_non_null (sp->cmd);
      GNUNET_free_non_null (sp->cmd_args);
      GNUNET_free (sp->desc);
      GNUNET_free (sp);
  }

  gt_next = pp_head;
	while (NULL != (gt_cur = gt_next))
	{
			gt_next = gt_cur->next;
			GNUNET_CONTAINER_DLL_remove (pp_head, pp_tail, gt_cur);
			GNUNET_free (gt_cur->srv);
			GNUNET_free (gt_cur->binary);
			GNUNET_free (gt_cur);
	}

#if HAVE_LIBGTOP
  glibtop_close();
#endif
}

static void
shutdown_now (void)
{
  if (GNUNET_SCHEDULER_NO_TASK != end_task)
    GNUNET_SCHEDULER_cancel (end_task);
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}

static void
to_lower_str (char * str)
{
  int c;
  for (c = 0; c <= strlen (str); c++)
    str[c] = tolower(str[c]);
}

static int
put_property (struct SysmonProperty *sp)
{
  if (v_numeric ==sp->value_type)
  {
  		fprintf (stderr, "%s : %s : %llu\n",
  				GNUNET_STRINGS_absolute_time_to_string(GNUNET_TIME_absolute_get()),
  				sp->desc, (unsigned long long) sp->num_val);
  }
  else if (v_string ==sp->value_type)
  {
  		fprintf (stderr, "%s : %s : %s\n",
  				GNUNET_STRINGS_absolute_time_to_string(GNUNET_TIME_absolute_get()),
  				sp->desc, sp->str_val);
  }
  else
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static void
update_uptime (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct SysmonProperty *sp = cls;
	static int first_run = GNUNET_YES;

	if (GNUNET_YES == first_run)
			first_run = GNUNET_NO;
	else
			sp->num_val += sp->interval.rel_value_us / 1000LL / 1000LL;

  put_property (sp);
}

static void
exec_cmd_proc (void *cls, const char *line)
{
  struct SysmonProperty *sp = cls;
  unsigned long long tmp;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Property output: `%s'\n", line);
  if (NULL == line)
  {
      GNUNET_OS_command_stop (sp->cmd_exec_handle);
      sp->cmd_exec_handle = NULL;
      return;
  }

  switch (sp->value_type) {
    case v_numeric:
      if (1 != sscanf (line, "%llu", &tmp))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Command output was not a numerical value: `%s'\n", line);
        return;
      }
      break;
    case v_string:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "NOT IMPLEMENTED\n");
      break;
    default:
      break;

  }
  sp->num_val = tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Property output: `%s'\n", line);
  put_property (sp);


}

static void
exec_cmd (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SysmonProperty *sp = cls;
  GNUNET_assert (NULL != sp->cmd);

  if (NULL != sp->cmd_exec_handle)
  {
    GNUNET_OS_command_stop (sp->cmd_exec_handle);
    sp->cmd_exec_handle = NULL;
    GNUNET_break (0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Property `%s': command `%s' `%s'\n", sp->desc, sp->cmd, sp->cmd_args);
  if (NULL == (sp->cmd_exec_handle = GNUNET_OS_command_run (&exec_cmd_proc, sp,
      GNUNET_TIME_UNIT_SECONDS,
      sp->cmd, sp->cmd,
      sp->cmd_args,
      NULL)))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Property `%s': command `%s' failed\n", sp->desc, sp->cmd);
}

#if HAVE_LIBGTOP
static void
exec_gtop_proc_mon (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
   struct SysmonGtopProcProperty *sp = cls;
   glibtop_proclist proc_list;
   glibtop_proc_args proc_args;
   glibtop_proc_mem proc_mem;
   glibtop_proc_time proc_time;
   pid_t *pids = NULL;
   unsigned i;
   char *argss;

   /* get process list */
   pids = glibtop_get_proclist(&proc_list, GLIBTOP_KERN_PROC_ALL, 0);
   if (NULL == pids)
   {
     fprintf (stderr, "Could not retrieve process list!\n");
     ret = 1;
     return;
   }
   for (i = 0; i < proc_list.number; ++i)
   {
       //printf("PID %u:\n", pids[i]);

       /* get process args */
       argss = glibtop_get_proc_args (&proc_args, pids[i], 1024);
       if (NULL == argss)
       {
         fprintf (stderr, "Could not retrieve process args!\n");
         ret = 1;
         return;
       }
       //printf ("\targument string: %s\n", argss);
       if (NULL != strstr (argss, sp->binary))
       {
				 /* get memory info */
				 glibtop_get_proc_mem (&proc_mem, pids[i]);
		  	 fprintf (stderr, "%s : %s process information\n",
		  				GNUNET_STRINGS_absolute_time_to_string(GNUNET_TIME_absolute_get()),
							sp->srv);
				 fprintf (stderr, "\t%s memory information:\n", sp->binary);
				 fprintf (stderr, "\t%-50s: %llu\n", "total # of pages of memory", (long long unsigned int) proc_mem.size);
				 fprintf (stderr, "\t%-50s: %llu\n", "number of pages of virtual memory", (long long unsigned int) proc_mem.vsize);
				 fprintf (stderr, "\t%-50s: %llu\n", "number of resident set", (long long unsigned int) proc_mem.resident);
				 fprintf (stderr, "\t%-50s: %llu\n", "number of pages of shared (mmap'd) memory", (long long unsigned int) proc_mem.share);
				 fprintf (stderr, "\t%-50s: %llu\n", "resident set size", (long long unsigned int) proc_mem.rss);

				 /* get time info */
				 glibtop_get_proc_time (&proc_time, pids[i]);
				 fprintf (stderr, "\t%s time information:\n", sp->binary);
				 fprintf (stderr, "\t%-50s: %llu\n", "real time accumulated by process", (long long unsigned int) proc_time.rtime);
				 fprintf (stderr, "\t%-50s: %llu\n", "user-mode CPU time accumulated by process", (long long unsigned int) proc_time.utime);
				 fprintf (stderr, "\t%-50s: %llu\n", "kernel-mode CPU time accumulated by process", (long long unsigned int) proc_time.stime);
   	 	 }
       g_free (argss);
   }
   g_free(pids);
   pids = NULL;
}
#endif

#if HAVE_LIBGTOP
static void
exec_gtop_net_mon (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
   glibtop_netlist netlist;
   glibtop_netload netload;
   int i;
   char ** tmp;
   uint8_t *address;
   uint8_t *netmask;
   char address6_string[INET6_ADDRSTRLEN];
   char prefix6_string[INET6_ADDRSTRLEN];

   tmp = glibtop_get_netlist (&netlist);

	 fprintf (stderr, "%s : Network information: %u devices\n",
				GNUNET_STRINGS_absolute_time_to_string(GNUNET_TIME_absolute_get()),
				netlist.number);
   for (i = 0; i < netlist.number; ++i)
   {
     fprintf (stderr, "Device %i: %s\n", i, tmp[i]);
     glibtop_get_netload (&netload, tmp[i]);
     address = (uint8_t *) &netload.address;
     netmask = (uint8_t *) &netload.subnet;
   	 inet_ntop (AF_INET6, netload.address6, address6_string, INET6_ADDRSTRLEN);
   	 inet_ntop (AF_INET6, netload.prefix6,  prefix6_string,  INET6_ADDRSTRLEN);
     fprintf (stderr, "\t%-50s: %u.%u.%u.%u\n", "IPv4 subnet", netmask[0], netmask[1], netmask[2],netmask[3]);
     fprintf (stderr, "\t%-50s: %u.%u.%u.%u\n", "IPv4 address", address[0], address[1], address[2],address[3]);
     fprintf (stderr, "\t%-50s: %s\n", "IPv6 prefix", prefix6_string);
     fprintf (stderr, "\t%-50s: %s\n", "IPv6 address", address6_string);


     fprintf (stderr, "\t%-50s: %llu\n", "bytes in", (long long unsigned int) netload.bytes_in);
     fprintf (stderr, "\t%-50s: %llu\n", "bytes out", (long long unsigned int) netload.bytes_out);
     fprintf (stderr, "\t%-50s: %llu\n", "bytes total", (long long unsigned int) netload.bytes_total);
   }
   fprintf (stderr, "\n");
}
#endif

static void
load_property (void *cls,
               const char *section)
{
  struct GNUNET_CONFIGURATION_Handle *properties = cls;
  struct SysmonProperty *sp;
  char *tmp;

  if (NULL == strstr (section, "sysmon-"))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loading section `%s'\n", section);

  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (properties, section, "TYPE"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing value %s in section `%s'\n",
        "TYPE", section);
    return;
  }
  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (properties, section,"VALUE"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing value %s in section `%s'\n",
        "VALUE", section);
    return;
  }
  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (properties, section,"DESCRIPTION"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing value %s in section `%s'\n",
        "DESCRIPTION", section);
    return;
  }
  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (properties, section,"CMD"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing value %s in section `%s'\n",
        "CMD", section);
    return;
  }
  sp = GNUNET_malloc (sizeof (struct SysmonProperty));

  /* description */
  GNUNET_CONFIGURATION_get_value_string (properties, section, "DESCRIPTION", &sp->desc);

  /* cmd */
  GNUNET_CONFIGURATION_get_value_string (properties, section, "CMD", &tmp);
  char *args = "";
  if (NULL != strchr (tmp, ' '))
  {
      args = strchr (tmp, ' ');
      if (strlen (args) > 1)
      {
          args[0] = '\0';
          args++;
      }
  }
  sp->task_cls = sp;
  sp->cmd = GNUNET_strdup (tmp);
  sp->cmd_args = GNUNET_strdup (args);
  GNUNET_free (tmp);
  sp->task = &exec_cmd;

  /* type */
  GNUNET_CONFIGURATION_get_value_string (properties, section, "TYPE", &tmp);
  to_lower_str (tmp);
  if (0 == strcasecmp(tmp, "static"))
    sp->type = t_static;
  else if (0 == strcasecmp(tmp, "continous"))
    sp->type = t_continous;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Invalid value %s for %s in section `%s'\n",
        tmp, "TYPE", section);
    GNUNET_free (tmp);
    GNUNET_free (sp);
    return;
  }
  GNUNET_free (tmp);

  /* value */
  GNUNET_CONFIGURATION_get_value_string (properties, section, "VALUE", &tmp);
  to_lower_str (tmp);
  if (0 == strcasecmp(tmp, V_NUMERIC_STR))
    sp->value_type = v_numeric;
  else if (0 == strcasecmp(tmp, V_STRING_STR))
    sp->value_type = v_string;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Invalid value %s for %s in section `%s'\n",
        tmp, "VALUE", section);
    GNUNET_free (tmp);
    GNUNET_free (sp);
    return;
  }
  GNUNET_free (tmp);

  /* interval */
  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (properties, section,"INTERVAL"))
    sp->interval = GNUNET_TIME_UNIT_MINUTES;
  else
  {
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (properties, section, "INTERVAL", &sp->interval))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
            _("Could not parse execution interval for `%s', set to default 60 sec.\n"), section);
        sp->interval = GNUNET_TIME_UNIT_MINUTES;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Loaded property `%s': %s, %s, interval %s\n",
	      (NULL != sp->desc) ? sp->desc: "<undefined>",
	      (t_continous == sp->type) ? "continious" : "static",
	      (v_numeric == sp->value_type) ? "numeric" : "string",
	      GNUNET_STRINGS_relative_time_to_string (sp->interval,
						      GNUNET_YES));

  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);

}

static int
load_default_properties (void)
{
  struct SysmonProperty *sp;
  /* GNUnet version array */
  unsigned int ver[3];

  /* GNUnet vcs revision */
  unsigned int revision;
  /* version */
#ifdef VERSION
  if (3 != sscanf (VERSION, "%u.%u.%u", &ver[0], &ver[1], &ver[2]))
  {
    ver[0] = 0;
    ver[1] = 0;
    ver[2] = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse version string `%s'\n", VERSION);
  }
#else
  ver[0] = 0;
  ver[1] = 0;
  ver[2] = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Version string is undefined \n");
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Version: %u.%u.%u\n", ver[0], ver[1], ver[2]);

  sp = GNUNET_malloc (sizeof (struct SysmonProperty));
  sp->desc = GNUNET_strdup ("GNUnet version");
  sp->type = t_static;
  sp->value_type = v_numeric;
  sp->num_val = 100 * ver[0] + 10  * ver[1] + ver[2];
  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);
  /* revision */
#ifdef VCS_VERSION
  if (1 != sscanf (VCS_VERSION, "svn-%uM", &revision))
  {
    revision = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse revision string `%s'\n", VCS_VERSION);
  }
#else
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "VCS revision string is undefined \n");
  revision = 0;
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Revision: %u\n", revision);
  sp = GNUNET_malloc (sizeof (struct SysmonProperty));
  sp->desc = GNUNET_strdup ("GNUnet vcs revision");
  sp->type = t_static;
  sp->value_type = v_numeric;
  sp->num_val = (uint64_t) revision;
  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);


  /* GNUnet startup time  */
  sp = GNUNET_malloc (sizeof (struct SysmonProperty));
  sp->desc = GNUNET_strdup ("GNUnet startup time");
  sp->type = t_static;
  sp->value_type = v_numeric;
  sp->num_val = (uint64_t) GNUNET_TIME_absolute_get().abs_value_us;
  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);


  /* GNUnet sysmon daemon uptime in seconds */
  sp = GNUNET_malloc (sizeof (struct SysmonProperty));
  sp->desc = GNUNET_strdup ("GNUnet uptime");
  sp->type = t_continous;
  sp->value_type = v_numeric;
  sp->num_val = (uint64_t) 0;
  sp->interval = GNUNET_TIME_UNIT_MINUTES;
  sp->task_id = GNUNET_SCHEDULER_NO_TASK;
  sp->task = update_uptime;
  sp->task_cls = sp;
  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);
  return GNUNET_OK;
}

#if HAVE_LIBGTOP
static int
load_gtop_properties (void)
{
	char *services;
	char *s;
	char *binary;
	struct SysmonGtopProcProperty *pp;
	struct SysmonProperty *sp;
	struct GNUNET_TIME_Relative interval;

	/* Load service memory monitoring tasks */
	if (GNUNET_NO == GNUNET_CONFIGURATION_have_value (cfg, "sysmon", "MONITOR_SERVICES"))
		return GNUNET_OK;

	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "sysmon", "MONITOR_SERVICES", &services))
		return GNUNET_SYSERR;

	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,"sysmon", "MONITOR_SERVICES_INTERVAL", &interval))
		interval = GNUNET_TIME_UNIT_MINUTES;

	s = strtok (services, " ");
	while (NULL != s)
	{
		if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, s, "BINARY", &binary))
		{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Monitoring service `%s' with binary `%s'\n", s, binary);
			pp = GNUNET_malloc (sizeof (struct SysmonGtopProcProperty));
			pp->srv = GNUNET_strdup (s);
			pp->binary = binary;
			GNUNET_CONTAINER_DLL_insert (pp_head, pp_tail, pp);

		  sp = GNUNET_malloc (sizeof (struct SysmonProperty));
		  GNUNET_asprintf(&sp->desc, "Process Monitoring for service %s", s);
		  sp->type = t_continous;
		  sp->value_type = v_numeric;
		  sp->num_val = (uint64_t) 0;
		  sp->interval = interval;
		  sp->task_id = GNUNET_SCHEDULER_NO_TASK;
		  sp->task = exec_gtop_proc_mon;
		  sp->task_cls = pp;
		  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);
		}
		s = strtok (NULL, " ");
	}
	GNUNET_free (services);

	/* Load network monitoring tasks */

	if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (cfg,"sysmon", "MONITOR_NETWORK_INTERVAL", &interval))
		interval = GNUNET_TIME_UNIT_MINUTES;

  sp = GNUNET_malloc (sizeof (struct SysmonProperty));
  GNUNET_asprintf(&sp->desc, "Network interface monitoring");
  sp->type = t_continous;
  sp->value_type = v_numeric;
  sp->num_val = (uint64_t) 0;
  sp->interval = interval;
  sp->task_id = GNUNET_SCHEDULER_NO_TASK;
  sp->task = exec_gtop_net_mon;
  sp->task_cls = sp;
  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);

	return GNUNET_OK;
}
#endif


static void
run_property (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SysmonProperty *sp = cls;
  sp->task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Running continous property `%s' \n", sp->desc);
  sp->task (sp->task_cls, tc);
  sp->task_id = GNUNET_SCHEDULER_add_delayed (sp->interval, &run_property, sp);
}


static int
run_properties (void)
{
  struct SysmonProperty *sp;

  for (sp = sp_head; NULL != sp; sp = sp->next)
  {
      if (t_static == sp->type)
      {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Running static property `%s' \n", sp->desc);
          put_property (sp);
      }
      else
      {
          if (NULL == sp->task)
          {
            GNUNET_break (0);
            continue;
          }
          sp->task_id = GNUNET_SCHEDULER_add_now (&run_property, sp);
      }
  }
  return GNUNET_OK;
}


/**
 * Process template requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param mycfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *mycfg)
{
	static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    /* FIXME: add handlers here! */
    {NULL, NULL, 0, 0}
  };
  /* FIXME: do setup here */
  GNUNET_SERVER_add_handlers (server, handlers);

  struct GNUNET_CONFIGURATION_Handle *properties;
  char *file;

  end_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);
  cfg = mycfg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sysmon starting ... \n");

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_filename (mycfg, "sysmon", "CFGFILE", &file))
  {
  	  properties = GNUNET_CONFIGURATION_create();
  	  if (NULL == properties)
  	  {
  	    GNUNET_break (0);
  	    shutdown_now();
  	    ret = 1;
  	    return;
  	  }
  	  if ((GNUNET_YES == GNUNET_DISK_file_test(file)) &&
  	  		(GNUNET_OK == GNUNET_CONFIGURATION_load (properties, file)))
    	  GNUNET_CONFIGURATION_iterate_sections (properties, &load_property, properties);

  	  GNUNET_CONFIGURATION_destroy (properties);
  	  GNUNET_free (file);

  	  /* Creating statistics */
  	  stats = GNUNET_STATISTICS_create ("sysmon", mycfg);
  	  if (NULL == stats)
  	  {
  	    GNUNET_break (0);
  	    shutdown_now();
  	    ret = 1;
  	    return;
  	  }
  }

  /* load properties */
  if (GNUNET_SYSERR == load_default_properties ())
  {
    GNUNET_break (0);
    shutdown_now();
    ret = 1;
    return;
  }

#if HAVE_LIBGTOP
  if (NULL != glibtop_init())
		if ( GNUNET_SYSERR == load_gtop_properties ())
		{
				GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to load gtop properties \n");
		}
#endif

  /* run properties */
  if (GNUNET_SYSERR == run_properties ())
  {
    GNUNET_break (0);
    shutdown_now();
    ret = 1;
    return;
  }
}


/**
 * The main function for the sysmon service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "sysmon",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-sysmon.c */

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
 * @file sysmon/gnunet-daemon-sysmon.c
 * @brief system monitoring aemon
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"

enum type
{
  t_static,
  t_continous
};

enum value
{
  v_numeric,
  v_string
};

struct SysmonProperty
{
  struct SysmonProperty *next;
  struct SysmonProperty *prev;

 char * desc;
 int type;
 int value;
 struct GNUNET_TIME_Relative interval;
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

static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SysmonProperty *sp;
  struct SysmonProperty *next;

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
      GNUNET_CONTAINER_DLL_remove (sp_head, sp_tail, sp);
      next = sp->next;
      GNUNET_free_non_null (sp->desc);
      GNUNET_free (sp);
  }

}

static void
shutdown_now ()
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

void load_property (void *cls,
                    const char *section)
{
  struct GNUNET_CONFIGURATION_Handle *properties = cls;
  struct SysmonProperty *sp;
  char *tmp;

  if (NULL == strstr (section, "sysmon-"))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loading section `%s'\n", section);

  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value(properties, section, "TYPE"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing value %s in section `%s'\n",
        "TYPE", section);
    return;
  }
  if (GNUNET_NO == GNUNET_CONFIGURATION_have_value(properties, section,"VALUE"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing value %s in section `%s'\n",
        "VALUE", section);
    return;
  }


  sp = GNUNET_malloc (sizeof (struct SysmonProperty));

  /* description */
  GNUNET_CONFIGURATION_get_value_string(properties, section, "DESCRIPTION", &sp->desc);

  /* type */
  GNUNET_CONFIGURATION_get_value_string(properties, section, "TYPE", &tmp);
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
  GNUNET_CONFIGURATION_get_value_string(properties, section, "VALUE", &tmp);
  to_lower_str (tmp);
  if (0 == strcasecmp(tmp, "numeric"))
    sp->value = v_numeric;
  else if (0 == strcasecmp(tmp, "string"))
    sp->value = v_string;
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loaded property `%s': type %u, value %u,\n",
      (NULL != sp->desc) ? sp->desc: "<undefined>",
      sp->type, sp->value);

  GNUNET_CONTAINER_DLL_insert (sp_head, sp_tail, sp);

}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *mycfg)
{
  struct GNUNET_CONFIGURATION_Handle *properties;
  char *file;

  end_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);
  cfg = mycfg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sysdaemon starting ... \n");

  if (GNUNET_SYSERR ==GNUNET_CONFIGURATION_get_value_filename (mycfg, "sysmon", "CFGFILE", &file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Sysmon configuration file not set, exit! \n");
    shutdown_now();
    ret = 1;
    return;
  }

  properties = GNUNET_CONFIGURATION_create();
  if (NULL == properties)
  {
    GNUNET_break (0);
    shutdown_now();
    ret = 1;
    return;
  }
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (properties, file))
  {
      GNUNET_break (0);
      GNUNET_CONFIGURATION_destroy (properties);
      GNUNET_free (file);
      ret = 1;
      shutdown_now();
      return;
  }
  GNUNET_free (file);
  GNUNET_CONFIGURATION_iterate_sections (properties, &load_property, properties);

  GNUNET_CONFIGURATION_destroy (properties);

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
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-sysmon",
			     gettext_noop ("GNUnet system monitoring and information daemon"), options, &run,
			     NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-daemon-sysmon.c */

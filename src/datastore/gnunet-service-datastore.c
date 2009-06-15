/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file datastore/gnunet-service-datastore.c
 * @brief Management for the datastore for files stored on a GNUnet node
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "plugin_datastore.h"
#include "datastore.h"


/**
 * Our datastore plugin.
 */
struct DatastorePlugin
{

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_DATSTORE_PluginFunctions *api;

  /**
   * Short name for the plugin (i.e. "sqlite").
   */
  char *short_name;

  /**
   * Name of the library (i.e. "gnunet_plugin_datastore_sqlite").
   */
  char *lib_name;

  /**
   * Environment this transport service is using
   * for this plugin.
   */
  struct GNUNET_DATASTORE_PluginEnvironment env;

};


/**
 * Our datastore plugin (NULL if not available).
 */
static struct DatastorePlugin *plugin;


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  /*  {&handle_xxx, NULL, GNUNET_MESSAGE_TYPE_DATASTORE_XXX, 0}, */
  {NULL, NULL, 0, 0}
};



/**
 * Load the datastore plugin.
 */
static struct DatastorePlugin *
load_plugin (struct GNUNET_CONFIGURATION_Handle *cfg,
	     struct GNUNET_SCHEDULER_Handle *sched)
{
  struct DatastorePlugin *ret;
  char *libname;
  char *name;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "DATASTORE", "DATABASE", &name))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("No `%s' specified for `%s' in configuration!\n"),
		  "DATABASE",
		  "DATASTORE");
      return NULL;
    }
  ret = GNUNET_malloc (sizeof(struct DatastorePlugin));
  ret->env.cfg = cfg;
  ret->env.sched = sched;  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' datastore plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  ret->short_name = GNUNET_strdup (name);
  ret->lib_name = libname;
  ret->api = GNUNET_PLUGIN_load (libname, &ret->env);
  if (ret->api == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to load datastore plugin for `%s'\n"), name);
      GNUNET_free (ret->short_name);
      GNUNET_free (libname);
      GNUNET_free (ret);
      return NULL;
    }
  return ret;
}


/**
 * Function called when the service shuts
 * down.  Unloads our datastore plugin.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
static void
unload_plugin (struct DatastorePlugin *plug)
{
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Datastore service is unloading plugin...\n");
#endif
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (plug->lib_name, plug->api));
  GNUNET_free (plug->lib_name);
  GNUNET_free (plug->short_name);
  GNUNET_free (plug);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unload_plugin (plugin);
  plugin = NULL;
}


/**
 * Process datastore requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     struct GNUNET_CONFIGURATION_Handle *cfg)
{
  plugin = load_plugin (cfg, sched);
  if (NULL == plugin)
    return;
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_YES,
                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
}


/**
 * The main function for the datastore service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_SERVICE_run (argc,
                             argv,
                             "datastore", &run, NULL, NULL, NULL)) ? 0 : 1;
  return ret;
}


/* end of gnunet-service-datastore.c */

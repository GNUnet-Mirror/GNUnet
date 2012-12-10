/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/plugin.c
 * @brief Methods to access plugins
 * @author Christian Grothoff
 */

#include "platform.h"
#include <ltdl.h>
#include "gnunet_common.h"
#include "gnunet_os_lib.h"
#include "gnunet_plugin_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Linked list of active plugins.
 */
struct PluginList
{
  /**
   * This is a linked list.
   */
  struct PluginList *next;

  /**
   * Name of the library.
   */
  char *name;

  /**
   * System handle.
   */
  void *handle;
};


/**
 * Have we been initialized?
 */
static int initialized;


/**
 * Libtool search path before we started.
 */
static char *old_dlsearchpath;


/**
 * List of plugins we have loaded.
 */
static struct PluginList *plugins;


/**
 * Setup libtool paths.
 */
static void
plugin_init ()
{
  int err;
  const char *opath;
  char *path;
  char *cpath;

  err = lt_dlinit ();
  if (err > 0)
  {
    FPRINTF (stderr, _("Initialization of plugin mechanism failed: %s!\n"),
             lt_dlerror ());
    return;
  }
  opath = lt_dlgetsearchpath ();
  if (opath != NULL)
    old_dlsearchpath = GNUNET_strdup (opath);
  path = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBDIR);
  if (path != NULL)
  {
    if (opath != NULL)
    {
      GNUNET_asprintf (&cpath, "%s:%s", opath, path);
      lt_dlsetsearchpath (cpath);
      GNUNET_free (path);
      GNUNET_free (cpath);
    }
    else
    {
      lt_dlsetsearchpath (path);
      GNUNET_free (path);
    }
  }
}


/**
 * Shutdown libtool.
 */
static void
plugin_fini ()
{
  lt_dlsetsearchpath (old_dlsearchpath);
  if (old_dlsearchpath != NULL)
  {
    GNUNET_free (old_dlsearchpath);
    old_dlsearchpath = NULL;
  }
  lt_dlexit ();
}


/**
 * Lookup a function in the plugin.
 */
static GNUNET_PLUGIN_Callback
resolve_function (struct PluginList *plug, const char *name)
{
  char *initName;
  void *mptr;

  GNUNET_asprintf (&initName, "_%s_%s", plug->name, name);
  mptr = lt_dlsym (plug->handle, &initName[1]);
  if (mptr == NULL)
    mptr = lt_dlsym (plug->handle, initName);
  if (mptr == NULL)
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("`%s' failed to resolve method '%s' with error: %s\n"), "lt_dlsym",
         &initName[1], lt_dlerror ());
  GNUNET_free (initName);
  return mptr;
}

/**
 * Test if a plugin exists.
 *
 * Note that the library must export a symbol called
 * "library_name_init" for the test to succeed.
 *
 * @param library_name name of the plugin to test if it is installed
 * @return GNUNET_YES if the plugin exists, GNUNET_NO if not
 */
int
GNUNET_PLUGIN_test (const char *library_name)
{
  void *libhandle;
  GNUNET_PLUGIN_Callback init;
  struct PluginList plug;

  if (!initialized)
  {
    initialized = GNUNET_YES;
    plugin_init ();
  }
  libhandle = lt_dlopenext (library_name);
  if (libhandle == NULL)
    return GNUNET_NO;
  plug.handle = libhandle;
  plug.name = (char *) library_name;
  init = resolve_function (&plug, "init");
  if (init == NULL)
  {
    GNUNET_break (0);
    lt_dlclose (libhandle);
    return GNUNET_NO;
  }
  lt_dlclose (libhandle);
  return GNUNET_YES;
}


/**
 * Setup plugin (runs the "init" callback and returns whatever "init"
 * returned).  If "init" returns NULL, the plugin is unloaded.
 *
 * Note that the library must export symbols called
 * "library_name_init" and "library_name_done".  These will be called
 * when the library is loaded and unloaded respectively.
 *
 * @param library_name name of the plugin to load
 * @param arg argument to the plugin initialization function
 * @return whatever the initialization function returned
 */
void *
GNUNET_PLUGIN_load (const char *library_name, void *arg)
{
  void *libhandle;
  struct PluginList *plug;
  GNUNET_PLUGIN_Callback init;
  void *ret;

  if (!initialized)
  {
    initialized = GNUNET_YES;
    plugin_init ();
  }
  libhandle = lt_dlopenext (library_name);
  if (libhandle == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("`%s' failed for library `%s' with error: %s\n"), "lt_dlopenext",
         library_name, lt_dlerror ());
    return NULL;
  }
  plug = GNUNET_malloc (sizeof (struct PluginList));
  plug->handle = libhandle;
  plug->name = GNUNET_strdup (library_name);
  plug->next = plugins;
  plugins = plug;
  init = resolve_function (plug, "init");
  if ((init == NULL) || (NULL == (ret = init (arg))))
  {
    lt_dlclose (libhandle);
    GNUNET_free (plug->name);
    plugins = plug->next;
    GNUNET_free (plug);
    return NULL;
  }
  return ret;
}


/**
 * Unload plugin (runs the "done" callback and returns whatever "done"
 * returned).  The plugin is then unloaded.
 *
 * @param library_name name of the plugin to unload
 * @param arg argument to the plugin shutdown function
 * @return whatever the shutdown function returned
 */
void *
GNUNET_PLUGIN_unload (const char *library_name, void *arg)
{
  struct PluginList *pos;
  struct PluginList *prev;
  GNUNET_PLUGIN_Callback done;
  void *ret;

  prev = NULL;
  pos = plugins;
  while ((pos != NULL) && (0 != strcmp (pos->name, library_name)))
  {
    prev = pos;
    pos = pos->next;
  }
  if (pos == NULL)
    return NULL;

  done = resolve_function (pos, "done");
  ret = NULL;
  if (done != NULL)
    ret = done (arg);
  if (prev == NULL)
    plugins = pos->next;
  else
    prev->next = pos->next;
  lt_dlclose (pos->handle);
  GNUNET_free (pos->name);
  GNUNET_free (pos);
  if (plugins == NULL)
  {
    plugin_fini ();
    initialized = GNUNET_NO;
  }
  return ret;
}


struct LoadAllContext
{
  const char *basename;
  void *arg;
  GNUNET_PLUGIN_LoaderCallback cb;
  void *cb_cls;
};


static int
find_libraries (void *cls, const char *filename)
{
  struct LoadAllContext *lac = cls;
  const char *slashpos;
  const char *libname;
  char *basename;
  char *dot;
  void *lib_ret;
  size_t n;

  libname = filename;
  while (NULL != (slashpos = strstr (libname, DIR_SEPARATOR_STR)))
    libname = slashpos + 1;
  n = strlen (libname);
  if (0 != strncmp (lac->basename, libname, strlen (lac->basename)))
    return GNUNET_OK;           /* wrong name */
  if ((n > 3) && (0 == strcmp (&libname[n - 3], ".la")))
    return GNUNET_OK;           /* .la file */
  basename = GNUNET_strdup (libname);
  if (NULL != (dot = strstr (basename, ".")))
    *dot = '\0';
  lib_ret = GNUNET_PLUGIN_load (basename, lac->arg);
  if (NULL != lib_ret)
    lac->cb (lac->cb_cls, basename, lib_ret);
  GNUNET_free (basename);
  return GNUNET_OK;
}


/**
 * Load all compatible plugins with the given base name.
 *
 * Note that the library must export symbols called
 * "basename_ANYTHING_init" and "basename_ANYTHING__done".  These will
 * be called when the library is loaded and unloaded respectively.
 *
 * @param basename basename of the plugins to load
 * @param arg argument to the plugin initialization function
 * @param cb function to call for each plugin found
 * @param cb_cls closure for 'cb'
 */
void
GNUNET_PLUGIN_load_all (const char *basename, void *arg,
                        GNUNET_PLUGIN_LoaderCallback cb, void *cb_cls)
{
  struct LoadAllContext lac;
  char *path;

  path = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBDIR);
  if (path == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not determine plugin installation path.\n"));
    return;
  }
  lac.basename = basename;
  lac.arg = arg;
  lac.cb = cb;
  lac.cb_cls = cb_cls;
  GNUNET_DISK_directory_scan (path, &find_libraries, &lac);
  GNUNET_free (path);
}


/* end of plugin.c */

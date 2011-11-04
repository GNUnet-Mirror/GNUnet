/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_plugin_lib.h
 * @brief plugin loading and unloading
 * @author Christian Grothoff
 */

#ifndef GNUNET_PLUGIN_LIB_H
#define GNUNET_PLUGIN_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"


/**
 * Signature of any function exported by a plugin.
 *
 * @param arg argument to the function (context)
 * @return some pointer, NULL if the plugin was
 *         shutdown or if there was an error, otherwise
 *         the plugin's API on success
 */
typedef void *(*GNUNET_PLUGIN_Callback) (void *arg);


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
GNUNET_PLUGIN_test (const char *library_name);


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
 * @return whatever the initialization function returned, NULL on error
 */
void *
GNUNET_PLUGIN_load (const char *library_name, void *arg);


/**
 * Signature of a function called by 'GNUNET_PLUGIN_load_all'.
 *
 * @param cls closure
 * @param library_name full name of the library (to be used with
 *        'GNUNET_PLUGIN_unload')
 * @param lib_ret return value from the initialization function
 *        of the library (same as what 'GNUNET_PLUGIN_load' would
 *        have returned for the given library name)
 */
typedef void (*GNUNET_PLUGIN_LoaderCallback) (void *cls,
                                              const char *library_name,
                                              void *lib_ret);


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
                        GNUNET_PLUGIN_LoaderCallback cb, void *cb_cls);


/**
 * Unload plugin (runs the "done" callback and returns whatever "done"
 * returned).  The plugin is then unloaded.
 *
 * @param library_name name of the plugin to unload
 * @param arg argument to the plugin shutdown function
 * @return whatever the shutdown function returned, typically NULL
 *         or a "char *" representing the error message
 */
void *
GNUNET_PLUGIN_unload (const char *library_name, void *arg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_PLUGIN_LIB_H */
#endif
/* end of gnunet_plugin_lib.h */

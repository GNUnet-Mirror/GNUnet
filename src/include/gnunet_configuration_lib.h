/*
     This file is part of GNUnet.
     (C) 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_configuration_lib.h
 * @brief configuration API
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_CONFIGURATION_LIB_H
#define GNUNET_CONFIGURATION_LIB_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_time_lib.h"

/**
 * A configuration object.
 */
struct GNUNET_CONFIGURATION_Handle;

/**
 * Create a new configuration object.
 * @return fresh configuration object
 */
struct GNUNET_CONFIGURATION_Handle *GNUNET_CONFIGURATION_create (void);


/**
 * Duplicate an existing configuration object.
 *
 * @param c configuration to duplicate
 * @return duplicate configuration
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_dup (const struct GNUNET_CONFIGURATION_Handle *c);


/**
 * Destroy configuration object.
 */
void GNUNET_CONFIGURATION_destroy (struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Load configuration.  This function will first parse the
 * defaults and then parse the specific configuration file
 * to overwrite the defaults.
 *
 * @param filename name of the configuration file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_load (struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *filename);


/**
 * Parse a configuration file, add all of the options in the
 * file to the configuration environment.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_parse (struct GNUNET_CONFIGURATION_Handle *cfg,
                                const char *filename);


/**
 * Write configuration file.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_write (struct GNUNET_CONFIGURATION_Handle *cfg,
                                const char *filename);


/**
 * Test if there are configuration options that were
 * changed since the last save.
 * @return GNUNET_NO if clean, GNUNET_YES if dirty, GNUNET_SYSERR on error (i.e. last save failed)
 */
int GNUNET_CONFIGURATION_is_dirty (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Function to iterate over options.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
typedef void (*GNUNET_CONFIGURATION_Iterator)(void *cls,
					      const char *section,
					      const char *option,
					      const char *value);


/**
 * Iterate over all options in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each option
 * @param iter_cls closure for iter
 */
void GNUNET_CONFIGURATION_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
				   GNUNET_CONFIGURATION_Iterator iter,
				   void *iter_cls);


/**
 * Get a configuration value that should be a number.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_get_value_number (const struct GNUNET_CONFIGURATION_Handle
                                           *cfg, const char *section,
                                           const char *option,
                                           unsigned long long *number);

/**
 * Get a configuration value that should be a relative time.
 *
 * @param time set to the time value stored in the configuration
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_get_value_time (const struct GNUNET_CONFIGURATION_Handle
					 *cfg, const char *section,
					 const char *option,
					 struct GNUNET_TIME_Relative *time);

/**
 * Test if we have a value for a particular option
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int GNUNET_CONFIGURATION_have_value (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section, const char *option);

/**
 * Get a configuration value that should be a string.
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_get_value_string (const struct GNUNET_CONFIGURATION_Handle
                                           *cfg, const char *section,
                                           const char *option, char **value);

/**
 * Get a configuration value that should be the name of a file
 * or directory.
 *
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_get_value_filename (const struct
                                             GNUNET_CONFIGURATION_Handle *cfg,
                                             const char *section,
                                             const char *option,
                                             char **value);

/**
 * Iterate over the set of filenames stored in a configuration value.
 *
 * @return number of filenames iterated over, -1 on error
 */
int GNUNET_CONFIGURATION_iterate_value_filenames (const struct
                                                  GNUNET_CONFIGURATION_Handle
                                                  *cfg,
                                                  const char *section,
                                                  const char *option,
                                                  GNUNET_FileNameCallback
                                                  cb, void *cls);

/**
 * Get a configuration value that should be in a set of
 * predefined strings
 *
 * @param choices NULL-terminated list of legal values
 * @param value will be set to an entry in the legal list,
 *        or NULL if option is not specified and no default given
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_CONFIGURATION_get_value_choice (const struct GNUNET_CONFIGURATION_Handle
                                           *cfg, const char *section,
                                           const char *option,
                                           const char **choices,
                                           const char **value);

/**
 * Get a configuration value that should be in a set of
 * "YES" or "NO".
 *
 * @return GNUNET_YES, GNUNET_NO or if option has no valid value, GNUNET_SYSERR
 */
int GNUNET_CONFIGURATION_get_value_yesno (const struct GNUNET_CONFIGURATION_Handle
                                          *cfg, const char *section,
                                          const char *option);

/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment
 * "FOO" is set to "DIRECTORY".

 * @param old string to $-expand (will be freed!)
 * @return $-expanded string
 */
char *GNUNET_CONFIGURATION_expand_dollar (const struct GNUNET_CONFIGURATION_Handle
                                          *cfg, char *old);

/**
 * Set a configuration value that should be a number.
 */
void
GNUNET_CONFIGURATION_set_value_number (struct GNUNET_CONFIGURATION_Handle
                                       *cfg,
                                       const char *section,
                                       const char *option,
                                       unsigned long long number);


/**
 * Set a configuration value that should be a string.
 * @param value
 */
void
GNUNET_CONFIGURATION_set_value_string (struct GNUNET_CONFIGURATION_Handle
                                       *cfg,
                                       const char *section,
                                       const char *option, const char *value);

/**
 * Remove a filename from a configuration value that
 * represents a list of filenames
 *
 * @param value filename to remove
 * @return GNUNET_OK on success,
 *         GNUNET_SYSERR if the filename is not in the list
 */
int GNUNET_CONFIGURATION_remove_value_filename (struct
                                                GNUNET_CONFIGURATION_Handle
                                                *cfg,
                                                const char *section,
                                                const char *option,
                                                const char *value);

/**
 * Append a filename to a configuration value that
 * represents a list of filenames
 *
 * @param value filename to append
 * @return GNUNET_OK on success,
 *         GNUNET_SYSERR if the filename already in the list
 */
int GNUNET_CONFIGURATION_append_value_filename (struct
                                                GNUNET_CONFIGURATION_Handle
                                                *cfg, const char *section,
                                                const char *option,
                                                const char *value);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

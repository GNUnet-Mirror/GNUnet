/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2008, 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @author Christian Grothoff
 *
 * @file
 * Configuration API
 *
 * @defgroup configuration  Configuration library
 * Configuration management
 * @{
 */
#ifndef GNUNET_CONFIGURATION_LIB_H
#define GNUNET_CONFIGURATION_LIB_H

#include "gnunet_time_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * A configuration object.
 */
struct GNUNET_CONFIGURATION_Handle;

/**
 * Create a new configuration object.
 * @return fresh configuration object
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_create (void);


/**
 * Duplicate an existing configuration object.
 *
 * @param cfg configuration to duplicate
 * @return duplicate configuration
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_dup (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy configuration object.
 *
 * @param cfg configuration to destroy
 */
void
GNUNET_CONFIGURATION_destroy (struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Load configuration.  This function will first parse the
 * defaults and then parse the specific configuration file
 * to overwrite the defaults.
 *
 * @param cfg configuration to update
 * @param filename name of the configuration file, NULL to load defaults
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_load (struct GNUNET_CONFIGURATION_Handle *cfg,
                           const char *filename);


/**
 * Load default configuration.  This function will parse the
 * defaults from the given @a defaults_d directory.
 *
 * @param cfg configuration to update
 * @param defaults_d directory with the defaults
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_load_from (struct GNUNET_CONFIGURATION_Handle *cfg,
				const char *defaults_d);


/**
 * Parse a configuration file, add all of the options in the
 * file to the configuration environment.
 *
 * @param cfg configuration to update
 * @param filename name of the configuration file
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_parse (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename);


/**
 * Serializes the given configuration.
 *
 * @param cfg configuration to serialize
 * @param size will be set to the size of the serialized memory block
 * @return the memory block where the serialized configuration is
 *           present. This memory should be freed by the caller
 */
char *
GNUNET_CONFIGURATION_serialize (const struct GNUNET_CONFIGURATION_Handle *cfg,
				size_t *size);


/**
 * De-serializes configuration
 *
 * @param cfg configuration to update
 * @param mem the memory block of serialized configuration
 * @param size the size of the memory block
 * @param allow_inline set to the base directory if we recursively load configuration
 *          from inlined configurations; NULL if not and raise warnings
 *          when we come across them
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_deserialize (struct GNUNET_CONFIGURATION_Handle *cfg,
				  const char *mem,
				  size_t size,
				  const char *basedir);


/**
 * Write configuration file.
 *
 * @param cfg configuration to write
 * @param filename where to write the configuration
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_write (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename);


/**
 * Write only configuration entries that have been changed to configuration file
 * @param cfg_default default configuration
 * @param cfg_new new configuration
 * @param filename where to write the configuration diff between default and new
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_write_diffs (const struct GNUNET_CONFIGURATION_Handle *cfg_default,
                                  const struct GNUNET_CONFIGURATION_Handle *cfg_new,
                                  const char *filename);


/**
 * Compute configuration with only entries that have been changed
 *
 * @param cfg_default original configuration
 * @param cfg_new new configuration
 * @return configuration with only the differences, never NULL
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_get_diff (const struct GNUNET_CONFIGURATION_Handle *cfg_default,
			       const struct GNUNET_CONFIGURATION_Handle *cfg_new);


/**
 * Test if there are configuration options that were
 * changed since the last save.
 *
 * @param cfg configuration to inspect
 * @return #GNUNET_NO if clean, #GNUNET_YES if dirty, #GNUNET_SYSERR on error (i.e. last save failed)
 */
int
GNUNET_CONFIGURATION_is_dirty (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Function to iterate over options.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
typedef void
(*GNUNET_CONFIGURATION_Iterator) (void *cls,
                                  const char *section,
                                  const char *option,
                                  const char *value);


/**
 * Function to iterate over section.
 *
 * @param cls closure
 * @param section name of the section
 */
typedef void
(*GNUNET_CONFIGURATION_Section_Iterator) (void *cls,
                                          const char *section);


/**
 * Iterate over all options in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each option
 * @param iter_cls closure for @a iter
 */
void
GNUNET_CONFIGURATION_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              GNUNET_CONFIGURATION_Iterator iter,
                              void *iter_cls);


/**
 * Iterate over all sections in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each section
 * @param iter_cls closure for @a iter
 */
void
GNUNET_CONFIGURATION_iterate_sections (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       GNUNET_CONFIGURATION_Section_Iterator iter,
                                       void *iter_cls);


/**
 * Remove the given section and all options in it.
 *
 * @param cfg configuration to inspect
 * @param section name of the section to remove
 */
void
GNUNET_CONFIGURATION_remove_section (struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section);


/**
 * Get a configuration value that should be a number.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param number where to store the numeric value of the option
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_number (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       unsigned long long *number);


/**
 * Get a configuration value that should be a floating point number.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param number where to store the floating value of the option
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_float  (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       float *number);


/**
 * Get a configuration value that should be a relative time.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param time set to the time value stored in the configuration
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_time (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section,
                                     const char *option,
                                     struct GNUNET_TIME_Relative *time);



/**
 * Get a configuration value that should be a size in bytes.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param size set to the size in bytes as stored in the configuration
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_size (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section,
                                     const char *option,
                                     unsigned long long *size);


/**
 * Test if we have a value for a particular option
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @return #GNUNET_YES if so, #GNUNET_NO if not.
 */
int
GNUNET_CONFIGURATION_have_value (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char *section,
                                 const char *option);


/**
 * Get a configuration value that should be a string.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_string (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       char **value);


/**
 * Get a configuration value that should be the name of a file
 * or directory.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_filename (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                         const char *section,
                                         const char *option,
                                         char **value);


/**
 * Iterate over the set of filenames stored in a configuration value.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param cb function to call on each filename
 * @param cb_cls closure for @a cb
 * @return number of filenames iterated over, -1 on error
 */
int
GNUNET_CONFIGURATION_iterate_value_filenames (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                              const char *section,
                                              const char *option,
                                              GNUNET_FileNameCallback cb,
                                              void *cb_cls);

/**
 * Iterate over values of a section in the configuration.
 *
 * @param cfg configuration to inspect
 * @param section the section
 * @param iter function to call on each option
 * @param iter_cls closure for @a iter
 */
void
GNUNET_CONFIGURATION_iterate_section_values (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                             const char *section,
                                             GNUNET_CONFIGURATION_Iterator iter,
                                             void *iter_cls);

/**
 * Get a configuration value that should be in a set of
 * predefined strings
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param choices NULL-terminated list of legal values
 * @param value will be set to an entry in the legal list,
 *        or NULL if option is not specified and no default given
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_choice (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       const char *const *choices,
                                       const char **value);

/**
 * Get a configuration value that should be in a set of
 * "YES" or "NO".
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @return #GNUNET_YES, #GNUNET_NO or if option has no valid value, #GNUNET_SYSERR
 */
int
GNUNET_CONFIGURATION_get_value_yesno (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                      const char *section,
                                      const char *option);


/**
 * Get Crockford32-encoded fixed-size binary data from a configuration.
 *
 * @param cfg configuration to access
 * @param section section to access
 * @param option option to access
 * @param buf where to store the decoded binary result
 * @param buf_size exact number of bytes to store in @a buf
 * @return #GNUNET_OK on success
 *         #GNUNET_NO is the value does not exist
 *         #GNUNET_SYSERR on decoding error
 */
int
GNUNET_CONFIGURATION_get_data (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *section,
                               const char *option,
                               void *buf,
                               size_t buf_size);


/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment "FOO" is
 * set to "DIRECTORY".  We also support default expansion,
 * i.e. ${VARIABLE:-default} will expand to $VARIABLE if VARIABLE is
 * set in PATHS or the environment, and otherwise to "default".  Note
 * that "default" itself can also be a $-expression, thus
 * "${VAR1:-{$VAR2}}" will expand to VAR1 and if that is not defined
 * to VAR2.
 *
 * @param cfg configuration to use for path expansion
 * @param orig string to $-expand (will be freed!)  Note that multiple
 *          $-expressions can be present in this string.  They will all be
 *          $-expanded.
 * @return $-expanded string
 */
char *
GNUNET_CONFIGURATION_expand_dollar (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                    char *orig);


/**
 * Set a configuration value that should be a number.
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param number value to set
 */
void
GNUNET_CONFIGURATION_set_value_number (struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       unsigned long long number);


/**
 * Set a configuration value that should be a string.
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param value value to set
 */
void
GNUNET_CONFIGURATION_set_value_string (struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       const char *value);


/**
 * Remove a filename from a configuration value that
 * represents a list of filenames
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param value filename to remove
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if the filename is not in the list
 */
int
GNUNET_CONFIGURATION_remove_value_filename (struct GNUNET_CONFIGURATION_Handle *cfg,
                                            const char *section,
                                            const char *option,
                                            const char *value);


/**
 * Append a filename to a configuration value that
 * represents a list of filenames
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param value filename to append
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if the filename already in the list
 */
int
GNUNET_CONFIGURATION_append_value_filename (struct GNUNET_CONFIGURATION_Handle *cfg,
                                            const char *section,
                                            const char *option,
                                            const char *value);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group configuration */

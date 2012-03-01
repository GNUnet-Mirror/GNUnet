/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_pseudonym_lib.h
 * @brief functions related to pseudonyms
 * @author Christian Grothoff
 */

#ifndef GNUNET_PSEUDONYM_LIB_H
#define GNUNET_PSEUDONYM_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_container_lib.h"

/**
 * Iterator over all known pseudonyms.
 *
 * @param cls closure
 * @param pseudonym hash code of public key of pseudonym
 * @param name name of the pseudonym (might be NULL)
 * @param unique_name unique name of the pseudonym (might be NULL)
 * @param md meta data known about the pseudonym
 * @param rating the local rating of the pseudonym
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_PSEUDONYM_Iterator) (void *cls,
                                          const GNUNET_HashCode * pseudonym,
                                          const char *name,
                                          const char *unique_name,
                                          const struct GNUNET_CONTAINER_MetaData
                                          * md, int rating);

/**
 * Change the ranking of a pseudonym.
 *
 * @param cfg overall configuration
 * @param nsid id of the pseudonym
 * @param delta by how much should the rating be changed?
 * @return new rating of the namespace
 */
int
GNUNET_PSEUDONYM_rank (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const GNUNET_HashCode * nsid, int delta);

/**
 * Add a pseudonym to the set of known pseudonyms.
 * For all pseudonym advertisements that we discover
 * FS should automatically call this function.
 *
 * @param cfg overall configuration
 * @param id the pseudonym identifier
 * @param meta metadata for the pseudonym
 */
void
GNUNET_PSEUDONYM_add (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      const GNUNET_HashCode * id,
                      const struct GNUNET_CONTAINER_MetaData *meta);


/**
 * List all known pseudonyms.
 *
 * @param cfg overall configuration
 * @param iterator function to call for each pseudonym
 * @param closure closure for iterator
 * @return number of pseudonyms found
 */
int
GNUNET_PSEUDONYM_list_all (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_PSEUDONYM_Iterator iterator, void *closure);

/**
 * Register callback to be invoked whenever we discover
 * a new pseudonym.
 */
int
GNUNET_PSEUDONYM_discovery_callback_register (const struct
                                              GNUNET_CONFIGURATION_Handle *cfg,
                                              GNUNET_PSEUDONYM_Iterator
                                              iterator, void *closure);

/**
 * Unregister namespace discovery callback.
 */
int
GNUNET_PSEUDONYM_discovery_callback_unregister (GNUNET_PSEUDONYM_Iterator
                                                iterator, void *closure);

/**
 * Return unique variant of the namespace name.
 * Use after GNUNET_PSEUDONYM_id_to_name() to make sure
 * that name is unique.
 *
 * @param cfg configuration
 * @param nsid cryptographic ID of the namespace
 * @param name name to uniquify
 * @param suffix if not NULL, filled with the suffix value
 * @return NULL on failure (should never happen), name on success.
 *         Free the name with GNUNET_free().
 */
char *
GNUNET_PSEUDONYM_name_uniquify (const struct GNUNET_CONFIGURATION_Handle *cfg,
    const GNUNET_HashCode * nsid, const char *name, unsigned int *suffix);

/**
 * Get namespace name, metadata and rank
 * This is a wrapper around internal read_info() call, and ensures that
 * returned data is not invalid (not NULL).
 * Writing back information returned by this function will give
 * a name "no-name" to pseudonyms that have no name. This side-effect is
 * unavoidable, but hardly harmful.
 *
 * @param cfg configuration
 * @param nsid cryptographic ID of the namespace
 * @param ret_meta a location to store metadata pointer. NULL, if metadata
 *        is not needed. Destroy with GNUNET_CONTAINER_meta_data_destroy().
 * @param ret_rank a location to store rank. NULL, if rank not needed.
 * @param ret_name a location to store human-readable name. Name is not unique.
 *        NULL, if name is not needed. Free with GNUNET_free().
 * @param name_is_a_dup is set to GNUNET_YES, if ret_name was filled with
 *        a duplicate of a "no-name" placeholder
 * @return GNUNET_OK on success. GNUENT_SYSERR if the data was
 *         unobtainable (in that case ret_* are filled with placeholders - 
 *         empty metadata container, rank -1 and a "no-name" name).
 */
int
GNUNET_PSEUDONYM_get_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
    const GNUNET_HashCode * nsid, struct GNUNET_CONTAINER_MetaData **ret_meta,
    int32_t *ret_rank, char **ret_name, int *name_is_a_dup);


/**
 * Get the namespace ID belonging to the given namespace name.
 *
 * @param cfg configuration to use
 * @param ns_uname unique (!) human-readable name for the namespace
 * @param nsid set to namespace ID based on 'ns_uname'
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_name_to_id (const struct GNUNET_CONFIGURATION_Handle *cfg,
    const char *ns_uname, GNUNET_HashCode * nsid);

/**
 * Set the pseudonym metadata, rank and name.
 *
 * @param cfg overall configuration
 * @param nsid id of the pseudonym
 * @param name name to set. Must be the non-unique version of it.
 *        May be NULL, in which case it erases pseudonym's name!
 * @param md metadata to set
 *        May be NULL, in which case it erases pseudonym's metadata!
 * @param rank rank to assign
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_PSEUDONYM_set_info (const struct GNUNET_CONFIGURATION_Handle *cfg,
    const GNUNET_HashCode * nsid, const char *name,
    const struct GNUNET_CONTAINER_MetaData *md, int rank);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSEUDONYM_LIB_H */
#endif
/* end of gnunet_pseudonym_lib.h */

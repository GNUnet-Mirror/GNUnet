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
 * @param md meta data known about the pseudonym
 * @param rating the local rating of the pseudonym
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_PSEUDONYM_Iterator) (void *cls,
                                          const GNUNET_HashCode * pseudonym,
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
 * Return the unique, human readable name for the given pseudonym.
 *
 * @return NULL on failure (should never happen)
 */
char *
GNUNET_PSEUDONYM_id_to_name (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const GNUNET_HashCode * pseudo);

/**
 * Get the pseudonym ID belonging to the given human readable name.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_PSEUDONYM_name_to_id (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *hname, GNUNET_HashCode * psid);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSEUDONYM_LIB_H */
#endif
/* end of gnunet_pseudonym_lib.h */

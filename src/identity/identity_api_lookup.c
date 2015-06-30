/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public Liceidentity as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public Liceidentity for more details.

     You should have received a copy of the GNU General Public Liceidentity
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file identity/identity_api_lookup.c
 * @brief api to lookup an ego
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "identity-api",__VA_ARGS__)


/**
 * Handle for ego lookup.
 */
struct GNUNET_IDENTITY_EgoLookup
{

  /**
   * Handle to the identity service.
   */
  struct GNUNET_IDENTITY_Handle *identity;

  /**
   * Name of the ego we are looking up.
   */
  char *name;

  /**
   * Function to call with the result.
   */
  GNUNET_IDENTITY_EgoCallback cb;

  /**
   * Closure for @e cb
   */
  void *cb_cls;
};


/**
 * Method called to inform about the egos of this peer.
 *
 * When used with #GNUNET_IDENTITY_connect, this function is
 * initially called for all egos and then again whenever a
 * ego's name changes or if it is deleted.  At the end of
 * the initial pass over all egos, the function is once called
 * with 'NULL' for @a ego. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * If the @a name matches the name from @a cls, we found the zone
 * for our computation and will invoke the callback.
 * If we have iterated over all egos and not found the name, we
 * invoke the callback with NULL.
 *
 * @param cls closure with the `struct GNUNET_IDENTITY_EgoLookup`
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_cb (void *cls,
	     struct GNUNET_IDENTITY_Ego *ego,
	     void **ctx,
	     const char *name)
{
  struct GNUNET_IDENTITY_EgoLookup *el = cls;

  if ( (NULL != name) &&
       (0 == strcmp (name,
		     el->name)) )
  {
    el->cb (el->cb_cls,
	    ego);
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    return;
  }
  if (NULL == ego)
  {
    /* not found */
    el->cb (el->cb_cls,
	    NULL);
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    return;
  }
}


/**
 * Lookup an ego by name.
 *
 * @param cfg configuration to use
 * @param name name to look up
 * @param cb callback to invoke with the result
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct GNUNET_IDENTITY_EgoLookup *
GNUNET_IDENTITY_ego_lookup (const struct GNUNET_CONFIGURATION_Handle *cfg,
			    const char *name,
			    GNUNET_IDENTITY_EgoCallback cb,
			    void *cb_cls)
{
  struct GNUNET_IDENTITY_EgoLookup *el;

  el = GNUNET_new (struct GNUNET_IDENTITY_EgoLookup);
  el->name = GNUNET_strdup (name);
  el->cb = cb;
  el->cb_cls = cb_cls;
  el->identity = GNUNET_IDENTITY_connect (cfg,
					  &identity_cb,
					  el);
  return el;
}


/**
 * Abort ego lookup attempt.
 *
 * @param el handle for lookup to abort
 */
void
GNUNET_IDENTITY_ego_lookup_cancel (struct GNUNET_IDENTITY_EgoLookup *el)
{
  GNUNET_IDENTITY_disconnect (el->identity);
  GNUNET_free (el->name);
  GNUNET_free (el);
}


/* end of identity_api_lookup.c */

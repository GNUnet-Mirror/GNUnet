/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016, 2018 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file gns/gns_tld_api.c
 * @brief library to access the GNS service, including TLD lookup
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "gns.h"
#include "gns_api.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "gns-tld-api", __VA_ARGS__)


/**
 * Handle to a lookup request
 */
struct GNUNET_GNS_LookupWithTldRequest
{

  /**
   * handle to gns
   */
  struct GNUNET_GNS_Handle *gns_handle;

  /**
   * processor to call on lookup result
   */
  GNUNET_GNS_LookupResultProcessor2 lookup_proc;

  /**
   * Domain name we are resolving.
   */
  char *name;

  /**
   * @e lookup_proc closure
   */
  void *lookup_proc_cls;

  /**
   * Underlying GNS lookup.
   */
  struct GNUNET_GNS_LookupRequest *lr;

  /**
   * Lookup an ego with the identity service.
   */
  struct GNUNET_IDENTITY_EgoSuffixLookup *id_co;

  /**
   * Name of the longest matching ego found so far.
   * Must be freed on termination.
   */
  char *longest_match;

  /**
   * Ego corresponding to @e longest_match.
   */
  struct GNUNET_IDENTITY_Ego *longest_match_ego;

  /**
   * Desired result record type.
   */
  uint32_t type;

  /**
   * Lookup options.
   */
  enum GNUNET_GNS_LocalOptions options;
};


/**
 * Obtain the TLD of the given @a name.
 *
 * @param name a name
 * @return the part of @a name after the last ".",
 *         or @a name if @a name does not contain a "."
 */
static const char *
get_tld (const char *name)
{
  const char *tld;

  tld = strrchr (name, (unsigned char) '.');
  if (NULL == tld)
    tld = name;
  else
    tld++; /* skip the '.' */
  return tld;
}


/**
 * Eat the "TLD" (last bit) of the given @a name.
 *
 * @param[in,out] name a name
 * @param tld what to eat (can be more than just the tld)
 */
static void
eat_tld (char *name, const char *tld)
{
  GNUNET_assert (0 < strlen (name));
  if ((NULL == tld) || (strlen (name) == strlen (tld)))
  {
    strcpy (name, GNUNET_GNS_EMPTY_LABEL_AT);
  }
  else
  {
    GNUNET_assert (strlen (tld) < strlen (name));
    name[strlen (name) - strlen (tld) - 1] = '\0';
  }
}


/**
 * Function called with the result of a GNS lookup.
 *
 * @param cls a `struct GNUNET_GNS_LookupWithTldRequest *`
 * @param rd_count number of records returned
 * @param rd array of @a rd_count records with the results
 */
static void
process_lookup_result (void *cls,
                       uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNS_LookupWithTldRequest *ltr = cls;

  ltr->lr = NULL;
  ltr->lookup_proc (ltr->lookup_proc_cls, GNUNET_YES, rd_count, rd);
  GNUNET_GNS_lookup_with_tld_cancel (ltr);
}


/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key.
 *
 * @param pkey public key to use for the zone, can be NULL
 */
static void
lookup_with_public_key (struct GNUNET_GNS_LookupWithTldRequest *ltr,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
{
  ltr->lr = GNUNET_GNS_lookup (ltr->gns_handle,
                               ltr->name,
                               pkey,
                               ltr->type,
                               ltr->options,
                               &process_lookup_result,
                               ltr);
}


/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is determined by a name.
 *
 * @param cls a `struct GNUNET_GNS_LookupWithTldRequest *`
 * @param ego ego handle, NULL at the end of the iteration
 * @param ctx context we could store data to associate with @e ego
 * @param name name of the ego
 */
static void
identity_zone_cb (void *cls,
		  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
		  const char *ego_name)
{
  struct GNUNET_GNS_LookupWithTldRequest *ltr = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  ltr->id_co = NULL;
  if (NULL == priv)
  {
    /* no matching ego found */
    ltr->lookup_proc (ltr->lookup_proc_cls, GNUNET_NO, 0, NULL);
    return;
  }
  /* Final case: TLD matches one of our egos */
  if (0 == strcmp (ltr->name, ego_name))
  {
    /* name matches ego name perfectly, only "@" remains */
    strcpy (ltr->name, GNUNET_GNS_EMPTY_LABEL_AT);
  }
  else
  {
    GNUNET_assert (strlen (ego_name) < strlen (ltr->name));
    ltr->name[strlen (ltr->name) - strlen (ego_name) - 1] = '\0';
  }
  /* if the name is of the form 'label' (and not 'label.SUBDOMAIN'), never go to the DHT */
  if (NULL == strchr (ltr->name, (unsigned char) '.'))
    ltr->options = GNUNET_GNS_LO_NO_DHT;
  else
    ltr->options = GNUNET_GNS_LO_LOCAL_MASTER;
  GNUNET_CRYPTO_ecdsa_key_get_public (priv, &pkey);
  lookup_with_public_key (ltr, &pkey);
}


/**
 * Perform an asynchronous lookup operation on the GNS,
 * determining the zone using the TLD of the given name
 * and the current configuration to resolve TLDs to zones.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up, including TLD
 * @param type the record type to look up
 * @param options local options for the lookup
 * @param proc processor to call on result
 * @param proc_cls closure for @a proc
 * @return handle to the get request, NULL on error (i.e. bad configuration)
 */
struct GNUNET_GNS_LookupWithTldRequest *
GNUNET_GNS_lookup_with_tld (struct GNUNET_GNS_Handle *handle,
                            const char *name,
                            uint32_t type,
                            enum GNUNET_GNS_LocalOptions options,
                            GNUNET_GNS_LookupResultProcessor2 proc,
                            void *proc_cls)
{
  struct GNUNET_GNS_LookupWithTldRequest *ltr;
  const char *tld;
  char *dot_tld;
  char *zonestr;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  ltr = GNUNET_new (struct GNUNET_GNS_LookupWithTldRequest);
  ltr->gns_handle = handle;
  ltr->name = GNUNET_strdup (name);
  ltr->type = type;
  ltr->options = options;
  ltr->lookup_proc = proc;
  ltr->lookup_proc_cls = proc_cls;
  /* start with trivial case: TLD is zkey */
  tld = get_tld (ltr->name);
  if (GNUNET_OK ==
      GNUNET_CRYPTO_ecdsa_public_key_from_string (tld, strlen (tld), &pkey))
  {
    eat_tld (ltr->name, tld);
    lookup_with_public_key (ltr, &pkey);
    return ltr;
  }

  /* second case: domain is mapped in our configuration file */
  for (const char *domain = name; NULL != domain;
       domain = strchr (domain, (unsigned char) '.'))
  {
    if ('.' == domain[0])
      domain++;
    GNUNET_asprintf (&dot_tld, ".%s", domain);
    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (handle->cfg,
                                                            "gns",
                                                            dot_tld,
                                                            &zonestr))
    {
      if (GNUNET_OK !=
          GNUNET_CRYPTO_ecdsa_public_key_from_string (zonestr,
                                                      strlen (zonestr),
                                                      &pkey))
      {
        GNUNET_log_config_invalid (
          GNUNET_ERROR_TYPE_ERROR,
          "gns",
          dot_tld,
          _ ("Expected a base32-encoded public zone key\n"));
        GNUNET_free (zonestr);
        GNUNET_free (dot_tld);
        GNUNET_free (ltr->name);
        GNUNET_free (ltr);
        return NULL;
      }
      eat_tld (ltr->name, &dot_tld[1]);
      GNUNET_free (zonestr);
      GNUNET_free (dot_tld);
      lookup_with_public_key (ltr, &pkey);
      return ltr;
    }
    GNUNET_free (dot_tld);
  }
  ltr->id_co =
    GNUNET_IDENTITY_ego_lookup_by_suffix (ltr->gns_handle->cfg,
					  ltr->name,
					  &identity_zone_cb,
					  ltr);
  if (NULL == ltr->id_co)
  {
    GNUNET_free (ltr->name);
    GNUNET_free (ltr);
    return NULL;
  }
  return ltr;
}


/**
 * Cancel pending lookup request
 *
 * @param ltr the lookup request to cancel
 * @return closure from the lookup result processor
 */
void *
GNUNET_GNS_lookup_with_tld_cancel (struct GNUNET_GNS_LookupWithTldRequest *ltr)
{
  void *ret = ltr->lookup_proc_cls;

  if (NULL != ltr->id_co)
  {
    GNUNET_IDENTITY_ego_lookup_by_suffix_cancel (ltr->id_co);
    ltr->id_co = NULL;
  }
  if (NULL != ltr->lr)
  {
    GNUNET_GNS_lookup_cancel (ltr->lr);
    ltr->lr = NULL;
  }
  GNUNET_free_non_null (ltr->longest_match);
  GNUNET_free (ltr->name);
  GNUNET_free (ltr);
  return ret;
}

/* end of gns_tld_api.c */

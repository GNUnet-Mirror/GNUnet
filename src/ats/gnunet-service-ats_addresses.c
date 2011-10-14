/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_addresses.c
 * @brief ats service address management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_scheduling.h"

struct ATS_Address
{
  struct GNUNET_PeerIdentity peer;

  size_t addr_len;

  struct GNUNET_SERVER_Client *session_client;
		   
  uint32_t session_id;

  uint32_t ats_count;

  void * addr;

  char * plugin;

  struct GNUNET_TRANSPORT_ATS_Information * ats;

  struct GNUNET_BANDWIDTH_Value32NBO bw_in;

  struct GNUNET_BANDWIDTH_Value32NBO bw_out;
};


static struct GNUNET_CONTAINER_MultiHashMap * addresses;


struct CompareAddressContext
{
  struct ATS_Address * search;
  struct ATS_Address * result;
};


static int 
compare_address_it (void *cls,
		    const GNUNET_HashCode * key,
		    void *value)
{
  struct CompareAddressContext * cac = cls;
  struct ATS_Address * aa = (struct ATS_Address *) value;

  /* compare sessions */
  if ((aa->session_client != cac->search->session_client) ||
      (aa->session_id != cac->search->session_id))
    return GNUNET_YES;

  if (0 == strcmp(aa->plugin, cac->search->plugin))
  {
    if ((aa->addr_len == cac->search->addr_len) &&
        (0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)))
      cac->result = aa;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

struct ATS_Address *
find_address (const struct GNUNET_PeerIdentity *peer,
              struct ATS_Address * addr)
{
  struct CompareAddressContext cac;
  cac.result = NULL;
  cac.search = addr;

  GNUNET_CONTAINER_multihashmap_get_multiple(addresses,
         &peer->hashPubKey,
         compare_address_it,
         &cac);

  return cac.result;
}

static void
merge_ats (struct ATS_Address * dest, struct ATS_Address * source)
{
  /*
  int c_src = 0;
  int c_dest = 0;
  struct GNUNET_TRANSPORT_ATS_Information * a_src = source->ats;
  struct GNUNET_TRANSPORT_ATS_Information * a_dest = dest->ats;

  int new_entries = dest->ats_count;

  for (c_dest = 0; c_dest < dest->ats_count; c_dest ++)
  {
    for (c_src = 0; c_src < source->ats_count; c_src ++)
    {
      if (a_src[c_src].type == a_dest[c_dest].type)
        new_entries--;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    "Have %u new entries\n",
    new_entries);
*/
}

void
GAS_address_update (const struct GNUNET_PeerIdentity *peer,
		    const char *plugin_name,
		    const void *plugin_addr, size_t plugin_addr_len,
		    struct GNUNET_SERVER_Client *session_client,
		    uint32_t session_id,
		    const struct GNUNET_TRANSPORT_ATS_Information *atsi,
		    uint32_t atsi_count)
{
  struct ATS_Address * aa;
  struct ATS_Address * old;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) +
                      plugin_addr_len);
  aa->ats = GNUNET_malloc(atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));

  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->ats_count = atsi_count;
  memcpy (aa->ats, atsi, atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  aa->addr = &aa[1];
  memcpy (&aa->addr, plugin_addr, plugin_addr_len);
  aa->plugin = GNUNET_strdup (plugin_name);
  aa->session_client = session_client;
  aa->session_id = session_id;

  old = find_address (peer, aa);
  if (old == NULL)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put(addresses,
                                                     &peer->hashPubKey,
                                                     aa,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Added new address for peer `%s' %X\n",
      GNUNET_i2s (peer), aa);
  }
  else
  {
    merge_ats (old, aa);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Updated existing address for peer `%s' %X \n",
      GNUNET_i2s (peer), old);
    GNUNET_free (aa->ats);
    GNUNET_free (aa);
  }

}


void
GAS_address_destroyed (const struct GNUNET_PeerIdentity *peer,
		       const char *plugin_name,
		       const void *plugin_addr, size_t plugin_addr_len,
		       struct GNUNET_SERVER_Client *session_client,
		       uint32_t session_id)
{

  struct ATS_Address *aa;
  struct ATS_Address *res;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) +
                    plugin_addr_len);

  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->addr = &aa[1];
  memcpy (aa->addr, plugin_addr, plugin_addr_len);
  aa->plugin = GNUNET_strdup (plugin_name);
  aa->session_client = session_client;
  aa->session_id = session_id;

  res = find_address (peer, aa);

  GNUNET_break (GNUNET_YES ==
		GNUNET_CONTAINER_multihashmap_remove(addresses, &peer->hashPubKey, res));
  GNUNET_free (res->plugin);
  GNUNET_free_non_null (res->ats);
  GNUNET_free (res);

}


void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address * aa = NULL;
  aa = GNUNET_CONTAINER_multihashmap_get (addresses, &peer->hashPubKey);
  if (aa != NULL)
    GAS_scheduling_transmit_address_suggestion (peer, aa->plugin, aa->addr, aa->addr_len, aa->session_client, aa->session_id, aa->ats, aa->ats_count, aa->bw_out, aa->bw_in);
}


/**
 * Initialize address subsystem.
 */
void
GAS_addresses_init ()
{
  addresses = GNUNET_CONTAINER_multihashmap_create(128);
}


/**
 * Free memory of address.
 *
 * @param cls NULL
 * @param key peer identity (unused)
 * @param value the 'struct ATS_Address' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int 
free_address_it (void *cls,
		 const GNUNET_HashCode * key,
		 void *value)
{
  struct ATS_Address * aa = value;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    "Freeing address for peer `%s' %X\n",
    GNUNET_i2s (&aa->peer), aa);
  GNUNET_free (aa);
  return GNUNET_OK;
}



/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done ()
{
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &free_address_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
}


/* end of gnunet-service-ats_addresses.c */

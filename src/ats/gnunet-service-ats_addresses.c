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

static void
destroy_address (struct ATS_Address * addr)
{
  GNUNET_free_non_null (addr->ats);
  GNUNET_free (addr->plugin);
  GNUNET_free (addr);
}

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

  if (aa->addr_len != cac->search->addr_len)
  {
    return GNUNET_YES;
  }

  if (0 == strcmp(aa->plugin, cac->search->plugin))
  {
    return GNUNET_YES;
  }

  if (0 == memcmp (aa->addr, cac->search->addr, aa->addr_len))
  {
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

  aa = GNUNET_malloc (sizeof (struct ATS_Address) + plugin_addr_len);
  aa->ats = GNUNET_malloc(atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));

  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->ats_count = atsi_count;
  memcpy (aa->ats, atsi, atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  aa->addr = &aa[1];
  memcpy (aa->addr, plugin_addr, plugin_addr_len);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Updated existing address for peer `%s' %X \n",
      GNUNET_i2s (peer), old);
    GNUNET_free_non_null(old->ats);
    old->ats = NULL;
    old->ats_count = 0;
    old->ats = aa->ats;
    old->ats_count = aa->ats_count;
    GNUNET_free (aa->plugin);
    GNUNET_free (aa);
  }

}

static int
remove_client (void *cls,
               const GNUNET_HashCode * key,
               void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct ATS_Address * aa = (struct ATS_Address * ) value;

  if (aa->session_client == client)
  {
    GNUNET_CONTAINER_multihashmap_remove(addresses, key, value);
    destroy_address (aa);
  }
  return GNUNET_OK;
}



void
GAS_address_client_disconnected (struct GNUNET_SERVER_Client *client)
{
  if (addresses != NULL)
    GNUNET_CONTAINER_multihashmap_iterate(addresses, &remove_client, client);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    "Deleting address for peer `%s': `%s'\n",
    GNUNET_i2s (peer), plugin_name);

  res = find_address (peer, aa);
  if (res != NULL)
  {
    GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(addresses, &peer->hashPubKey, res));
    destroy_address (aa);
    destroy_address (res);
  }
}


void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer)
{
  struct ATS_Address * aa = NULL;
  aa = GNUNET_CONTAINER_multihashmap_get (addresses, &peer->hashPubKey);
  if (aa != NULL)
  {
    aa->bw_in.value__ = htonl (100000);
    aa->bw_out.value__ = htonl (100000);
    GAS_scheduling_transmit_address_suggestion (peer, aa->plugin, aa->addr, aa->addr_len, aa->session_client, aa->session_id, aa->ats, aa->ats_count, aa->bw_out, aa->bw_in);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Cannot provide address for peer `%s'\n",
      GNUNET_i2s (peer));
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
  GNUNET_CONTAINER_multihashmap_remove (addresses, key, value);
  destroy_address (aa);
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
  addresses = NULL;
}


/* end of gnunet-service-ats_addresses.c */

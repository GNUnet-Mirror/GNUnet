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
 */
#include "platform.h"
#include "gnunet-service-ats_addresses.h"


struct ATS_Address
{
  struct GNUNET_PeerIdentity peer;

  size_t addr_len;

  uint32_t session_id;

  uint32_t ats_count;

  void * addr;

  char * plugin;

  struct GNUNET_TRANSPORT_ATS_Information * ats;
};

static struct GNUNET_CONTAINER_MultiHashMap * addresses;


struct CompareAddressContext
{
  struct ATS_Address * search;
  struct ATS_Address * result;
};

int compare_address_it (void *cls,
               const GNUNET_HashCode * key,
               void *value)
{
  struct CompareAddressContext * cac = cls;
  struct ATS_Address * aa = (struct ATS_Address *) value;
  if (0 == strcmp(aa->plugin, cac->search->plugin))
  {
    if ((aa->addr_len == cac->search->addr_len) &&
        (0 == memcmp (aa->addr, cac->search->addr, aa->addr_len)))
      cac->result = aa;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


static int 
free_address_it (void *cls,
		 const GNUNET_HashCode * key,
		 void *value)
{
  struct ATS_Address * aa = cls;
  GNUNET_free (aa);
  return GNUNET_OK;
}


void
GAS_address_update (struct GNUNET_SERVER_Client *client,
		    const struct GNUNET_PeerIdentity *peer,
		    const char *plugin_name,
		    const void *plugin_addr, size_t plugin_addr_len,
		    uint32_t session_id,
		    const struct GNUNET_TRANSPORT_ATS_Information *atsi,
		    uint32_t atsi_count)
{
  struct ATS_Address * aa;

  aa = GNUNET_malloc (sizeof (struct ATS_Address) +
		      atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information) +
		      plugin_addr_len);
  aa->peer = *peer;
  aa->addr_len = plugin_addr_len;
  aa->ats_count = atsi_count;
  aa->ats = (struct GNUNET_TRANSPORT_ATS_Information *) &aa[1];  
  memcpy (&aa->ats, atsi, atsi_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  memcpy (aa->addr, plugin_addr, plugin_addr_len);
  aa->plugin = GNUNET_strdup (plugin_name);
  aa->session_id = session_id;

  GNUNET_assert (GNUNET_OK == 
		 GNUNET_CONTAINER_multihashmap_put(addresses, 
						   &peer->hashPubKey, 
						   aa, 
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


void
GAS_address_destroyed (struct GNUNET_SERVER_Client *client,
		       ...)
{
#if 0
  // struct AddressDestroyedMessage * msg = (struct AddressDestroyedMessage *) message;
/*
  struct GNUNET_PeerIdentity *peer = &msg->peer;
  struct ATS_Address * aa = find_address_by_addr (peer);
  GNUNET_CONTAINER_multihashmap_remove(addresses, peer, aa);
  GNUNET_free (aa);*/
#endif
}


/**
 */
void
GAS_addresses_done ()
{
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &free_address_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (addresses);
}


/**
 */
void
GAS_addresses_init ()
{
  addresses = GNUNET_CONTAINER_multihashmap_create(128);
}

/* end of gnunet-service-ats_addresses.c */

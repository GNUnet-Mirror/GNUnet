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
 * @file core/gnunet-service-core_typemap.c
 * @brief management of map that specifies which message types this peer supports
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_service_core.h"


/**
 * A type map describing which messages a given neighbour is able
 * to process.
 */
struct GSC_TypeMap 
{
  uint32_t bits[(UINT16_MAX + 1) / 32];
};


/**
 * Bitmap of message types this peer is able to handle.
 */
static uint32_t my_type_map[(UINT16_MAX + 1) / 32];


/**
 * Compute a type map message for this peer.
 *
 * @return this peers current type map message.
 */
static struct GNUNET_MessageHeader *
compute_type_map_message ()
{
  char *tmp;
  uLongf dlen;
  struct GNUNET_MessageHeader *hdr;

#ifdef compressBound
  dlen = compressBound (sizeof (my_type_map));
#else
  dlen = sizeof (my_type_map) + (sizeof (my_type_map) / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
   * should be able to overshoot by more to be safe */
#endif
  hdr = GNUNET_malloc (dlen + sizeof (struct GNUNET_MessageHeader));
  hdr->size = htons ((uint16_t) dlen + sizeof (struct GNUNET_MessageHeader));
  tmp = (char *) &hdr[1];
  if ((Z_OK !=
       compress2 ((Bytef *) tmp, &dlen, (const Bytef *) my_type_map,
                  sizeof (my_type_map), 9)) || (dlen >= sizeof (my_type_map)))
  {
    dlen = sizeof (my_type_map);
    memcpy (tmp, my_type_map, sizeof (my_type_map));
    hdr->type = htons (GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP);
  }
  else
  {
    hdr->type = htons (GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP);
  }
  return hdr;
}


/**
 * Send my type map to all connected peers (it got changed).
 */
static void
broadcast_my_type_map ()
{
  struct GNUNET_MessageHeader *hdr;

  hdr = compute_type_map_message ();
  GSC_SESSIONS_broadcast (hdr);x
  GNUNET_free (hdr);
}


/**
 * Add a set of types to our type map.
 */
void
GSC_TYPEMAP_add (const uint16_t *types,
		 unsigned int tlen)
{
  unsigned int i;

  for (i=0;i<tlen;i++)
    my_type_map[types[i] / 32] |= (1 << (types[i] % 32));
  if (tlen > 0)
    broadcast_my_type_map ();
}


/**
 * Remove a set of types from our type map.
 */
void
GSC_TYPEMAP_remove (const uint16_t *types,
		    unsigned int tlen)
{
  /* rebuild my_type_map */
  memset (my_type_map, 0, sizeof (my_type_map));
  for (pos = clients; NULL != pos; pos = pos->next)
  {
    wtypes = (const uint16_t *) &pos[1];
    for (i = 0; i < pos->tcnt; i++)
      my_type_map[wtypes[i] / 32] |= (1 << (wtypes[i] % 32));
  }
  broadcast_my_type_map ();
}


/**
 * Test if any of the types from the types array is in the
 * given type map.
 *
 * @param map map to test
 * @param types array of types
 * @param tcnt number of entries in types
 * @return GNUNET_YES if a type is in the map, GNUNET_NO if not
 */ 
int
GSC_TYPEMAP_test_match (const struct GSC_TypeMap *tmap,
			const uint16_t *types,
			unsigned int tcnt)
{  
  return GNUNET_YES; /* FIXME */
}


void
GSC_TYPEMAP_init ()
{
}


void
GSC_TYPEMAP_done ()
{
}

/* end of gnunet-service-core_typemap.c */

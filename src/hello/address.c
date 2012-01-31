/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file hello/address.c
 * @brief helper functions for handling addresses
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"


/**
 * Allocate an address struct.
 *
 * @param peer the peer
 * @param transport_name plugin name
 * @param address binary address
 * @param address_length number of bytes in 'address'
 * @return the address struct
 */
struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_allocate (const struct GNUNET_PeerIdentity *peer,
                               const char *transport_name, const void *address,
                               size_t address_length)
{
  struct GNUNET_HELLO_Address *addr;
  size_t slen;
  char *end;

  GNUNET_assert (transport_name != NULL);

  slen = strlen (transport_name) + 1;
  addr =
      GNUNET_malloc (sizeof (struct GNUNET_HELLO_Address) + address_length +
                     slen);
  addr->peer = *peer;
  addr->address = &addr[1];
  end = (char *) &addr[1];
  memcpy (end, address, address_length);
  addr->address_length = address_length;
  addr->transport_name = &end[address_length];
  memcpy (&end[address_length], transport_name, slen);
  return addr;
}


/**
 * Get the size of an address struct.
 *
 * @param address address
 * @return the size
 */
size_t
GNUNET_HELLO_address_get_size (const struct GNUNET_HELLO_Address * address)
{
  return sizeof (struct GNUNET_HELLO_Address) + address->address_length +
      strlen (address->transport_name) + 1;
}


/**
 * Copy an address struct.
 *
 * @param address address to copy
 * @return a copy of the address struct
 */
struct GNUNET_HELLO_Address *
GNUNET_HELLO_address_copy (const struct GNUNET_HELLO_Address *address)
{
  return GNUNET_HELLO_address_allocate (&address->peer, address->transport_name,
                                        address->address,
                                        address->address_length);
}


/**
 * Compare two addresses.  Does NOT compare the peer identity,
 * that is assumed already to match!
 *
 * @param a1 first address
 * @param a2 second address
 * @return 0 if the addresses are equal, -1 if a1<a2, 1 if a1>a2.
 */
int
GNUNET_HELLO_address_cmp (const struct GNUNET_HELLO_Address *a1,
                          const struct GNUNET_HELLO_Address *a2)
{
  int ret;

  ret = strcmp (a1->transport_name, a2->transport_name);
  if (0 != ret)
    return ret;
  if (a1->address_length < a2->address_length)
    return -1;
  if (a1->address_length > a2->address_length)
    return 1;
  return memcmp (a1->address, a1->address, a1->address_length);
}


/* end of address.c */

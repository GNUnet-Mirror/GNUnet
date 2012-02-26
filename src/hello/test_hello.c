/*
     This file is part of GNUnet
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
 * @file hello/test_hello.c
 * @brief test for hello.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"

#define DEBUG GNUNET_EXTRA_LOGGING

#define VERBOSE GNUNET_NO


static size_t
my_addr_gen (void *cls, size_t max, void *buf)
{
  unsigned int *i = cls;
  size_t ret;
  struct GNUNET_HELLO_Address address;

#if DEBUG
  FPRINTF (stderr, "DEBUG: my_addr_gen called with i = %d\n", *i);
#endif
  if (0 == *i)
    return 0;
  memset (&address.peer, 0, sizeof (struct GNUNET_PeerIdentity));
  address.address = "address_information";
  address.transport_name = "test";
  address.address_length = *i;
  ret =
      GNUNET_HELLO_add_address (&address, GNUNET_TIME_absolute_get (), buf,
                                max);
  (*i)--;
  return ret;
}


static int
check_addr (void *cls, const struct GNUNET_HELLO_Address *address,
            struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *i = cls;

#if DEBUG
  FPRINTF (stderr, "DEBUG: check_addr called with i = %d and addrlen = %u\n",
           *i, (unsigned int) address->address_length);
#endif
  GNUNET_assert (address->address_length > 0);
  GNUNET_assert (*i & (1 << (address->address_length - 1)));
  *i -= (1 << (address->address_length - 1));
  GNUNET_assert (0 ==
                 strncmp ("address_information", address->address,
                          address->address_length));
  GNUNET_assert (0 == strcmp ("test", address->transport_name));
  return GNUNET_OK;
}


static int
remove_some (void *cls, const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *i = cls;

#if DEBUG
  FPRINTF (stderr, "DEBUG: remove_some called with i = %d and addrlen = %u\n",
           *i, (unsigned int) address->address_length);
#endif
  GNUNET_assert (address->address_length > 0);
  if (*i & (1 << (address->address_length - 1)))
  {
    *i -= (1 << (address->address_length - 1));
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


int
main (int argc, char *argv[])
{
  struct GNUNET_HELLO_Message *msg1;
  struct GNUNET_HELLO_Message *msg2;
  struct GNUNET_HELLO_Message *msg3;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  struct GNUNET_TIME_Absolute startup_time;
  unsigned int i;

  GNUNET_log_setup ("test-hello", "DEBUG", NULL);
  startup_time = GNUNET_TIME_absolute_get ();
  memset (&publicKey, 42, sizeof (publicKey));
#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing HELLO creation (without addresses)...\n");
#endif
  i = 0;
  msg1 = GNUNET_HELLO_create (&publicKey, &my_addr_gen, &i);
  GNUNET_assert (msg1 != NULL);
  GNUNET_assert (0 < GNUNET_HELLO_size (msg1));

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing address iteration (empty set)...\n");
#endif
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg1, GNUNET_NO, &check_addr,
                                                 &i));

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing HELLO creation (with one address)...\n");
#endif
  i = 1;
  msg2 = GNUNET_HELLO_create (&publicKey, &my_addr_gen, &i);
  GNUNET_assert (msg2 != NULL);
  GNUNET_assert (GNUNET_HELLO_size (msg1) < GNUNET_HELLO_size (msg2));

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing address iteration (one address)...\n");
#endif
  i = 1;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg2, GNUNET_NO, &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing get_key from HELLO...\n");
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_key (msg2, &pk));
  GNUNET_assert (0 == memcmp (&publicKey, &pk, sizeof (pk)));
  GNUNET_free (msg1);

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing HELLO creation (with two addresses)...\n");
#endif
  i = 2;
  msg3 = GNUNET_HELLO_create (&publicKey, &my_addr_gen, &i);
  GNUNET_assert (msg3 != NULL);
  GNUNET_assert (GNUNET_HELLO_size (msg2) < GNUNET_HELLO_size (msg3));

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing address iteration (two addresses)...\n");
#endif
  i = 3;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg3, GNUNET_NO, &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing HELLO merge...\n");
#endif
  msg1 = GNUNET_HELLO_merge (msg2, msg3);
  GNUNET_assert (GNUNET_HELLO_size (msg1) == GNUNET_HELLO_size (msg3));

  i = 3;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg1, GNUNET_NO, &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);
  GNUNET_free (msg1);

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing address iteration to copy HELLO...\n");
#endif
  i = 2;
  msg1 = GNUNET_HELLO_iterate_addresses (msg3, GNUNET_YES, &remove_some, &i);
  GNUNET_assert (msg1 != NULL);
  GNUNET_assert (i == 0);
  i = 1;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg1, GNUNET_NO, &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);
  GNUNET_free (msg1);

#if VERBOSE
  FPRINTF (stderr, "%s",  "Testing delta address iteration...\n");
#endif
  i = 2;
  GNUNET_HELLO_iterate_new_addresses (msg3, msg2, startup_time, &check_addr,
                                      &i);
  GNUNET_assert (i == 0);
  GNUNET_free (msg2);
  GNUNET_free (msg3);
  return 0;                     /* testcase passed */
}

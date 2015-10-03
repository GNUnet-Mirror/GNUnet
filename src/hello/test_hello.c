/*
     This file is part of GNUnet
     Copyright (C) 2009, 2015 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file hello/test_hello.c
 * @brief test for hello.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"


/**
 *
 *
 * @param cls
 * @param max
 * @param buf
 * @return
 */
static ssize_t
my_addr_gen (void *cls,
             size_t max,
             void *buf)
{
  unsigned int *i = cls;
  size_t ret;
  struct GNUNET_HELLO_Address address;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "DEBUG: my_addr_gen called with i = %d\n",
              *i);
  if (0 == *i)
    return GNUNET_SYSERR;
  memset (&address.peer, 0, sizeof (struct GNUNET_PeerIdentity));
  address.address = "address_information";
  address.transport_name = "test";
  address.address_length = *i;
  ret = GNUNET_HELLO_add_address (&address,
                                  GNUNET_TIME_absolute_get (),
                                  buf,
                                  max);
  (*i)--;
  return ret;
}


/**
 *
 *
 * @param cls
 * @param address
 * @param expiration
 * @return
 */
static int
check_addr (void *cls,
            const struct GNUNET_HELLO_Address *address,
            struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *i = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DEBUG: check_addr called with i = %d and addrlen = %u\n",
              *i,
              (unsigned int) address->address_length);
  GNUNET_assert (address->address_length > 0);
  GNUNET_assert (*i & (1 << (address->address_length - 1)));
  *i -= (1 << (address->address_length - 1));
  GNUNET_assert (0 ==
                 strncmp ("address_information",
                          address->address,
                          address->address_length));
  GNUNET_assert (0 == strcmp ("test",
                              address->transport_name));
  return GNUNET_OK;
}


/**
 *
 *
 * @param cls
 * @param address
 * @param expiration
 * @return
 */
static int
remove_some (void *cls,
             const struct GNUNET_HELLO_Address *address,
             struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *i = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "DEBUG: remove_some called with i = %d and addrlen = %u\n",
           *i,
              (unsigned int) address->address_length);
  GNUNET_assert (address->address_length > 0);
  if (*i & (1 << (address->address_length - 1)))
  {
    *i -= (1 << (address->address_length - 1));
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_HELLO_Message *msg1;
  struct GNUNET_HELLO_Message *msg2;
  struct GNUNET_HELLO_Message *msg3;
  struct GNUNET_CRYPTO_EddsaPublicKey publicKey;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_TIME_Absolute startup_time;
  unsigned int i;

  GNUNET_log_setup ("test-hello",
                    "DEBUG",
                    NULL);
  startup_time = GNUNET_TIME_absolute_get ();
  memset (&publicKey, 42, sizeof (publicKey));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Testing HELLO creation (without addresses)...\n");
  i = 0;
  msg1 = GNUNET_HELLO_create (&publicKey,
                              &my_addr_gen,
                              &i,
                              GNUNET_NO);
  GNUNET_assert (msg1 != NULL);
  GNUNET_assert (0 < GNUNET_HELLO_size (msg1));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Testing address iteration (empty set)...\n");
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg1,
                                                 GNUNET_NO,
                                                 &check_addr,
                                                 &i));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing HELLO creation (with one address)...\n");
  i = 1;
  msg2 = GNUNET_HELLO_create (&publicKey,
                              &my_addr_gen,
                              &i,
                              GNUNET_NO);
  GNUNET_assert (msg2 != NULL);
  GNUNET_assert (GNUNET_HELLO_size (msg1) < GNUNET_HELLO_size (msg2));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing address iteration (one address)...\n");
  i = 1;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg2,
                                                 GNUNET_NO,
                                                 &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing get_key from HELLO...\n");
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_get_id (msg2, &pid));
  GNUNET_assert (0 == memcmp (&publicKey,
                              &pid.public_key,
                              sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)));
  GNUNET_free (msg1);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing HELLO creation (with two addresses)...\n");
  i = 2;
  msg3 = GNUNET_HELLO_create (&publicKey,
                              &my_addr_gen,
                              &i,
                              GNUNET_NO);
  GNUNET_assert (msg3 != NULL);
  GNUNET_assert (GNUNET_HELLO_size (msg2) < GNUNET_HELLO_size (msg3));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing address iteration (two addresses)...\n");
  i = 3;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg3,
                                                 GNUNET_NO,
                                                 &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing HELLO merge...\n");
  msg1 = GNUNET_HELLO_merge (msg2, msg3);
  GNUNET_assert (GNUNET_HELLO_size (msg1) == GNUNET_HELLO_size (msg3));

  i = 3;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg1,
                                                 GNUNET_NO,
                                                 &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);
  GNUNET_free (msg1);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing address iteration to copy HELLO...\n");
  i = 2;
  msg1 = GNUNET_HELLO_iterate_addresses (msg3,
                                         GNUNET_YES,
                                         &remove_some,
                                         &i);
  GNUNET_assert (msg1 != NULL);
  GNUNET_assert (i == 0);
  i = 1;
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (msg1,
                                                 GNUNET_NO,
                                                 &check_addr,
                                                 &i));
  GNUNET_assert (i == 0);
  GNUNET_free (msg1);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	   "Testing delta address iteration...\n");
  i = 2;
  GNUNET_HELLO_iterate_new_addresses (msg3,
                                      msg2,
                                      startup_time,
                                      &check_addr,
                                      &i);
  GNUNET_assert (i == 0);
  GNUNET_free (msg2);
  GNUNET_free (msg3);
  return 0;                     /* testcase passed */
}

/* end of test_hello.c */

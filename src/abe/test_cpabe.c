/*
     This file is part of GNUnet.
     Copyright (C) 2002, 2003, 2004, 2006 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

*/
/**
 * @author Martin Schanzenbach
 * @file util/test_crypto_abe.c
 * @brief test for ABE ciphers
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_abe_lib.h"

#define TESTSTRING "Hello World!"

static int
testAbecipher ()
{
  struct GNUNET_ABE_AbeMasterKey *msk;
  struct GNUNET_ABE_AbeKey *key;
  char *result;
  char **attrs;
  int size;
  char *res;
  msk = GNUNET_ABE_cpabe_create_master_key ();
  size = GNUNET_ABE_cpabe_encrypt (TESTSTRING, strlen (TESTSTRING) + 1,
                                      "testattr", //Policy
                                      msk,
                                      (void*)&result);
  GNUNET_assert (-1 != size);
  attrs = GNUNET_malloc (2 * sizeof (char*));
  attrs[0] = "testattr";
  attrs[1] = NULL;
  key = GNUNET_ABE_cpabe_create_key (msk,
                                        attrs);

  size = GNUNET_ABE_cpabe_decrypt (result, size,
                                      key,
                                      (void*)&res);
  if (strlen (TESTSTRING) + 1 != size)
  {
    printf ("abeciphertest failed: decryptBlock returned %d\n", size);
    return 1;
  }
  if (0 != strcmp (res, TESTSTRING))
  {
    printf ("abeciphertest failed: %s != %s\n", res, TESTSTRING);
    return 1;
  }
  else
    return 0;
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;

  GNUNET_log_setup ("test-crypto-abe", "WARNING", NULL);
  failureCount += testAbecipher ();

  if (failureCount != 0)
  {
    printf ("%d TESTS FAILED!\n", failureCount);
    return -1;
  }
  return 0;
}

/* end of test_crypto_aes.c */

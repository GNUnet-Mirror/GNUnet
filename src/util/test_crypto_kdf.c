/*
    Copyright (c) 2010 Jeffrey Burdges

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
*/

/**
 * @file src/util/test_crypt_kdf.c
 * @brief Testcases for KDF mod n
 * @author Jeffrey Burdges <burdges@gnunet.org>
 */

#include <gcrypt.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"


int
main ()
{
#define RND_BLK_SIZE 4096
  unsigned char rnd_blk[RND_BLK_SIZE];
  int i;
  gcry_mpi_t r,n;

  GNUNET_log_setup ("test-crypto-kdf", "WARNING", NULL);

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              rnd_blk,
                              RND_BLK_SIZE);

  /* test full domain hash size */
  for (i=0; i<100; i++) {
    gcry_mpi_scan (&n,
                   GCRYMPI_FMT_USG,
                   rnd_blk, RND_BLK_SIZE,
                   NULL);
    GNUNET_CRYPTO_kdf_mod_mpi (&r, n,
                               "", 0,
                               "", 0,
                               "");
    GNUNET_assert( 0 > gcry_mpi_cmp(r,n) );

    /* Is it worth checking that it's not too small? */
    /* GNUNET_assert (gcry_mpi_get_nbits(r) > 3*RND_BLK_SIZE/4); */
    /* This test necessarily randomly fails with probability 2^(3 - RND_BLK_SIZE/4) */

    gcry_mpi_release(n);
    gcry_mpi_release(r);
  }

  return 0;
}

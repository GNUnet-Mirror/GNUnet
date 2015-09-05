/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file util/test_ecc_scalarproduct.c
 * @brief testcase for math behind ECC SP calculation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

/**
 * Global context.
 */
static struct GNUNET_CRYPTO_EccDlogContext *edc;


/**
 * Perform SP calculation.
 *
 * @param avec 0-terminated vector of Alice's values
 * @param bvec 0-terminated vector of Bob's values
 * @return avec * bvec
 */
static int
test_sp (const unsigned int *avec,
         const unsigned int *bvec)
{
  unsigned int len;
  unsigned int i;
  gcry_mpi_t a;
  gcry_mpi_t a_inv;
  gcry_mpi_t ri;
  gcry_mpi_t val;
  gcry_mpi_point_t *g;
  gcry_mpi_point_t *h;
  gcry_mpi_point_t pg;
  gcry_mpi_point_t ph;
  gcry_mpi_point_t pgi;
  gcry_mpi_point_t gsp;
  int sp;

  /* determine length */
  for (len=0;0 != avec[len];len++) ;
  if (0 == len)
    return 0;

  /* Alice */
  GNUNET_CRYPTO_ecc_rnd_mpi (edc,
                             &a, &a_inv);
  g = GNUNET_new_array (len,
                        gcry_mpi_point_t);
  h = GNUNET_new_array (len,
                        gcry_mpi_point_t);
  for (i=0;i<len;i++)
  {
    gcry_mpi_t tmp;
    gcry_mpi_t ria;

    ri = GNUNET_CRYPTO_ecc_random_mod_n (edc);
    g[i] = GNUNET_CRYPTO_ecc_dexp_mpi (edc,
                                       ri);
    /* ria = ri * a */
    ria = gcry_mpi_new (0);
    gcry_mpi_mul (ria,
                  ri,
                  a);
    /* tmp = ria + avec[i] */
    tmp = gcry_mpi_new (0);
    gcry_mpi_add_ui (tmp,
                     ria,
                     avec[i]);
    gcry_mpi_release (ria);
    h[i] = GNUNET_CRYPTO_ecc_dexp_mpi (edc,
                                       tmp);
    gcry_mpi_release (tmp);
  }

  /* Bob */
  val = gcry_mpi_new (0);
  gcry_mpi_set_ui (val, bvec[0]);
  pg = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                   g[0],
                                   val);
  ph = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                   h[0],
                                   val);
  for (i=1;i<len;i++)
  {
    gcry_mpi_point_t m;
    gcry_mpi_point_t tmp;

    gcry_mpi_set_ui (val, bvec[i]);
    m = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                    g[i],
                                    val);
    tmp = GNUNET_CRYPTO_ecc_add (edc,
                                 m,
                                 pg);
    gcry_mpi_point_release (m);
    gcry_mpi_point_release (pg);
    gcry_mpi_point_release (g[i]);
    pg = tmp;

    m = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                    h[i],
                                    val);
    tmp = GNUNET_CRYPTO_ecc_add (edc,
                                 m,
                                 ph);
    gcry_mpi_point_release (m);
    gcry_mpi_point_release (ph);
    gcry_mpi_point_release (h[i]);
    ph = tmp;
  }
  gcry_mpi_release (val);
  GNUNET_free (g);
  GNUNET_free (h);

  /* Alice */
  pgi = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                    pg,
                                    a_inv);
  gsp = GNUNET_CRYPTO_ecc_add (edc,
                               pgi,
                               ph);
  gcry_mpi_point_release (pgi);
  gcry_mpi_point_release (ph);
  sp = GNUNET_CRYPTO_ecc_dlog (edc,
                               gsp);
  gcry_mpi_point_release (gsp);
  return sp;
}


int
main (int argc, char *argv[])
{
  static unsigned int v11[] = { 1, 1, 0 };
  static unsigned int v22[] = { 2, 2, 0 };
  static unsigned int v35[] = { 3, 5, 0 };
  static unsigned int v24[] = { 2, 4, 0 };

  GNUNET_log_setup ("test-ecc-scalarproduct",
		    "WARNING",
		    NULL);
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (128, 128);
  GNUNET_assert ( 2 == test_sp (v11, v11));
  GNUNET_assert ( 4 == test_sp (v22, v11));
  GNUNET_assert ( 8 == test_sp (v35, v11));
  GNUNET_assert (26 == test_sp (v35, v24));
  GNUNET_assert (26 == test_sp (v24, v35));
  GNUNET_assert (16 == test_sp (v22, v35));
  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}

/* end of test_ecc_scalarproduct.c */

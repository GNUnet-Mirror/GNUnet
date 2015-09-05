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
  return -1;
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
  GNUNET_assert ( 2 == test_sp (v11, v11));
  GNUNET_assert ( 4 == test_sp (v22, v11));
  GNUNET_assert ( 8 == test_sp (v35, v11));
  GNUNET_assert (26 == test_sp (v35, v24));
  GNUNET_assert (26 == test_sp (v24, v35));
  GNUNET_assert (16 == test_sp (v22, v35));
  return 0;
}

/* end of test_ecc_scalarproduct.c */

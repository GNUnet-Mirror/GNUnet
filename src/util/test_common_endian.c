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
 * @file util/test_common_endian.c
 * @brief testcase for common_endian.c
 */
#include "platform.h"
#include "gnunet_common.h"

#define CHECK(n) if (n != GNUNET_htonll(GNUNET_ntohll(n))) return 1;

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-common-endian", "WARNING", NULL);
  CHECK (1);
  CHECK (0x12345678);
  CHECK (123456789012345LL);
  if ((0x1234567890ABCDEFLL != GNUNET_htonll (0xEFCDAB9078563412LL)) &&
      42 != htonl (42))
    return 1;
  return 0;
}

/* end of test_common_endian.c */

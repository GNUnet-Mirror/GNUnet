/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file monkey/test_monkey_edb.c
 * @brief testcase for edb_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_monkey_edb.h"


static const char *ref[16] =
  { "args", "32", "argv", "32", "whole", "42", "whole.member", "42",
  "whole.member=1", "42", "whole.part", "43", "&part", "43",
    "whole.part=&part", "43"
};

static int refCount = 0;
static int ret = 1;

int
expressionIterator (void *cls, int colNum, char **colValues, char **colNames)
{
  int i;
  for (i = 0; i < colNum; i++)
    {
      if (strcmp (colValues[i], ref[refCount]) != 0)
	return 1;
      refCount++;
    }

  return 0;
}


int
main (int args, const char *argv[])
{
  struct GNUNET_MONKEY_EDB_Context *cntxt;
  cntxt = GNUNET_MONKEY_EDB_connect ("test.db");
  ret =
    GNUNET_MONKEY_EDB_get_expressions (cntxt,
				       "monkey/seaspider/SeaspiderTest.c", 44,
				       83, &expressionIterator, NULL);
  GNUNET_MONKEY_EDB_disconnect (cntxt);

  if (ret == GNUNET_OK)
    {
      return 0;
    }
  return 1;
}

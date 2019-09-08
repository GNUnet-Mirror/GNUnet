/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file util/test_strings_to_data.c
 * @brief testcase for strings.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


int
main(int argc, char *argv[])
{
  char buf[1024];
  char *end;
  char src[128];
  char dst[128];
  unsigned int i;
  int ret = 0;

  GNUNET_log_setup("util", "DEBUG", NULL);
  for (i = 0; i < sizeof(src); i++)
    {
      memset(src, i, sizeof(src));
      memset(dst, i + 1, sizeof(dst));

      end = GNUNET_STRINGS_data_to_string(&src, i, buf, sizeof(buf));
      GNUNET_assert(NULL != end);
      end[0] = '\0';
      if (GNUNET_OK !=
          GNUNET_STRINGS_string_to_data(buf, strlen(buf), dst, i))
        {
          fprintf(stderr, "%u failed decode (%u bytes)\n", i, (unsigned int)strlen(buf));
          ret = 1;
        }
      else if (0 != memcmp(src, dst, i))
        {
          fprintf(stderr, "%u wrong decode (%u bytes)\n", i, (unsigned int)strlen(buf));
          ret = 1;
        }
    }
  return ret;
}


/* end of test_strings_to_data.c */

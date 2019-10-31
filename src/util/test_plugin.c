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
 * @file util/test_plugin.c
 * @brief testcase for plugin.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


static void
test_cb (void *cls, const char *libname, void *lib_ret)
{
  void *ret;

  GNUNET_assert (0 == strcmp (cls, "test"));
  GNUNET_assert (0 == strcmp (lib_ret, "Hello"));
  ret = GNUNET_PLUGIN_unload (libname, "out");
  GNUNET_assert (NULL != ret);
  GNUNET_assert (0 == strcmp (ret, "World"));
  free (ret);
}


int
main (int argc, char *argv[])
{
  void *ret;

  GNUNET_log_setup ("test-plugin", "WARNING", NULL);
  GNUNET_log_skip (1, GNUNET_NO);
  ret = GNUNET_PLUGIN_load ("libgnunet_plugin_missing", NULL);
  GNUNET_log_skip (0, GNUNET_NO);
  if (ret != NULL)
    return 1;
  ret = GNUNET_PLUGIN_load ("libgnunet_plugin_test", "in");
  if (ret == NULL)
    return 1;
  if (0 != strcmp (ret, "Hello"))
    return 2;
  ret = GNUNET_PLUGIN_unload ("libgnunet_plugin_test", "out");
  if (ret == NULL)
    return 3;
  if (0 != strcmp (ret, "World"))
    return 4;
  free (ret);
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_tes", "in", &test_cb, "test");
  return 0;
}


/* end of test_plugin.c */

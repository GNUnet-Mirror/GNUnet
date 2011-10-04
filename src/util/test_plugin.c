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
 * @file util/test_plugin.c
 * @brief testcase for plugin.c
 */
#include "platform.h"
#include "gnunet_plugin_lib.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

static int
check ()
{
  void *ret;

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
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-plugin", "WARNING", NULL);
  ret = check ();

  return ret;
}

/* end of test_plugin.c */

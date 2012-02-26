/*
     This file is part of GNUnet
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
 * @file block/test_block.c
 * @brief test for block.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_block_lib.h"

#define DEBUG GNUNET_EXTRA_LOGGING

#define VERBOSE GNUNET_NO

static int
test_fs (struct GNUNET_BLOCK_Context *ctx)
{
  GNUNET_HashCode key;
  char block[4];

  memset (block, 1, sizeof (block));
  if (GNUNET_OK !=
      GNUNET_BLOCK_get_key (ctx, GNUNET_BLOCK_TYPE_FS_DBLOCK, block,
                            sizeof (block), &key))
    return 1;
  if (GNUNET_BLOCK_EVALUATION_OK_LAST !=
      GNUNET_BLOCK_evaluate (ctx, GNUNET_BLOCK_TYPE_FS_DBLOCK, &key, NULL, 0,
                             NULL, 0, block, sizeof (block)))
    return 2;
  if (GNUNET_BLOCK_EVALUATION_REQUEST_VALID !=
      GNUNET_BLOCK_evaluate (ctx, GNUNET_BLOCK_TYPE_FS_DBLOCK, &key, NULL, 0,
                             NULL, 0, NULL, 0))
    return 4;
  GNUNET_log_skip (1, GNUNET_NO);
  if (GNUNET_BLOCK_EVALUATION_REQUEST_INVALID !=
      GNUNET_BLOCK_evaluate (ctx, GNUNET_BLOCK_TYPE_FS_DBLOCK, &key, NULL, 0,
                             "bogus", 5, NULL, 0))
    return 8;
  GNUNET_log_skip (0, GNUNET_YES);
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret;
  struct GNUNET_BLOCK_Context *ctx;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_log_setup ("test-block", "WARNING", NULL);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_string (cfg, "block", "PLUGINS", "fs");
  ctx = GNUNET_BLOCK_context_create (cfg);
  ret = test_fs (ctx);
  GNUNET_BLOCK_context_destroy (ctx);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (ret != 0)
    FPRINTF (stderr, "Tests failed: %d\n", ret);
  return ret;
}

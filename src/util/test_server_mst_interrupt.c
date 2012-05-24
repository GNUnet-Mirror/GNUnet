/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/test_server_mst_interrupt.c
 * @brief test for interrupt message processing in server_mst.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"

static struct GNUNET_SERVER_MessageStreamTokenizer * mst;
static int ret;

/* Callback destroying mst with data in buffer */
static int
mst_cb (void *cls, void *client,
        const struct GNUNET_MessageHeader * message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MST gave me message, destroying\n");
  GNUNET_SERVER_mst_destroy (mst);
  return GNUNET_SYSERR;
}

/**
 * Main method
 */
static int
check ()
{

  struct GNUNET_PeerIdentity id;
  struct GNUNET_MessageHeader msg[2];

  /* Prepare */
  memset (&id, sizeof (id), '\0');
  msg[0].size = htons (sizeof (msg));
  msg[0].type = htons (sizeof (GNUNET_MESSAGE_TYPE_DUMMY));

  mst = GNUNET_SERVER_mst_create(mst_cb, NULL);

  GNUNET_SERVER_mst_receive(mst, &id,  (const char *) &msg, 2 * sizeof (msg), GNUNET_NO, GNUNET_NO);

  /* If we reach this line, it did not crash */
  ret = 0;

  return ret;
}

int
main (int argc, char *argv[])
{
  ret = 1;

  GNUNET_log_setup ("test_server", "WARNING", NULL);
  check ();

  return ret;
}

/* end of test_server_mst_interrupt.c */

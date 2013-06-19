/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file set/test_mq.c
 * @brief simple tests for mq
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


GNUNET_NETWORK_STRUCT_BEGIN

struct MyMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t x GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END

void
test1 (void)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct MyMessage *mm;
  
  mm = NULL;
  mqm = NULL;

  mqm = GNUNET_MQ_msg (mm, 42);
  GNUNET_assert (NULL != mqm);
  GNUNET_assert (NULL != mm);
  GNUNET_assert (42 == ntohs (mm->header.type));
  GNUNET_assert (sizeof (struct MyMessage) == ntohs (mm->header.size));
}


void
test2 (void)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_MessageHeader *mh;

  mqm = GNUNET_MQ_msg_header (42);
  /* how could the above be checked? */

  GNUNET_MQ_discard (mqm);

  mqm = GNUNET_MQ_msg_header_extra (mh, 20, 42);
  GNUNET_assert (42 == ntohs (mh->type));
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) + 20 == ntohs (mh->size));
}


int
main (int argc, char **argv)
{

  GNUNET_log_setup ("test-mq", "INFO", NULL);
  test1 ();
  test2 ();

  return 0;
}


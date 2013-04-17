/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @author Florian Dold
 * @file mq/mq.c
 * @brief general purpose request queue
 */

#include "mq.h"


struct GNUNET_MQ_Message
{
  struct GNUNET_MessageHeader *mh;
};


struct GNUNET_MQ_Message *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp, uint16_t size, uint16_t type)
{
  struct GNUNET_MQ_Message *mqm;
  mqm = GNUNET_malloc (sizeof *mqm + size);
  mqm->mh = (struct GNUNET_MessageHeader *) &mqm[1];
  mqm->mh->size = htons (size);
  mqm->mh->type = htons(type);
  if (NULL != mhp)
    *mhp = mqm->mh;
  return mqm;
}

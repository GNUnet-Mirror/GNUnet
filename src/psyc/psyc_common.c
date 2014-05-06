/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file psyc/psyc_common.c
 * @brief Common functions for PSYC
 * @author Gabor X Toth
 */

#include <inttypes.h>
#include "psyc.h"

/**
 * Check if @a data contains a series of valid message parts.
 *
 * @param      data_size    Size of @a data.
 * @param      data	    Data.
 * @param[out] first_ptype  Type of first message part.
 * @param[out] last_ptype   Type of last message part.
 *
 * @return Number of message parts found in @a data.
 *         or GNUNET_SYSERR if the message contains invalid parts.
 */
int
GNUNET_PSYC_check_message_parts (uint16_t data_size, const char *data,
                                 uint16_t *first_ptype, uint16_t *last_ptype)
{
  const struct GNUNET_MessageHeader *pmsg;
  uint16_t parts = 0, ptype = 0, psize = 0, pos = 0;
  if (NULL != first_ptype)
    *first_ptype = 0;
  if (NULL != last_ptype)
    *last_ptype = 0;

  for (pos = 0; pos < data_size; pos += psize, parts++)
  {
    pmsg = (const struct GNUNET_MessageHeader *) (data + pos);
    psize = ntohs (pmsg->size);
    ptype = ntohs (pmsg->type);
    if (0 == parts && NULL != first_ptype)
      *first_ptype = ptype;
    if (NULL != last_ptype
        && *last_ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END)
      *last_ptype = ptype;
    if (psize < sizeof (*pmsg)
        || pos + psize > data_size
        || ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD
        || GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL < ptype)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid message part of type %u and size %u.\n",
                  ptype, psize);
      return GNUNET_SYSERR;
    }
    /* FIXME: check message part order */
  }
  return parts;
}


void
GNUNET_PSYC_log_message (enum GNUNET_ErrorType kind,
                         const struct GNUNET_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->size);
  uint16_t type = ntohs (msg->type);
  GNUNET_log (kind, "Message of type %d and size %u:\n", type, size);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE:
  {
    struct GNUNET_PSYC_MessageHeader *pmsg
      = (struct GNUNET_PSYC_MessageHeader *) msg;
    GNUNET_log (kind, "\tID: %" PRIu64 "\tflags: %" PRIu32 "\n",
                GNUNET_ntohll (pmsg->message_id), ntohl (pmsg->flags));
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  {
    struct GNUNET_PSYC_MessageMethod *meth
      = (struct GNUNET_PSYC_MessageMethod *) msg;
    GNUNET_log (kind, "\t%.*s\n", size - sizeof (*meth), &meth[1]);
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *mod
      = (struct GNUNET_PSYC_MessageModifier *) msg;
    uint16_t name_size = ntohs (mod->name_size);
    char oper = ' ' < mod->oper ? mod->oper : ' ';
    GNUNET_log (kind, "\t%c%.*s\t%.*s\n", oper, name_size, &mod[1],
                size - sizeof (*mod) - name_size - 1,
                ((char *) &mod[1]) + name_size + 1);
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    GNUNET_log (kind, "\t%.*s\n", size - sizeof (*msg), &msg[1]);
    break;
  }
}

/*
      This file is part of GNUnet
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
 * @file consensus/consensus_flout.h
 * @brief intentionally misbehave in certain ways for testing
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_FLOUT_H
#define GNUNET_CONSENSUS_FLOUT_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_consensus_service.h"

void
GNUNET_CONSENSUS_flout_disable_peer (struct GNUNET_CONSENSUS_Handle *consensus);

void
GNUNET_CONSENSUS_flout_ignore_element_hash (struct GNUNET_CONSENSUS_Handle *consensus, struct GNUNET_HashCode *element_hash);

void
GNUNET_CONSENSUS_flout_send_bogos_ibf (struct GNUNET_CONSENSUS_Handle *consensus, ...);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

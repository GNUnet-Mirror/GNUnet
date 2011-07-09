/*
     This file is part of GNUnet
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/fragmentation/defragmentation_new.c
 * @brief library to help defragment messages
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fragmentation_lib.h"
#include "fragmentation.h"

/**
 * Defragmentation context.
 */
struct GNUNET_DEFRAGMENT_Context
{

  /**
   * For statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Closure for 'proc' and 'ackp'.
   */
  void *cls;

  /**
   * Function to call with defragmented messages.
   */
  GNUNET_FRAGMENT_MessageProcessor proc;

  /**
   * Function to call with acknowledgements.
   */
  GNUNET_FRAGMENT_MessageProcessor ackp;
};


/**
 * Create a defragmentation context.
 *
 * @param stats statistics context
 * @param cls closure for proc and ackp
 * @param proc function to call with defragmented messages
 * @param ackp function to call with acknowledgements (to send
 *             back to the other side)
 * @return the defragmentation context
 */
struct GNUNET_DEFRAGMENT_Context *
GNUNET_DEFRAGMENT_context_create (struct GNUNET_STATISTICS_Handle *stats,
				  void *cls,
				  GNUNET_FRAGMENT_MessageProcessor proc,
				  GNUNET_FRAGMENT_MessageProcessor ackp)
{
  struct GNUNET_DEFRAGMENT_Context *dc;

  dc = GNUNET_malloc (sizeof (struct GNUNET_DEFRAGMENT_Context));
  dc->stats = stats;
  dc->cls = cls;
  dc->proc = proc;
  dc->ackp = ackp;
  return dc;
}


/**
 * Destroy the given defragmentation context.
 *
 * @param dc defragmentation context
 */
void 
GNUNET_DEFRAGMENT_context_destroy (struct GNUNET_DEFRAGMENT_Context *dc)
{
  GNUNET_free (dc);
}


/**
 * We have received a fragment.  Process it.
 *
 * @param dc the context
 * @param msg the message that was received
 */
void 
GNUNET_DEFRAGMENT_process_fragment (struct GNUNET_DEFRAGMENT_Context *dc,
				    const struct GNUNET_MessageHeader *msg)
{
}

/* end of defragmentation_new.c */


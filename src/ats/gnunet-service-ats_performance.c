/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_performance.c
 * @brief ats service, interaction with 'performance' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats_performance.h"
#include "ats.h"


struct PerformanceClient
{
  struct PerformanceClient * next;

  struct PerformanceClient * prev;

  struct GNUNET_SERVER_Client *client;

};


/**
 * Head of linked list of all clients to this service.
 */
static struct PerformanceClient *pc_head;

/**
 * Tail of linked list of all clients to this service.
 */
static struct PerformanceClient *pc_tail;
 

static struct PerformanceClient * 
find_client (struct GNUNET_SERVER_Client *client)
{
  struct PerformanceClient * pc;

  for (pc = pc_head; pc != NULL; pc = pc->next)
    if (pc->client == client)
      return pc;
  return NULL;
}


void
GAS_performance_add_client (struct GNUNET_SERVER_Client *client)
{
  struct PerformanceClient * pc;

  GNUNET_break (NULL == find_client (client));
  pc = GNUNET_malloc (sizeof (struct PerformanceClient));
  pc->client = client;
  GNUNET_CONTAINER_DLL_insert(pc_head, pc_tail, pc);
}


void
GAS_performance_remove_client (struct GNUNET_SERVER_Client *client)
{
  struct PerformanceClient * pc;

  pc = find_client (client);
  if (NULL == pc)
    return;
  GNUNET_CONTAINER_DLL_remove (pc_head, pc_tail, pc);
  GNUNET_SERVER_client_drop (client);
  GNUNET_free (pc);
}


void
GAS_handle_reservation_request (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct AddressUpdateMessage * msg = (struct AddressUpdateMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "RESERVATION_REQUEST");
}


void
GAS_handle_preference_change (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)

{
  // struct ChangePreferenceMessage * msg = (struct ChangePreferenceMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "PREFERENCE_CHANGE");
}


/* end of gnunet-service-ats_performance.c */

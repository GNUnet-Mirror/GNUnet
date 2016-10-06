/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file gns/gnunet-service-gns_reverser.c
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */


#include "platform.h"
#include "gnunet_gns_service.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_reverser.h"

struct ReverseTreeNode
{
  /**
   * DLL
   */
  struct ReverseTreeNode *next;

  /**
   * DLL
   */
  struct ReverseTreeNode *prev;

  /**
   * Resolved name until now
   */
  char *name;

  /**
   * Depth of the resolution at this node
   */
  uint8_t depth;

  /**
   * The pkey of the namespace
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

};


struct GNS_ReverserHandle
{
  /**
   * GNS resolver handle
   */
  struct GNS_ResolverHandle *rh;

  /**
   * The authority to look for
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey authority;
  
  /**
   * Resolution candidate queue
   */
  struct ReverseTreeNode *node_queue_head;

  /**
   * Resolution candidate queue
   */
  struct ReverseTreeNode *node_queue_tail;

  /**
   * Max depth for the resolution
   */
  uint8_t max_depth;

  /**
   * Result callback
   */
  GNS_ReverseResultProcessor proc;

  /**
   * Callback closure
   */
  void *proc_cls;
};

void
cleanup_handle (struct GNS_ReverserHandle *rh)
{
  struct ReverseTreeNode *rtn;

  for (rtn = rh->node_queue_head; NULL != rtn; rtn = rh->node_queue_head)
  {
    if (NULL != rtn->name)
      GNUNET_free (rtn->name);
    GNUNET_CONTAINER_DLL_remove (rh->node_queue_head,
                                 rh->node_queue_tail,
                                 rtn);
    GNUNET_free (rtn);
  }
}

void
handle_gns_result (void *cls,
                   uint32_t rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNS_ReverserHandle *rh = cls;
  const struct GNUNET_GNSRECORD_ReverseRecord *rr;
  struct ReverseTreeNode *rtn;
  char *result;
  const char *name;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got result (%d)\n", rd_count);

  for (int i = 0; i < rd_count; i++)
  {
    /**
     * Check if we are in the delegation set
     */
    if (GNUNET_GNSRECORD_TYPE_REVERSE != rd[i].record_type)
      continue;
    rr = rd[i].data;
    name = (const char*) &rr[1];
    if (0 == memcmp (&rh->authority,
                     &rr->pkey,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      //Found!
      GNUNET_asprintf (&result,
                       "%s.%s.gnu",
                       rh->node_queue_head->name,
                       name);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found path from %s\n", result);

      rh->proc (rh->proc_cls, result);
      cleanup_handle (rh);
      GNUNET_free (result);
      return;
    } else {
      if (rh->node_queue_head->depth >= rh->max_depth)
        break;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found REVERSE from %s\n", name);

      rtn = GNUNET_new (struct ReverseTreeNode);
      if (NULL == rh->node_queue_head->name)
        rtn->name = GNUNET_strdup (name);
      else
        GNUNET_asprintf (&rtn->name,
                         "%s.%s",
                         rh->node_queue_head->name,
                         name);
      rtn->depth = rh->node_queue_head->depth + 1;
      rtn->pkey = rr->pkey;
      GNUNET_CONTAINER_DLL_insert_tail (rh->node_queue_head,
                                        rh->node_queue_tail,
                                        rtn);
    }
  }

  /**
   * Done here remove node from queue
   */
  rtn = rh->node_queue_head;
  GNUNET_CONTAINER_DLL_remove (rh->node_queue_head,
                               rh->node_queue_tail,
                               rtn);
  if (NULL == rh->node_queue_head)
  {
    //No luck
    rh->proc (rh->proc_cls, NULL);
    cleanup_handle (rh);
    return;
  }
  rh->rh = GNS_resolver_lookup (&rh->node_queue_head->pkey,
                                GNUNET_GNSRECORD_TYPE_REVERSE,
                                "+.gnu",
                                NULL,
                                GNUNET_GNS_LO_DEFAULT,
                                &handle_gns_result,
                                rh);
}

struct GNS_ReverserHandle *
GNS_reverse_lookup (const struct GNUNET_CRYPTO_EcdsaPublicKey *target,
                    const struct GNUNET_CRYPTO_EcdsaPublicKey *authority,
                    GNS_ReverseResultProcessor proc,
                    void *proc_cls)
{
  struct GNS_ReverserHandle *rh;
  struct ReverseTreeNode *rtn;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting reverse resolution\n");
  rh = GNUNET_new (struct GNS_ReverserHandle);
  rh->proc = proc;
  rh->proc_cls = proc_cls;
  rtn = GNUNET_new (struct ReverseTreeNode);
  rtn->name = NULL;
  rtn->pkey = *target;
  rtn->depth = 0;
  GNUNET_CONTAINER_DLL_insert (rh->node_queue_head,
                               rh->node_queue_tail,
                               rtn);
  rh->authority = *authority;
  rh->max_depth = 3; //TODO make argument
  rh->rh = GNS_resolver_lookup (target,
                                GNUNET_GNSRECORD_TYPE_REVERSE,
                                "+.gnu",
                                NULL,
                                GNUNET_GNS_LO_DEFAULT,
                                &handle_gns_result,
                                rh);
  return rh;
}

/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_reverse_lookup_cancel (struct GNS_ReverserHandle *rh)
{
  cleanup_handle (rh);
  return;
}



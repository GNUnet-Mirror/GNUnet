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
 * @file fs/gnunet-service-fs_push.c
 * @brief API to push content from our datastore to other peers
 *            ('anonymous'-content P2P migration)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_indexing.h"
#include "gnunet-service-fs_push.h"


/**
 * Maximum number of blocks we keep in memory for migration.
 */
#define MAX_MIGRATION_QUEUE 8

/**
 * Blocks are at most migrated to this number of peers
 * plus one, each time they are fetched from the database.
 */
#define MIGRATION_LIST_SIZE 2

/**
 * How long must content remain valid for us to consider it for migration?
 * If content will expire too soon, there is clearly no point in pushing
 * it to other peers.  This value gives the threshold for migration.  Note
 * that if this value is increased, the migration testcase may need to be
 * adjusted as well (especially the CONTENT_LIFETIME in fs_test_lib.c).
 */
#define MIN_MIGRATION_CONTENT_LIFETIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)


/**
 * Block that is ready for migration to other peers.  Actual data is at the end of the block.
 */
struct MigrationReadyBlock
{

  /**
   * This is a doubly-linked list.
   */
  struct MigrationReadyBlock *next;

  /**
   * This is a doubly-linked list.
   */
  struct MigrationReadyBlock *prev;

  /**
   * Query for the block.
   */
  GNUNET_HashCode query;

  /**
   * When does this block expire?
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Peers we already forwarded this
   * block to.  Zero for empty entries.
   */
  GNUNET_PEER_Id target_list[MIGRATION_LIST_SIZE];

  /**
   * Size of the block.
   */
  size_t size;

  /**
   *  Number of targets already used.
   */
  unsigned int used_targets;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Information about a peer waiting for
 * migratable data.
 */
struct MigrationReadyPeer
{
  /**
   * This is a doubly-linked list.
   */
  struct MigrationReadyPeer *next;

  /**
   * This is a doubly-linked list.
   */
  struct MigrationReadyPeer *prev;

  /**
   * Handle to peer.
   */
  struct GSF_ConnectedPeer *peer;

  /**
   * Handle for current transmission request,
   * or NULL for none.
   */
  struct GSF_PeerTransmitHandle *th;

  /**
   * Message we are trying to push right now (or NULL)
   */
  struct PutMessage *msg;
};


/**
 * Head of linked list of blocks that can be migrated.
 */
static struct MigrationReadyBlock *mig_head;

/**
 * Tail of linked list of blocks that can be migrated.
 */
static struct MigrationReadyBlock *mig_tail;

/**
 * Head of linked list of peers.
 */
static struct MigrationReadyPeer *peer_head;

/**
 * Tail of linked list of peers.
 */
static struct MigrationReadyPeer *peer_tail;

/**
 * Request to datastore for migration (or NULL).
 */
static struct GNUNET_DATASTORE_QueueEntry *mig_qe;

/**
 * ID of task that collects blocks for migration.
 */
static GNUNET_SCHEDULER_TaskIdentifier mig_task;

/**
 * What is the maximum frequency at which we are allowed to
 * poll the datastore for migration content?
 */
static struct GNUNET_TIME_Relative min_migration_delay;

/**
 * Size of the doubly-linked list of migration blocks.
 */
static unsigned int mig_size;

/**
 * Is this module enabled?
 */
static int enabled;


/**
 * Delete the given migration block.
 *
 * @param mb block to delete
 */
static void
delete_migration_block (struct MigrationReadyBlock *mb)
{
  GNUNET_CONTAINER_DLL_remove (mig_head, mig_tail, mb);
  GNUNET_PEER_decrement_rcs (mb->target_list, MIGRATION_LIST_SIZE);
  mig_size--;
  GNUNET_free (mb);
}


/**
 * Find content for migration to this peer.
 */
static void
find_content (struct MigrationReadyPeer *mrp);


/**
 * Transmit the message currently scheduled for
 * transmission.
 *
 * @param cls the 'struct MigrationReadyPeer'
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
static size_t
transmit_message (void *cls, size_t buf_size, void *buf)
{
  struct MigrationReadyPeer *peer = cls;
  struct PutMessage *msg;
  uint16_t msize;

  peer->th = NULL;
  msg = peer->msg;
  peer->msg = NULL;
  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to migrate content to another peer (disconnect)\n");
    GNUNET_free (msg);
    return 0;
  }
  msize = ntohs (msg->header.size);
  GNUNET_assert (msize <= buf_size);
  memcpy (buf, msg, msize);
  GNUNET_free (msg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Pushing %u bytes to another peer\n",
              msize);
  find_content (peer);
  return msize;
}


/**
 * Send the given block to the given peer.
 *
 * @param peer target peer
 * @param block the block
 * @return GNUNET_YES if the block was deleted (!)
 */
static int
transmit_content (struct MigrationReadyPeer *peer,
                  struct MigrationReadyBlock *block)
{
  size_t msize;
  struct PutMessage *msg;
  unsigned int i;
  struct GSF_PeerPerformanceData *ppd;
  int ret;

  ppd = GSF_get_peer_performance_data_ (peer->peer);
  GNUNET_assert (NULL == peer->th);
  msize = sizeof (struct PutMessage) + block->size;
  msg = GNUNET_malloc (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
  msg->header.size = htons (msize);
  msg->type = htonl (block->type);
  msg->expiration = GNUNET_TIME_absolute_hton (block->expiration);
  memcpy (&msg[1], &block[1], block->size);
  peer->msg = msg;
  for (i = 0; i < MIGRATION_LIST_SIZE; i++)
  {
    if (block->target_list[i] == 0)
    {
      block->target_list[i] = ppd->pid;
      GNUNET_PEER_change_rc (block->target_list[i], 1);
      break;
    }
  }
  if (MIGRATION_LIST_SIZE == i)
  {
    delete_migration_block (block);
    ret = GNUNET_YES;
  }
  else
  {
    ret = GNUNET_NO;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for transmission of %u bytes for migration\n", msize);
  peer->th = GSF_peer_transmit_ (peer->peer, GNUNET_NO, 0 /* priority */ ,
                                 GNUNET_TIME_UNIT_FOREVER_REL, msize,
                                 &transmit_message, peer);
  return ret;
}


/**
 * Count the number of peers this block has
 * already been forwarded to.
 *
 * @param block the block
 * @return number of times block was forwarded
 */
static unsigned int
count_targets (struct MigrationReadyBlock *block)
{
  unsigned int i;

  for (i = 0; i < MIGRATION_LIST_SIZE; i++)
    if (block->target_list[i] == 0)
      return i;
  return i;
}


/**
 * Check if sending this block to this peer would
 * be a good idea.
 *
 * @param peer target peer
 * @param block the block
 * @return score (>= 0: feasible, negative: infeasible)
 */
static long
score_content (struct MigrationReadyPeer *peer,
               struct MigrationReadyBlock *block)
{
  unsigned int i;
  struct GSF_PeerPerformanceData *ppd;
  struct GNUNET_PeerIdentity id;
  uint32_t dist;

  ppd = GSF_get_peer_performance_data_ (peer->peer);
  for (i = 0; i < MIGRATION_LIST_SIZE; i++)
    if (block->target_list[i] == ppd->pid)
      return -1;
  GNUNET_assert (0 != ppd->pid);
  GNUNET_PEER_resolve (ppd->pid, &id);
  dist = GNUNET_CRYPTO_hash_distance_u32 (&block->query, &id.hashPubKey);
  /* closer distance, higher score: */
  return UINT32_MAX - dist;
}


/**
 * If the migration task is not currently running, consider
 * (re)scheduling it with the appropriate delay.
 */
static void
consider_gathering (void);


/**
 * Find content for migration to this peer.
 *
 * @param mrp peer to find content for
 */
static void
find_content (struct MigrationReadyPeer *mrp)
{
  struct MigrationReadyBlock *pos;
  long score;
  long best_score;
  struct MigrationReadyBlock *best;

  GNUNET_assert (NULL == mrp->th);
  best = NULL;
  best_score = -1;
  pos = mig_head;
  while (NULL != pos)
  {
    score = score_content (mrp, pos);
    if (score > best_score)
    {
      best_score = score;
      best = pos;
    }
    pos = pos->next;
  }
  if (NULL == best)
  {
    if (mig_size < MAX_MIGRATION_QUEUE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No content found for pushing, waiting for queue to fill\n");
      return;                   /* will fill up eventually... */
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No suitable content found, purging content from full queue\n");
    /* failed to find migration target AND
     * queue is full, purge most-forwarded
     * block from queue to make room for more */
    pos = mig_head;
    while (NULL != pos)
    {
      score = count_targets (pos);
      if (score >= best_score)
      {
        best_score = score;
        best = pos;
      }
      pos = pos->next;
    }
    GNUNET_assert (NULL != best);
    delete_migration_block (best);
    consider_gathering ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Preparing to push best content to peer\n");
  transmit_content (mrp, best);
}


/**
 * Task that is run periodically to obtain blocks for content
 * migration
 *
 * @param cls unused
 * @param tc scheduler context (also unused)
 */
static void
gather_migration_blocks (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * If the migration task is not currently running, consider
 * (re)scheduling it with the appropriate delay.
 */
static void
consider_gathering ()
{
  struct GNUNET_TIME_Relative delay;

  if (GSF_dsh == NULL)
    return;
  if (mig_qe != NULL)
    return;
  if (mig_task != GNUNET_SCHEDULER_NO_TASK)
    return;
  if (mig_size >= MAX_MIGRATION_QUEUE)
    return;
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, mig_size);
  delay = GNUNET_TIME_relative_divide (delay, MAX_MIGRATION_QUEUE);
  delay = GNUNET_TIME_relative_max (delay, min_migration_delay);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling gathering task (queue size: %u)\n", mig_size);
  mig_task =
      GNUNET_SCHEDULER_add_delayed (delay, &gather_migration_blocks, NULL);
}


/**
 * Process content offered for migration.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_migration_content (void *cls, const GNUNET_HashCode * key, size_t size,
                           const void *data, enum GNUNET_BLOCK_Type type,
                           uint32_t priority, uint32_t anonymity,
                           struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct MigrationReadyBlock *mb;
  struct MigrationReadyPeer *pos;

  mig_qe = NULL;
  if (key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No content found for migration...\n");
    consider_gathering ();
    return;
  }
  if (GNUNET_TIME_absolute_get_remaining (expiration).rel_value <
      MIN_MIGRATION_CONTENT_LIFETIME.rel_value)
  {
    /* content will expire soon, don't bother */
    consider_gathering ();
    return;
  }
  if (type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
  {
    if (GNUNET_OK !=
        GNUNET_FS_handle_on_demand_block (key, size, data, type, priority,
                                          anonymity, expiration, uid,
                                          &process_migration_content, NULL))
      consider_gathering ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Retrieved block `%s' of type %u for migration (queue size: %u/%u)\n",
              GNUNET_h2s (key), type, mig_size + 1, MAX_MIGRATION_QUEUE);
  mb = GNUNET_malloc (sizeof (struct MigrationReadyBlock) + size);
  mb->query = *key;
  mb->expiration = expiration;
  mb->size = size;
  mb->type = type;
  memcpy (&mb[1], data, size);
  GNUNET_CONTAINER_DLL_insert_after (mig_head, mig_tail, mig_tail, mb);
  mig_size++;
  pos = peer_head;
  while (pos != NULL)
  {
    if (NULL == pos->th)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Preparing to push best content to peer\n");
      if (GNUNET_YES == transmit_content (pos, mb))
        break;                  /* 'mb' was freed! */
    }
    pos = pos->next;
  }
  consider_gathering ();
}


/**
 * Task that is run periodically to obtain blocks for content
 * migration
 *
 * @param cls unused
 * @param tc scheduler context (also unused)
 */
static void
gather_migration_blocks (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  mig_task = GNUNET_SCHEDULER_NO_TASK;
  if (mig_size >= MAX_MIGRATION_QUEUE)
    return;
  if (GSF_dsh != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking datastore for content for replication (queue size: %u)\n",
                mig_size);
    mig_qe =
        GNUNET_DATASTORE_get_for_replication (GSF_dsh, 0, UINT_MAX,
                                              GNUNET_TIME_UNIT_FOREVER_REL,
                                              &process_migration_content, NULL);
    if (NULL == mig_qe)
      consider_gathering ();
  }
}


/**
 * A peer connected to us.  Start pushing content
 * to this peer.
 *
 * @param peer handle for the peer that connected
 */
void
GSF_push_start_ (struct GSF_ConnectedPeer *peer)
{
  struct MigrationReadyPeer *mrp;

  if (GNUNET_YES != enabled)
    return;
  mrp = GNUNET_malloc (sizeof (struct MigrationReadyPeer));
  mrp->peer = peer;
  find_content (mrp);
  GNUNET_CONTAINER_DLL_insert (peer_head, peer_tail, mrp);
}


/**
 * A peer disconnected from us.  Stop pushing content
 * to this peer.
 *
 * @param peer handle for the peer that disconnected
 */
void
GSF_push_stop_ (struct GSF_ConnectedPeer *peer)
{
  struct MigrationReadyPeer *pos;

  pos = peer_head;
  while (pos != NULL)
  {
    if (pos->peer == peer)
    {
      GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, pos);
      if (NULL != pos->th)
      {
        GSF_peer_transmit_cancel_ (pos->th);
        pos->th = NULL;
      }
      if (NULL != pos->msg)
      {
        GNUNET_free (pos->msg);
        pos->msg = NULL;
      }
      GNUNET_free (pos);
      return;
    }
    pos = pos->next;
  }
}


/**
 * Setup the module.
 */
void
GSF_push_init_ ()
{
  enabled =
      GNUNET_CONFIGURATION_get_value_yesno (GSF_cfg, "FS", "CONTENT_PUSHING");
  if (GNUNET_YES != enabled)
    return;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (GSF_cfg, "fs", "MIN_MIGRATION_DELAY",
                                           &min_migration_delay))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Invalid value specified for option `%s' in section `%s', content pushing disabled\n"),
                "MIN_MIGRATION_DELAY", "fs");
    return;
  }
  consider_gathering ();
}


/**
 * Shutdown the module.
 */
void
GSF_push_done_ ()
{
  if (GNUNET_SCHEDULER_NO_TASK != mig_task)
  {
    GNUNET_SCHEDULER_cancel (mig_task);
    mig_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != mig_qe)
  {
    GNUNET_DATASTORE_cancel (mig_qe);
    mig_qe = NULL;
  }
  while (NULL != mig_head)
    delete_migration_block (mig_head);
  GNUNET_assert (0 == mig_size);
}

/* end of gnunet-service-fs_push.c */

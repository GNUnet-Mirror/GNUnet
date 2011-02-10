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
#include "gnunet-service-fs_push.h"


/* FIXME: below are only old code fragments to use... */

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
   * Peers we would consider forwarding this
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
 * Head of linked list of blocks that can be migrated.
 */
static struct MigrationReadyBlock *mig_head;

/**
 * Tail of linked list of blocks that can be migrated.
 */
static struct MigrationReadyBlock *mig_tail;

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
 * Are we allowed to push out content from this peer.
 */
static int active_from_migration;

/**
 * Size of the doubly-linked list of migration blocks.
 */
static unsigned int mig_size;


/**
 * Delete the given migration block.
 *
 * @param mb block to delete
 */
static void
delete_migration_block (struct MigrationReadyBlock *mb)
{
  GNUNET_CONTAINER_DLL_remove (mig_head,
			       mig_tail,
			       mb);
  GNUNET_PEER_decrement_rcs (mb->target_list,
			     MIGRATION_LIST_SIZE);
  mig_size--;
  GNUNET_free (mb);
}


/**
 * Compare the distance of two peers to a key.
 *
 * @param key key
 * @param p1 first peer
 * @param p2 second peer
 * @return GNUNET_YES if P1 is closer to key than P2
 */
static int
is_closer (const GNUNET_HashCode *key,
	   const struct GNUNET_PeerIdentity *p1,
	   const struct GNUNET_PeerIdentity *p2)
{
  return GNUNET_CRYPTO_hash_xorcmp (&p1->hashPubKey,
				    &p2->hashPubKey,
				    key);
}


/**
 * Consider migrating content to a given peer.
 *
 * @param cls 'struct MigrationReadyBlock*' to select
 *            targets for (or NULL for none)
 * @param key ID of the peer 
 * @param value 'struct ConnectedPeer' of the peer
 * @return GNUNET_YES (always continue iteration)
 */
static int
consider_migration (void *cls,
		    const GNUNET_HashCode *key,
		    void *value)
{
  struct MigrationReadyBlock *mb = cls;
  struct ConnectedPeer *cp = value;
  struct MigrationReadyBlock *pos;
  struct GNUNET_PeerIdentity cppid;
  struct GNUNET_PeerIdentity otherpid;
  struct GNUNET_PeerIdentity worstpid;
  size_t msize;
  unsigned int i;
  unsigned int repl;
  
  /* consider 'cp' as a migration target for mb */
  if (GNUNET_TIME_absolute_get_remaining (cp->migration_blocked).rel_value > 0)
    return GNUNET_YES; /* peer has requested no migration! */
  if (mb != NULL)
    {
      GNUNET_PEER_resolve (cp->pid,
			   &cppid);
      repl = MIGRATION_LIST_SIZE;
      for (i=0;i<MIGRATION_LIST_SIZE;i++)
	{
	  if (mb->target_list[i] == 0)
	    {
	      mb->target_list[i] = cp->pid;
	      GNUNET_PEER_change_rc (mb->target_list[i], 1);
	      repl = MIGRATION_LIST_SIZE;
	      break;
	    }
	  GNUNET_PEER_resolve (mb->target_list[i],
			       &otherpid);
	  if ( (repl == MIGRATION_LIST_SIZE) &&
	       is_closer (&mb->query,
			  &cppid,
			  &otherpid)) 
	    {
	      repl = i;
	      worstpid = otherpid;
	    }
	  else if ( (repl != MIGRATION_LIST_SIZE) &&
		    (is_closer (&mb->query,
				&worstpid,
				&otherpid) ) )
	    {
	      repl = i;
	      worstpid = otherpid;
	    }	    
	}
      if (repl != MIGRATION_LIST_SIZE) 
	{
	  GNUNET_PEER_change_rc (mb->target_list[repl], -1);
	  mb->target_list[repl] = cp->pid;
	  GNUNET_PEER_change_rc (mb->target_list[repl], 1);
	}
    }

  /* consider scheduling transmission to cp for content migration */
  if (cp->cth != NULL)        
    return GNUNET_YES; 
  msize = 0;
  pos = mig_head;
  while (pos != NULL)
    {
      for (i=0;i<MIGRATION_LIST_SIZE;i++)
	{
	  if (cp->pid == pos->target_list[i])
	    {
	      if (msize == 0)
		msize = pos->size;
	      else
		msize = GNUNET_MIN (msize,
				    pos->size);
	      break;
	    }
	}
      pos = pos->next;
    }
  if (msize == 0)
    return GNUNET_YES; /* no content available */
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Trying to migrate at least %u bytes to peer `%s'\n",
	      msize,
	      GNUNET_h2s (key));
#endif
  if (cp->delayed_transmission_request_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (cp->delayed_transmission_request_task);
      cp->delayed_transmission_request_task = GNUNET_SCHEDULER_NO_TASK;
    }
  cp->cth 
    = GNUNET_CORE_notify_transmit_ready (core,
					 0, GNUNET_TIME_UNIT_FOREVER_REL,
					 (const struct GNUNET_PeerIdentity*) key,
					 msize + sizeof (struct PutMessage),
					 &transmit_to_peer,
					 cp);
  return GNUNET_YES;
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
consider_migration_gathering ()
{
  struct GNUNET_TIME_Relative delay;

  if (dsh == NULL)
    return;
  if (mig_qe != NULL)
    return;
  if (mig_task != GNUNET_SCHEDULER_NO_TASK)
    return;
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
					 mig_size);
  delay = GNUNET_TIME_relative_divide (delay,
				       MAX_MIGRATION_QUEUE);
  delay = GNUNET_TIME_relative_max (delay,
				    min_migration_delay);
  mig_task = GNUNET_SCHEDULER_add_delayed (delay,
					   &gather_migration_blocks,
					   NULL);
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
process_migration_content (void *cls,
			   const GNUNET_HashCode * key,
			   size_t size,
			   const void *data,
			   enum GNUNET_BLOCK_Type type,
			   uint32_t priority,
			   uint32_t anonymity,
			   struct GNUNET_TIME_Absolute
			   expiration, uint64_t uid)
{
  struct MigrationReadyBlock *mb;
  
  if (key == NULL)
    {
      mig_qe = NULL;
      if (mig_size < MAX_MIGRATION_QUEUE)  
	consider_migration_gathering ();
      return;
    }
  if (GNUNET_TIME_absolute_get_remaining (expiration).rel_value < 
      MIN_MIGRATION_CONTENT_LIFETIME.rel_value)
    {
      /* content will expire soon, don't bother */
      GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
      return;
    }
  if (type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
    {
      if (GNUNET_OK !=
	  GNUNET_FS_handle_on_demand_block (key, size, data,
					    type, priority, anonymity,
					    expiration, uid, 
					    &process_migration_content,
					    NULL))
	{
	  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
	}
      return;
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Retrieved block `%s' of type %u for migration\n",
	      GNUNET_h2s (key),
	      type);
#endif
  mb = GNUNET_malloc (sizeof (struct MigrationReadyBlock) + size);
  mb->query = *key;
  mb->expiration = expiration;
  mb->size = size;
  mb->type = type;
  memcpy (&mb[1], data, size);
  GNUNET_CONTAINER_DLL_insert_after (mig_head,
				     mig_tail,
				     mig_tail,
				     mb);
  mig_size++;
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					 &consider_migration,
					 mb);
  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
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
  if (dsh != NULL)
    {
      mig_qe = GNUNET_DATASTORE_get_random (dsh, 0, UINT_MAX,
					    GNUNET_TIME_UNIT_FOREVER_REL,
					    &process_migration_content, NULL);
      GNUNET_assert (mig_qe != NULL);
    }
}



size_t
API_ (void *cls,
      size_t size, void *buf)
{
    next = mig_head;
      while (NULL != (mb = next))
	{
	  next = mb->next;
	  for (i=0;i<MIGRATION_LIST_SIZE;i++)
	    {
	      if ( (cp->pid == mb->target_list[i]) &&
		   (mb->size + sizeof (migm) <= size) )
		{
		  GNUNET_PEER_change_rc (mb->target_list[i], -1);
		  mb->target_list[i] = 0;
		  mb->used_targets++;
		  memset (&migm, 0, sizeof (migm));
		  migm.header.size = htons (sizeof (migm) + mb->size);
		  migm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
		  migm.type = htonl (mb->type);
		  migm.expiration = GNUNET_TIME_absolute_hton (mb->expiration);
		  memcpy (&cbuf[msize], &migm, sizeof (migm));
		  msize += sizeof (migm);
		  size -= sizeof (migm);
		  memcpy (&cbuf[msize], &mb[1], mb->size);
		  msize += mb->size;
		  size -= mb->size;
#if DEBUG_FS
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Pushing migration block `%s' (%u bytes) to `%s'\n",
			      GNUNET_h2s (&mb->query),
			      (unsigned int) mb->size,
			      GNUNET_i2s (&pid));
#endif	  
		  break;
		}
	      else
		{
#if DEBUG_FS
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Migration block `%s' (%u bytes) is not on migration list for peer `%s'\n",
			      GNUNET_h2s (&mb->query),
			      (unsigned int) mb->size,
			      GNUNET_i2s (&pid));
#endif	  
		}
	    }
	  if ( (mb->used_targets >= MIGRATION_TARGET_COUNT) ||
	       (mb->used_targets >= GNUNET_CONTAINER_multihashmap_size (connected_peers)) )
	    {
	      delete_migration_block (mb);
	      consider_migration_gathering ();
	    }
	}
      consider_migration (NULL, 
			  &pid.hashPubKey,
			  cp);

}




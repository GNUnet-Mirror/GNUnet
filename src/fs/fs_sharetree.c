/*
     This file is part of GNUnet
     (C) 2005-2012 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_sharetree.c
 * @brief code to manipulate the 'struct GNUNET_FS_ShareTreeItem' tree
 * @author LRN
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_scheduler_lib.h"
#include <pthread.h>


/**
 * Entry for each unique keyword to track how often
 * it occured.  Contains the keyword and the counter.
 */
struct KeywordCounter
{

  /**
   * This is a doubly-linked list
   */
  struct KeywordCounter *prev;

  /**
   * This is a doubly-linked list
   */
  struct KeywordCounter *next;

  /**
   * Keyword that was found.
   */
  const char *value;

  /**
   * How many files have this keyword?
   */
  unsigned int count;

};


/**
 * Aggregate information we keep for meta data in each directory.
 */
struct MetaCounter
{

  /**
   * This is a doubly-linked list
   */
  struct MetaCounter *prev;

  /**
   * This is a doubly-linked list
   */
  struct MetaCounter *next;

  /**
   * Name of the plugin that provided that piece of metadata
   */
  const char *plugin_name;

  /**
   * MIME-type of the metadata itself
   */
  const char *data_mime_type;

  /**
   * The actual meta data.
   */
  const char *data;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Type of the data
   */
  enum EXTRACTOR_MetaType type;

  /**
   * Format of the data
   */
  enum EXTRACTOR_MetaFormat format;

  /**
   * How many files have meta entries matching this value?
   * (type and format do not have to match).
   */
  unsigned int count;

};


/**
 * A structure that forms a singly-linked list that serves as a stack
 * for metadata-processing function.
 */
struct TrimContext
{

  /**
   * Map from the hash over the keyword to an 'struct KeywordCounter *'
   * counter that says how often this keyword was
   * encountered in the current directory.
   */
  struct GNUNET_CONTAINER_MultiHashMap *keywordcounter;

  /**
   * Map from the hash over the metadata to an 'struct MetaCounter *'
   * counter that says how often this metadata was
   * encountered in the current directory.
   */
  struct GNUNET_CONTAINER_MultiHashMap *metacounter;

  /**
   * Position we are currently manipulating.
   */
  struct GNUNET_FS_ShareTreeItem *pos;

  /**
   * Number of times an item has to be found to be moved to the parent.
   */
  unsigned int move_threshold;

};


/**
 * Add the given keyword to the keyword statistics tracker.
 *
 * @param cls the multihashmap we store the keyword counters in
 * @param keyword the keyword to count
 * @param is_mandatory ignored
 * @return always GNUNET_OK
 */
static int
add_to_keyword_counter (void *cls, const char *keyword, int is_mandatory)
{
  struct GNUNET_CONTAINER_MultiHashMap *mcm = cls;
  struct KeywordCounter *cnt;
  GNUNET_HashCode hc;
  size_t klen;

  klen = strlen (keyword) + 1;
  GNUNET_CRYPTO_hash (keyword, klen - 1, &hc);
  cnt = GNUNET_CONTAINER_multihashmap_get (mcm, &hc);
  if (cnt == NULL)
  {
    cnt = GNUNET_malloc (sizeof (struct KeywordCounter) + klen);
    cnt->value = (const char *) &cnt[1];
    memcpy (&cnt[1], keyword, klen);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_put (mcm, 
						      &hc, cnt,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  cnt->count++;
  return GNUNET_OK;
}


/**
 * Function called on each meta data item.  Increments the
 * respective counter.
 *
 * @param cls the container multihashmap to update
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_len number of bytes in data
 * @return GNUNET_OK to continue extracting / iterating
 */
static int
add_to_meta_counter (void *cls, const char *plugin_name,
		     enum EXTRACTOR_MetaType type, enum EXTRACTOR_MetaFormat format,
		     const char *data_mime_type, const char *data, size_t data_len)
{
  struct GNUNET_CONTAINER_MultiHashMap *map = cls;
  GNUNET_HashCode key;
  struct MetaCounter *cnt;

  GNUNET_CRYPTO_hash (data, data_len, &key);
  cnt = GNUNET_CONTAINER_multihashmap_get (map, &key);
  if (cnt == NULL)
  {
    cnt = GNUNET_malloc (sizeof (struct MetaCounter));
    cnt->data = data;
    cnt->data_size = data_len;
    cnt->plugin_name = plugin_name;
    cnt->type = type;
    cnt->format = format;
    cnt->data_mime_type = data_mime_type;
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_put (map,
						      &key, cnt,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  cnt->count++;
  return 0;
}


/**
 * Remove keywords above the threshold.
 *
 * @param cls the 'struct TrimContext' with the pos to remove the keywords from
 * @param keyword the keyword to check
 * @param is_mandatory ignored
 * @return always GNUNET_OK
 */
static int
remove_high_frequency_keywords (void *cls, const char *keyword, int is_mandatory)
{
  struct TrimContext *tc = cls;
  struct KeywordCounter *counter;
  GNUNET_HashCode hc;
  size_t klen;

  klen = strlen (keyword) + 1;
  GNUNET_CRYPTO_hash (keyword, klen - 1, &hc);
  counter = GNUNET_CONTAINER_multihashmap_get (tc->keywordcounter, &hc);
  GNUNET_assert (NULL != counter);
  if (counter->count < tc->move_threshold)
    return GNUNET_OK;
  GNUNET_FS_uri_ksk_remove_keyword (tc->pos->ksk_uri,
				    counter->value);
  return GNUNET_OK;
}


/**
 * Move "frequent" keywords over to the target ksk uri, free the
 * counters.
 *
 * @param cls the 'struct TrimContext'
 * @param key key of the entry
 * @param value the 'struct KeywordCounter'
 * @return GNUNET_YES (always)
 */
static int
migrate_and_drop_keywords (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct TrimContext *tc = cls;
  struct KeywordCounter *counter = value;

  if (counter->count >= tc->move_threshold)
  {
    if (NULL == tc->pos->ksk_uri)
      tc->pos->ksk_uri = GNUNET_FS_uri_ksk_create_from_args (1, &counter->value);
    else
      GNUNET_FS_uri_ksk_add_keyword (tc->pos->ksk_uri, counter->value, GNUNET_NO);
  }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (tc->keywordcounter,
						       key,
						       counter));
  GNUNET_free (counter);
  return GNUNET_YES;
}


/**
 * Copy "frequent" metadata items over to the
 * target metadata container, free the counters.
 *
 * @param cls the 'struct TrimContext'
 * @param key key of the entry
 * @param value the 'struct KeywordCounter'
 * @return GNUNET_YES (always)
 */
static int
migrate_and_drop_metadata (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct TrimContext *tc = cls;
  struct MetaCounter *counter = value;

  if (counter->count >= tc->move_threshold)
  {
    if (NULL == tc->pos->meta)
      tc->pos->meta = GNUNET_CONTAINER_meta_data_create ();
    GNUNET_CONTAINER_meta_data_insert (tc->pos->meta,
				       counter->plugin_name,
				       counter->type,
				       counter->format,
				       counter->data_mime_type, counter->data,
				       counter->data_size); 
  }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (tc->metacounter,
						       key,
						       counter));
  GNUNET_free (counter);
  return GNUNET_YES;
}


/**
 * Process a share item tree, moving frequent keywords up and
 * copying frequent metadata up.
 *
 * @param tc trim context with hash maps to use
 * @param tree tree to trim
 */
static void
share_tree_trim (struct TrimContext *tc,
		 struct GNUNET_FS_ShareTreeItem *tree)
{
  struct GNUNET_FS_ShareTreeItem *pos;
  unsigned int num_children;

  /* first, trim all children */
  num_children = 0;
  for (pos = tree->children_head; NULL != pos; pos = pos->next)
  {
    share_tree_trim (tc, pos);
    num_children++;
  }

  /* consider adding filename to directory meta data */
  if (tree->is_directory == GNUNET_YES)
  {
    const char *user = getenv ("USER");
    if ( (user == NULL) || 
	 (0 != strncasecmp (user, tree->short_filename, strlen(user))))
    {
      /* only use filename if it doesn't match $USER */
      if (NULL == tree->meta)
	tree->meta = GNUNET_CONTAINER_meta_data_create ();
      GNUNET_CONTAINER_meta_data_insert (tree->meta, "<libgnunetfs>",
					 EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME,
					 EXTRACTOR_METAFORMAT_UTF8,
					 "text/plain", tree->short_filename,
					 strlen (tree->short_filename) + 1);
    }
  }

  if (1 >= num_children)
    return; /* nothing to trim */
  
  /* now, count keywords and meta data in children */
  for (pos = tree->children_head; NULL != pos; pos = pos->next)
  {
    if (NULL != pos->meta)
      GNUNET_CONTAINER_meta_data_iterate (pos->meta, &add_to_meta_counter, tc->metacounter);    
    if (NULL != pos->ksk_uri)
      GNUNET_FS_uri_ksk_get_keywords (pos->ksk_uri, &add_to_keyword_counter, tc->keywordcounter);
  }

  /* calculate threshold for moving keywords / meta data */
  tc->move_threshold = 1 + (num_children / 2);

  /* remove high-frequency keywords from children */
  for (pos = tree->children_head; NULL != pos; pos = pos->next)
  {
    tc->pos = pos;
    if (NULL != pos->ksk_uri)
    {
      struct GNUNET_FS_Uri *ksk_uri_copy = GNUNET_FS_uri_dup (pos->ksk_uri);
      GNUNET_FS_uri_ksk_get_keywords (ksk_uri_copy, &remove_high_frequency_keywords, tc);
      GNUNET_FS_uri_destroy (ksk_uri_copy);
    }
  }

  /* add high-frequency meta data and keywords to parent */
  tc->pos = tree;
  GNUNET_CONTAINER_multihashmap_iterate (tc->keywordcounter, 
					 &migrate_and_drop_keywords,
					 tc);
  GNUNET_CONTAINER_multihashmap_iterate (tc->metacounter, 
					 &migrate_and_drop_metadata,
					 tc);
}


/**
 * Process a share item tree, moving frequent keywords up and
 * copying frequent metadata up.
 *
 * @param toplevel toplevel directory in the tree, returned by the scanner
 */
void
GNUNET_FS_share_tree_trim (struct GNUNET_FS_ShareTreeItem *toplevel)
{
  struct TrimContext tc;

  if (toplevel == NULL)
    return;  
  tc.keywordcounter = GNUNET_CONTAINER_multihashmap_create (1024);
  tc.metacounter = GNUNET_CONTAINER_multihashmap_create (1024);
  share_tree_trim (&tc, toplevel);
  GNUNET_CONTAINER_multihashmap_destroy (tc.keywordcounter);
  GNUNET_CONTAINER_multihashmap_destroy (tc.metacounter);
}


/**
 * Release memory of a share item tree.
 *
 * @param toplevel toplevel of the tree to be freed
 */
void
GNUNET_FS_share_tree_free (struct GNUNET_FS_ShareTreeItem *toplevel)
{
  struct GNUNET_FS_ShareTreeItem *pos;

  while (NULL != (pos = toplevel->children_head))
    GNUNET_FS_share_tree_free (pos);
  if (NULL != toplevel->parent)
    GNUNET_CONTAINER_DLL_remove (toplevel->parent->children_head,
				 toplevel->parent->children_tail,
				 toplevel);
  if (NULL != toplevel->meta)
    GNUNET_CONTAINER_meta_data_destroy (toplevel->meta);
  if (NULL != toplevel->ksk_uri)
    GNUNET_FS_uri_destroy (toplevel->ksk_uri);
  GNUNET_free_non_null (toplevel->filename);
  GNUNET_free_non_null (toplevel->short_filename);
  GNUNET_free (toplevel);
}

/* end fs_sharetree.c */


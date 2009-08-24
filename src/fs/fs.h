/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs.h
 * @brief definitions for the entire fs module
 * @author Igor Wronsky, Christian Grothoff
 */
#ifndef FS_H
#define FS_H

/**
 * Size of the individual blocks used for file-sharing.
 */
#define GNUNET_FS_DBLOCK_SIZE (32*1024)

/**
 * @brief content hash key
 */
struct ContentHashKey 
{
  GNUNET_HashCode key;
  GNUNET_HashCode query;
};


/**
 * @brief complete information needed
 * to download a file.
 */
struct FileIdentifier
{

  /**
   * Total size of the file in bytes. (network byte order (!))
   */
  unsigned long long file_length;

  /**
   * Query and key of the top GNUNET_EC_IBlock.
   */
  struct ContentHashKey chk;

};


/**
 * Information about a file and its location
 * (peer claiming to share the file).
 */
struct Location
{
  /**
   * Information about the shared file.
   */
  struct FileIdentifier fi;

  /**
   * Identity of the peer sharing the file.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded peer;

  /**
   * Time when this location URI expires.
   */
  struct GNUNET_TIME_Absolute expirationTime;

  /**
   * RSA signature over the GNUNET_EC_FileIdentifier,
   * GNUNET_hash of the peer and expiration time.
   */
  struct GNUNET_CRYPTO_RsaSignature contentSignature;

};

enum uri_types
{ chk, sks, ksk, loc };

/**
 * A Universal Resource Identifier (URI), opaque.
 */
struct GNUNET_FS_Uri
{
  enum uri_types type;
  union
  {
    struct
    {
      /**
       * Keywords start with a '+' if they are
       * mandatory (in which case the '+' is NOT
       * part of the keyword) and with a
       * simple space if they are optional
       * (in which case the space is ALSO not
       * part of the actual keyword).
       *
       * Double-quotes to protect spaces and
       * %-encoding are NOT used internally
       * (only in URI-strings).
       */
      char **keywords;
      
      /**
       * Size of the keywords array.
       */
      unsigned int keywordCount;
    } ksk;

    struct
    {
      /**
       * Hash of the public key for the namespace.
       */
      GNUNET_HashCode namespace;

      /**
       * Human-readable identifier chosen for this
       * entry in the namespace.
       */
      char *identifier;
    } sks;

    /**
     * Information needed to retrieve a file (content-hash-key
     * plus file size).
     */
    struct FileIdentifier chk;

    /**
     * Information needed to retrieve a file including signed
     * location (identity of a peer) of the content.
     */
    struct Location loc;
  } data;

};


/**
 * Information for a file or directory that is
 * about to be published.
 */
struct GNUNET_FS_FileInformation
{

  /**
   * Files in a directory are kept as a linked list.
   */
  struct GNUNET_FS_FileInformation *next;

  /**
   * If this is a file in a directory, "dir" refers to
   * the directory; otherwise NULL.
   */
  struct GNUNET_FS_FileInformation *dir;

  /**
   * Pointer kept for the client.
   */
  void *client_info;

  /**
   * Metadata to use for the file.
   */
  struct GNUNET_CONTAINER_MetaData *meta;

  /**
   * Keywords to use for KBlocks.
   */
  struct GNUNET_FS_Uri *keywords;

  /**
   * At what time should the content expire?
   */
  struct GNUNET_TIME_Absolute expirationTime;

  /**
   * Under what filename is this struct serialized
   * (for operational persistence).
   */
  char *serialization;

  /**
   * How many bytes of this file or directory have been
   * published so far?
   */
  uint64_t publish_offset;

  /**
   * Data describing either the file or the directory.
   */
  union
  {

    /**
     * Data for a file.
     */
    struct {

      /**
       * Function that can be used to read the data for the file.
       */
      GNUNET_FS_DataReader reader;

      /**
       * Closure for reader.
       */
      void *reader_cls;

      /**
       * Size of the file (in bytes).
       */
      uint64_t file_size;

      /**
       * Should the file be indexed or inserted?
       */
      int do_index;

    } file;

    /**
     * Data for a directory.
     */
    struct {
      
      /**
       * Name of the directory.
       */
      char *dirname;
      
      /**
       * Linked list of entries in the directory.
       */
      struct GNUNET_FS_FileInformation *entries;

      /**
       * Size of the directory itself (in bytes); 0 if the
       * size has not yet been calculated.
       */
      uint64_t dir_size;

    } dir;

  } data;

  /**
   * Is this struct for a file or directory?
   */
  int is_directory;

  /**
   * Desired anonymity level.
   */
  unsigned int anonymity;

  /**
   * Desired priority (for keeping the content in the DB).
   */
  unsigned int priority;

};


#endif

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
      unsigned int keywordCount;
    } ksk;
    struct
    {
      GNUNET_HashCode namespace;
      char *identifier;
    } sks;
    struct FileIdentifier chk;
    struct Location loc;
  } data;

};

#endif

/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2008, 2011 Christian Grothoff (and other contributing authors)

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
 * @file util/container_bloomfilter.c
 * @brief data structure used to reduce disk accesses.
 *
 * The idea basically: Create a signature for each element in the
 * database. Add those signatures to a bit array. When doing a lookup,
 * check if the bit array matches the signature of the requested
 * element. If yes, address the disk, otherwise return 'not found'.
 *
 * A property of the bloom filter is that sometimes we will have
 * a match even if the element is not on the disk (then we do
 * an unnecessary disk access), but what's most important is that
 * we never get a single "false negative".
 *
 * To be able to delete entries from the bloom filter, we maintain
 * a 4 bit counter in the file on the drive (we still use only one
 * bit in memory).
 *
 * @author Igor Wronsky
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

struct GNUNET_CONTAINER_BloomFilter
{

  /**
   * The actual bloomfilter bit array
   */
  char *bitArray;

  /**
   * Filename of the filter
   */
  char *filename;

  /**
   * The bit counter file on disk
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * How many bits we set for each stored element
   */
  unsigned int addressesPerElement;

  /**
   * Size of bitArray in bytes
   */
  size_t bitArraySize;

};



/**
 * Get size of the bloom filter.
 *
 * @param bf the filter
 * @return number of bytes used for the data of the bloom filter
 */
size_t
GNUNET_CONTAINER_bloomfilter_get_size (const struct GNUNET_CONTAINER_BloomFilter
                                       *bf)
{
  if (bf == NULL)
    return 0;
  return bf->bitArraySize;
}


/**
 * Copy an existing memory.  Any association with a file
 * on-disk will be lost in the process.
 * @param bf the filter to copy
 * @return copy of the bf
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_copy (const struct GNUNET_CONTAINER_BloomFilter
                                   *bf)
{
  return GNUNET_CONTAINER_bloomfilter_init (bf->bitArray, bf->bitArraySize,
                                            bf->addressesPerElement);
}


/**
 * Sets a bit active in the bitArray. Increment bit-specific
 * usage counter on disk only if below 4bit max (==15).
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
static void
setBit (char *bitArray, unsigned int bitIdx)
{
  size_t arraySlot;
  unsigned int targetBit;

  arraySlot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitArray[arraySlot] |= targetBit;
}

/**
 * Clears a bit from bitArray. Bit is cleared from the array
 * only if the respective usage counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to unset
 */
static void
clearBit (char *bitArray, unsigned int bitIdx)
{
  size_t slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitArray[slot] = bitArray[slot] & (~targetBit);
}

/**
 * Checks if a bit is active in the bitArray
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @return GNUNET_YES if the bit is set, GNUNET_NO if not.
 */
static int
testBit (char *bitArray, unsigned int bitIdx)
{
  size_t slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  if (bitArray[slot] & targetBit)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}

/**
 * Sets a bit active in the bitArray and increments
 * bit-specific usage counter on disk (but only if
 * the counter was below 4 bit max (==15)).
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fh A file to keep the 4 bit address usage counters in
 */
static void
incrementBit (char *bitArray, unsigned int bitIdx,
              const struct GNUNET_DISK_FileHandle *fh)
{
  OFF_T fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  setBit (bitArray, bitIdx);
  if (GNUNET_DISK_handle_invalid (fh))
    return;
  /* Update the counter file on disk */
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;

  GNUNET_assert (fileSlot ==
                 GNUNET_DISK_file_seek (fh, fileSlot, GNUNET_DISK_SEEK_SET));
  if (1 != GNUNET_DISK_file_read (fh, &value, 1))
    value = 0;
  low = value & 0xF;
  high = (value & (~0xF)) >> 4;

  if (targetLoc == 0)
  {
    if (low < 0xF)
      low++;
  }
  else
  {
    if (high < 0xF)
      high++;
  }
  value = ((high << 4) | low);
  GNUNET_assert (fileSlot ==
                 GNUNET_DISK_file_seek (fh, fileSlot, GNUNET_DISK_SEEK_SET));
  GNUNET_assert (1 == GNUNET_DISK_file_write (fh, &value, 1));
}

/**
 * Clears a bit from bitArray if the respective usage
 * counter on the disk hits/is zero.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @param fh A file to keep the 4bit address usage counters in
 */
static void
decrementBit (char *bitArray, unsigned int bitIdx,
              const struct GNUNET_DISK_FileHandle *fh)
{
  OFF_T fileSlot;
  unsigned char value;
  unsigned int high;
  unsigned int low;
  unsigned int targetLoc;

  if (GNUNET_DISK_handle_invalid (fh))
    return;                     /* cannot decrement! */
  /* Each char slot in the counter file holds two 4 bit counters */
  fileSlot = bitIdx / 2;
  targetLoc = bitIdx % 2;
  GNUNET_DISK_file_seek (fh, fileSlot, GNUNET_DISK_SEEK_SET);
  if (1 != GNUNET_DISK_file_read (fh, &value, 1))
    value = 0;
  low = value & 0xF;
  high = (value & 0xF0) >> 4;

  /* decrement, but once we have reached the max, never go back! */
  if (targetLoc == 0)
  {
    if ((low > 0) && (low < 0xF))
      low--;
    if (low == 0)
    {
      clearBit (bitArray, bitIdx);
    }
  }
  else
  {
    if ((high > 0) && (high < 0xF))
      high--;
    if (high == 0)
    {
      clearBit (bitArray, bitIdx);
    }
  }
  value = ((high << 4) | low);
  GNUNET_DISK_file_seek (fh, fileSlot, GNUNET_DISK_SEEK_SET);
  GNUNET_assert (1 == GNUNET_DISK_file_write (fh, &value, 1));
}

#define BUFFSIZE 65536

/**
 * Creates a file filled with zeroes
 *
 * @param fh the file handle
 * @param size the size of the file
 * @return GNUNET_OK if created ok, GNUNET_SYSERR otherwise
 */
static int
make_empty_file (const struct GNUNET_DISK_FileHandle *fh, size_t size)
{
  char buffer[BUFFSIZE];
  size_t bytesleft = size;
  int res = 0;

  if (GNUNET_DISK_handle_invalid (fh))
    return GNUNET_SYSERR;
  memset (buffer, 0, sizeof (buffer));
  GNUNET_DISK_file_seek (fh, 0, GNUNET_DISK_SEEK_SET);
  while (bytesleft > 0)
  {
    if (bytesleft > sizeof (buffer))
    {
      res = GNUNET_DISK_file_write (fh, buffer, sizeof (buffer));
      if (res >= 0)
	bytesleft -= res;
    }
    else
    {
      res = GNUNET_DISK_file_write (fh, buffer, bytesleft);
      if (res >= 0)
	bytesleft -= res;
    }
    if (GNUNET_SYSERR == res)
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/* ************** GNUNET_CONTAINER_BloomFilter iterator ********* */

/**
 * Iterator (callback) method to be called by the
 * bloomfilter iterator on each bit that is to be
 * set or tested for the key.
 *
 * @param cls closure
 * @param bf the filter to manipulate
 * @param bit the current bit
 * @return GNUNET_YES to continue, GNUNET_NO to stop early
 */
typedef int (*BitIterator) (void *cls,
                            const struct GNUNET_CONTAINER_BloomFilter * bf,
                            unsigned int bit);


/**
 * Call an iterator for each bit that the bloomfilter
 * must test or set for this element.
 *
 * @param bf the filter
 * @param callback the method to call
 * @param arg extra argument to callback
 * @param key the key for which we iterate over the BF bits
 */
static void
iterateBits (const struct GNUNET_CONTAINER_BloomFilter *bf,
             BitIterator callback, void *arg, const GNUNET_HashCode * key)
{
  GNUNET_HashCode tmp[2];
  int bitCount;
  unsigned int round;
  unsigned int slot = 0;

  bitCount = bf->addressesPerElement;
  tmp[0] = *key;
  round = 0;
  while (bitCount > 0)
  {
    while (slot < (sizeof (GNUNET_HashCode) / sizeof (uint32_t)))
    {
      if (GNUNET_YES !=
          callback (arg, bf,
                    (((uint32_t *) & tmp[round & 1])[slot]) &
                    ((bf->bitArraySize * 8) - 1)))
        return;
      slot++;
      bitCount--;
      if (bitCount == 0)
        break;
    }
    if (bitCount > 0)
    {
      GNUNET_CRYPTO_hash (&tmp[round & 1], sizeof (GNUNET_HashCode),
                          &tmp[(round + 1) & 1]);
      round++;
      slot = 0;
    }
  }
}


/**
 * Callback: increment bit
 *
 * @param cls pointer to writeable form of bf
 * @param bf the filter to manipulate
 * @param bit the bit to increment
 * @return GNUNET_YES
 */
static int
incrementBitCallback (void *cls, const struct GNUNET_CONTAINER_BloomFilter *bf,
                      unsigned int bit)
{
  struct GNUNET_CONTAINER_BloomFilter *b = cls;

  incrementBit (b->bitArray, bit, bf->fh);
  return GNUNET_YES;
}


/**
 * Callback: decrement bit
 *
 * @param cls pointer to writeable form of bf
 * @param bf the filter to manipulate
 * @param bit the bit to decrement
 * @return GNUNET_YES
 */
static int
decrementBitCallback (void *cls, const struct GNUNET_CONTAINER_BloomFilter *bf,
                      unsigned int bit)
{
  struct GNUNET_CONTAINER_BloomFilter *b = cls;

  decrementBit (b->bitArray, bit, bf->fh);
  return GNUNET_YES;
}


/**
 * Callback: test if all bits are set
 *
 * @param cls pointer set to GNUNET_NO if bit is not set
 * @param bf the filter
 * @param bit the bit to test
 * @return YES if the bit is set, NO if not
 */
static int
testBitCallback (void *cls, const struct GNUNET_CONTAINER_BloomFilter *bf,
                 unsigned int bit)
{
  int *arg = cls;

  if (GNUNET_NO == testBit (bf->bitArray, bit))
  {
    *arg = GNUNET_NO;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

/* *********************** INTERFACE **************** */

/**
 * Load a bloom-filter from a file.
 *
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of GNUNET_CRYPTO_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_load (const char *filename, size_t size,
                                   unsigned int k)
{
  struct GNUNET_CONTAINER_BloomFilter *bf;
  char *rbuff;
  OFF_T pos;
  int i;
  size_t ui;
  OFF_T fsize;
  int must_read;

  GNUNET_assert (NULL != filename);
  if ((k == 0) || (size == 0))
    return NULL;
  if (size < BUFFSIZE)
    size = BUFFSIZE;
  ui = 1;
  while ( (ui < size) &&
	  (ui * 2 > ui) )
    ui *= 2;
  size = ui;                    /* make sure it's a power of 2 */

  bf = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_BloomFilter));
  /* Try to open a bloomfilter file */
  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    bf->fh =
      GNUNET_DISK_file_open (filename,
                             GNUNET_DISK_OPEN_READWRITE,
                             GNUNET_DISK_PERM_USER_READ |
                             GNUNET_DISK_PERM_USER_WRITE);
  if (NULL != bf->fh)
  {
    /* file existed, try to read it! */
    must_read = GNUNET_YES;
    if (GNUNET_OK !=
	GNUNET_DISK_file_handle_size (bf->fh, &fsize))
    {
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
    if (fsize == 0)
    {
      /* found existing empty file, just overwrite */
      if (GNUNET_OK != make_empty_file (bf->fh, size * 4LL))
      {
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			     "write");
	GNUNET_DISK_file_close (bf->fh);
	GNUNET_free (bf);
	return NULL;
      }
    }
    else if (fsize != size * 4LL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Size of file on disk is incorrect for this Bloom filter (want %llu, have %llu)\n"),
		  (unsigned long long) (size * 4LL),
		  (unsigned long long) fsize);
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
  }
  else
  {
    /* file did not exist, don't read, just create */
    must_read = GNUNET_NO;
    bf->fh =
      GNUNET_DISK_file_open (filename,
                             GNUNET_DISK_OPEN_CREATE |
                             GNUNET_DISK_OPEN_READWRITE,
                             GNUNET_DISK_PERM_USER_READ |
                             GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == bf->fh)
      {
	GNUNET_free (bf);
	return NULL;
      }
    if (GNUNET_OK != make_empty_file (bf->fh, size * 4LL))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			   "write");
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
  }
  bf->filename = GNUNET_strdup (filename);
  /* Alloc block */
  bf->bitArray = GNUNET_malloc_large (size);
  if (bf->bitArray == NULL)
  {
    if (bf->fh != NULL)
      GNUNET_DISK_file_close (bf->fh);
    GNUNET_free (bf->filename);
    GNUNET_free (bf);
    return NULL;
  }
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  memset (bf->bitArray, 0, bf->bitArraySize);

  if (GNUNET_YES != must_read)      
    return bf; /* already done! */  
  /* Read from the file what bits we can */
  rbuff = GNUNET_malloc (BUFFSIZE);
  pos = 0;
  while (pos < size * 8LL)
  {
    int res;

    res = GNUNET_DISK_file_read (bf->fh, rbuff, BUFFSIZE);
    if (res == -1)
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "read", bf->filename);
      GNUNET_free (rbuff);
      GNUNET_free (bf->filename);
      GNUNET_DISK_file_close (bf->fh);
      GNUNET_free (bf);
      return NULL;
    }
    if (res == 0)
      break;                    /* is ok! we just did not use that many bits yet */
    for (i = 0; i < res; i++)
    {
      if ((rbuff[i] & 0x0F) != 0)
        setBit (bf->bitArray, pos + i * 2);
      if ((rbuff[i] & 0xF0) != 0)
        setBit (bf->bitArray, pos + i * 2 + 1);
    }
    if (res < BUFFSIZE)
      break;
    pos += BUFFSIZE * 2;        /* 2 bits per byte in the buffer */
  }
  GNUNET_free (rbuff);
  return bf;
}


/**
 * Create a bloom filter from raw bits.
 *
 * @param data the raw bits in memory (maybe NULL,
 *        in which case all bits should be considered
 *        to be zero).
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use); also size of data
 *        -- unless data is NULL
 * @param k the number of GNUNET_CRYPTO_hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_CONTAINER_bloomfilter_init (const char *data, size_t size,
                                   unsigned int k)
{
  struct GNUNET_CONTAINER_BloomFilter *bf;
  size_t ui;

  if ((k == 0) || (size == 0))
    return NULL;
  ui = 1;
  while (ui < size)
    ui *= 2;
  if (size != ui)
  {
    GNUNET_break (0);
    return NULL;
  }
  bf = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_BloomFilter));
  bf->filename = NULL;
  bf->fh = NULL;
  bf->bitArray = GNUNET_malloc_large (size);
  if (bf->bitArray == NULL)
  {
    GNUNET_free (bf);
    return NULL;
  }
  bf->bitArraySize = size;
  bf->addressesPerElement = k;
  if (data != NULL)
    memcpy (bf->bitArray, data, size);
  else
    memset (bf->bitArray, 0, bf->bitArraySize);
  return bf;
}


/**
 * Copy the raw data of this bloomfilter into
 * the given data array.
 *
 * @param bf bloomfilter to take the raw data from
 * @param data where to write the data
 * @param size the size of the given data array
 * @return GNUNET_SYSERR if the data array is not big enough
 */
int
GNUNET_CONTAINER_bloomfilter_get_raw_data (const struct
                                           GNUNET_CONTAINER_BloomFilter *bf,
                                           char *data, size_t size)
{
  if (NULL == bf)
    return GNUNET_SYSERR;
  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  memcpy (data, bf->bitArray, size);
  return GNUNET_OK;
}


/**
 * Free the space associated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 *
 * @param bf the filter
 */
void
GNUNET_CONTAINER_bloomfilter_free (struct GNUNET_CONTAINER_BloomFilter *bf)
{
  if (NULL == bf)
    return;
  if (bf->fh != NULL)
    GNUNET_DISK_file_close (bf->fh);
  GNUNET_free_non_null (bf->filename);
  GNUNET_free (bf->bitArray);
  GNUNET_free (bf);
}


/**
 * Reset a bloom filter to empty. Clears the file on disk.
 *
 * @param bf the filter
 */
void
GNUNET_CONTAINER_bloomfilter_clear (struct GNUNET_CONTAINER_BloomFilter *bf)
{
  if (NULL == bf)
    return;

  memset (bf->bitArray, 0, bf->bitArraySize);
  if (bf->filename != NULL)
    make_empty_file (bf->fh, bf->bitArraySize * 4LL);
}


/**
 * Test if an element is in the filter.
 *
 * @param e the element
 * @param bf the filter
 * @return GNUNET_YES if the element is in the filter, GNUNET_NO if not
 */
int
GNUNET_CONTAINER_bloomfilter_test (const struct GNUNET_CONTAINER_BloomFilter
                                   *bf, const GNUNET_HashCode * e)
{
  int res;

  if (NULL == bf)
    return GNUNET_YES;
  res = GNUNET_YES;
  iterateBits (bf, &testBitCallback, &res, e);
  return res;
}


/**
 * Add an element to the filter
 *
 * @param bf the filter
 * @param e the element
 */
void
GNUNET_CONTAINER_bloomfilter_add (struct GNUNET_CONTAINER_BloomFilter *bf,
                                  const GNUNET_HashCode * e)
{
  if (NULL == bf)
    return;
  iterateBits (bf, &incrementBitCallback, bf, e);
}


/**
 * Or the entries of the given raw data array with the
 * data of the given bloom filter.  Assumes that
 * the size of the data array and the current filter
 * match.
 *
 * @param bf the filter
 * @param data the data to or-in
 * @param size number of bytes in data
 */
int
GNUNET_CONTAINER_bloomfilter_or (struct GNUNET_CONTAINER_BloomFilter *bf,
                                 const char *data, size_t size)
{
  unsigned int i;
  unsigned int n;
  unsigned long long *fc;
  const unsigned long long *dc;

  if (NULL == bf)
    return GNUNET_YES;
  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  fc = (unsigned long long *) bf->bitArray;
  dc = (const unsigned long long *) data;
  n = size / sizeof (unsigned long long);

  for (i = 0; i < n; i++)
    fc[i] |= dc[i];
  for (i = n * sizeof (unsigned long long); i < size; i++)
    bf->bitArray[i] |= data[i];
  return GNUNET_OK;
}

/**
 * Or the entries of the given raw data array with the
 * data of the given bloom filter.  Assumes that
 * the size of the data array and the current filter
 * match.
 *
 * @param bf the filter
 * @param to_or the bloomfilter to or-in
 * @param size number of bytes in data
 */
int
GNUNET_CONTAINER_bloomfilter_or2 (struct GNUNET_CONTAINER_BloomFilter *bf,
                                  const struct GNUNET_CONTAINER_BloomFilter
                                  *to_or, size_t size)
{
  unsigned int i;
  unsigned int n;
  unsigned long long *fc;
  const unsigned long long *dc;

  if (NULL == bf)
    return GNUNET_YES;
  if (bf->bitArraySize != size)
    return GNUNET_SYSERR;
  fc = (unsigned long long *) bf->bitArray;
  dc = (const unsigned long long *) to_or->bitArray;
  n = size / sizeof (unsigned long long);

  for (i = 0; i < n; i++)
    fc[i] |= dc[i];
  for (i = n * sizeof (unsigned long long); i < size; i++)
    bf->bitArray[i] |= to_or->bitArray[i];
  return GNUNET_OK;
}

/**
 * Remove an element from the filter.
 *
 * @param bf the filter
 * @param e the element to remove
 */
void
GNUNET_CONTAINER_bloomfilter_remove (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     const GNUNET_HashCode * e)
{
  if (NULL == bf)
    return;
  if (bf->filename == NULL)
    return;
  iterateBits (bf, &decrementBitCallback, bf, e);
}

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_cls argument to the iterator function
 * @param size the new size for the filter
 * @param k the new number of GNUNET_CRYPTO_hash-function to apply per element
 */
void
GNUNET_CONTAINER_bloomfilter_resize (struct GNUNET_CONTAINER_BloomFilter *bf,
                                     GNUNET_HashCodeIterator iterator,
                                     void *iterator_cls, size_t size,
                                     unsigned int k)
{
  GNUNET_HashCode hc;
  unsigned int i;

  GNUNET_free (bf->bitArray);
  i = 1;
  while (i < size)
    i *= 2;
  size = i;                     /* make sure it's a power of 2 */

  bf->bitArraySize = size;
  bf->bitArray = GNUNET_malloc (size);
  memset (bf->bitArray, 0, bf->bitArraySize);
  if (bf->filename != NULL)
    make_empty_file (bf->fh, bf->bitArraySize * 4LL);
  while (GNUNET_YES == iterator (iterator_cls, &hc))
    GNUNET_CONTAINER_bloomfilter_add (bf, &hc);
}

/* end of container_bloomfilter.c */

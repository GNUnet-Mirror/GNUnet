/*
     This file is part of GNUnet.
     (C) 2008, 2011 Christian Grothoff (and other contributing authors)

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
 * @file conversation/mst.c
 * @brief Message tokenizer
 * @author Christian Grothoff
 */

#include <gnunet/platform.h>
#include <gnunet/gnunet_constants.h>

/**
 * To what multiple do we align messages?  8 byte should suffice for everyone
 * for now.
 */
#define ALIGN_FACTOR 8

/**
 * Smallest supported message.
 */
#define MIN_BUFFER_SIZE sizeof (struct GNUNET_MessageHeader)


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * @param cls closure
 * @param message the actual message
 */
typedef void (*MessageTokenizerCallback) (void *cls, 
					  const struct
					  GNUNET_MessageHeader *
					  message);

/**
 * Handle to a message stream tokenizer.
 */
struct MessageStreamTokenizer
{

  /**
   * Function to call on completed messages.
   */
  MessageTokenizerCallback cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Size of the buffer (starting at 'hdr').
   */
  size_t curr_buf;

  /**
   * How many bytes in buffer have we already processed?
   */
  size_t off;

  /**
   * How many bytes in buffer are valid right now?
   */
  size_t pos;

  /**
   * Beginning of the buffer.  Typed like this to force alignment.
   */
  struct GNUNET_MessageHeader *hdr;

};


/**
 * Create a message stream tokenizer.
 *
 * @param cb function to call on completed messages
 * @param cb_cls closure for cb
 * @return handle to tokenizer
 */
static struct MessageStreamTokenizer *
mst_create (MessageTokenizerCallback cb,
		void *cb_cls)
{
  struct MessageStreamTokenizer *ret;

  ret = malloc (sizeof (struct MessageStreamTokenizer));
  if (NULL == ret)
  {
	fprintf (stderr, "Failed to allocate buffer for tokenizer\n");
	exit (1);
  }
  ret->hdr = malloc (MIN_BUFFER_SIZE);
  if (NULL == ret->hdr)
  {
	fprintf (stderr, "Failed to allocate buffer for alignment\n");
	exit (1);
  }
  ret->curr_buf = MIN_BUFFER_SIZE;
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  return ret;
}


/**
 * Add incoming data to the receive buffer and call the
 * callback for all complete messages.
 *
 * @param mst tokenizer to use
 * @param buf input data to add
 * @param size number of bytes in buf
 * @return GNUNET_OK if we are done processing (need more data)
 *         GNUNET_SYSERR if the data stream is corrupt
 */
static int
mst_receive (struct MessageStreamTokenizer *mst,
		 const char *buf, size_t size)
{
  const struct GNUNET_MessageHeader *hdr;
  size_t delta;
  uint16_t want;
  char *ibuf;
  int need_align;
  unsigned long offset;
  int ret;

  ret = GNUNET_OK;
  ibuf = (char *) mst->hdr;
  while (mst->pos > 0)
  {
do_align:
	if ((mst->curr_buf - mst->off < sizeof (struct GNUNET_MessageHeader)) ||
		(0 != (mst->off % ALIGN_FACTOR)))
	{
	  /* need to align or need more space */
	  mst->pos -= mst->off;
	  memmove (ibuf, &ibuf[mst->off], mst->pos);
	  mst->off = 0;
	}
	if (mst->pos - mst->off < sizeof (struct GNUNET_MessageHeader))
	{
	  delta =
		  GNUNET_MIN (sizeof (struct GNUNET_MessageHeader) -
					  (mst->pos - mst->off), size);
	  memcpy (&ibuf[mst->pos], buf, delta);
	  mst->pos += delta;
	  buf += delta;
	  size -= delta;
	}
	if (mst->pos - mst->off < sizeof (struct GNUNET_MessageHeader))
	{
	  return GNUNET_OK;
	}
	hdr = (const struct GNUNET_MessageHeader *) &ibuf[mst->off];
	want = ntohs (hdr->size);
	if (want < sizeof (struct GNUNET_MessageHeader))
	{
	  fprintf (stderr,
		   "Received invalid message from stdin\n");
	  exit (1);
	}
	if (mst->curr_buf - mst->off < want)
	{
	  /* need more space */
	  mst->pos -= mst->off;
	  memmove (ibuf, &ibuf[mst->off], mst->pos);
	  mst->off = 0;
	}
	if (want > mst->curr_buf)
	{
	  mst->hdr = realloc (mst->hdr, want);
	  if (NULL == mst->hdr)
	  {
	fprintf (stderr, "Failed to allocate buffer for alignment\n");
	exit (1);
	  }
	  ibuf = (char *) mst->hdr;
	  mst->curr_buf = want;
	}
	hdr = (const struct GNUNET_MessageHeader *) &ibuf[mst->off];
	if (mst->pos - mst->off < want)
	{
	  delta = GNUNET_MIN (want - (mst->pos - mst->off), size);
	  memcpy (&ibuf[mst->pos], buf, delta);
	  mst->pos += delta;
	  buf += delta;
	  size -= delta;
	}
	if (mst->pos - mst->off < want)
	{
	  return GNUNET_OK;
	}
	mst->cb (mst->cb_cls, hdr);
	mst->off += want;
	if (mst->off == mst->pos)
	{
	  /* reset to beginning of buffer, it's free right now! */
	  mst->off = 0;
	  mst->pos = 0;
	}
  }
  while (size > 0)
  {
	if (size < sizeof (struct GNUNET_MessageHeader))
	  break;
	offset = (unsigned long) buf;
	need_align = (0 != offset % ALIGN_FACTOR) ? GNUNET_YES : GNUNET_NO;
	if (GNUNET_NO == need_align)
	{
	  /* can try to do zero-copy and process directly from original buffer */
	  hdr = (const struct GNUNET_MessageHeader *) buf;
	  want = ntohs (hdr->size);
	  if (want < sizeof (struct GNUNET_MessageHeader))
	  {
	fprintf (stderr,
		 "Received invalid message from stdin\n");
	exit (1);
	  }
	  if (size < want)
		break;                  /* or not, buffer incomplete, so copy to private buffer... */
	  mst->cb (mst->cb_cls, hdr);
	  buf += want;
	  size -= want;
	}
	else
	{
	  /* need to copy to private buffer to align;
	   * yes, we go a bit more spagetti than usual here */
	  goto do_align;
	}
  }
  if (size > 0)
  {
	if (size + mst->pos > mst->curr_buf)
	{
	  mst->hdr = realloc (mst->hdr, size + mst->pos);
	  if (NULL == mst->hdr)
	  {
	fprintf (stderr, "Failed to allocate buffer for alignment\n");
	exit (1);
	  }
	  ibuf = (char *) mst->hdr;
	  mst->curr_buf = size + mst->pos;
	}
	if (mst->pos + size > mst->curr_buf)
	{
	  fprintf (stderr,
		   "Assertion failed\n");
	  exit (1);
	}
	memcpy (&ibuf[mst->pos], buf, size);
	mst->pos += size;
  }
  return ret;
}


/**
 * Destroys a tokenizer.
 *
 * @param mst tokenizer to destroy
 */
static void
mst_destroy (struct MessageStreamTokenizer *mst)
{
  free (mst->hdr);
  free (mst);
}

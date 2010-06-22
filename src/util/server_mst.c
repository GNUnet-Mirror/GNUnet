/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/server_mst.c
 * @brief convenience functions for handling inbound message buffers
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"

#if HAVE_UNALIGNED_64_ACCESS
#define ALIGN_FACTOR 4
#else
#define ALIGN_FACTOR 8
#endif


/**
 * Handle to a message stream tokenizer.
 */
struct GNUNET_SERVER_MessageStreamTokenizer
{

  /**
   * Function to call on completed messages.
   */
  GNUNET_SERVER_MessageTokenizerCallback cb;
  
  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Client to pass to cb.
   */
  void *client_identity;

  /**
   * Size of the buffer (starting at 'hdr').
   */
  size_t maxbuf;

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
  struct GNUNET_MessageHeader hdr;

};



/**
 * Create a message stream tokenizer.
 *
 * @param maxbuf maximum message size to support (typically
 *    GNUNET_SERVER_MAX_MESSAGE_SIZE)
 * @param client_identity ID of client for which this is a buffer,
 *        can be NULL (will be passed back to 'cb')
 * @param cb function to call on completed messages
 * @param cb_cls closure for cb
 * @return handle to tokenizer
 */
struct GNUNET_SERVER_MessageStreamTokenizer *
GNUNET_SERVER_mst_create (size_t maxbuf,
			  void *client_identity,
			  GNUNET_SERVER_MessageTokenizerCallback cb,
			  void *cb_cls)
{
  struct GNUNET_SERVER_MessageStreamTokenizer *ret;

  ret = GNUNET_malloc (maxbuf + sizeof (struct GNUNET_SERVER_MessageStreamTokenizer));
  ret->maxbuf = maxbuf;
  ret->client_identity = client_identity;
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
 * @param purge should any excess bytes in the buffer be discarded 
 *       (i.e. for packet-based services like UDP)
 * @param one_shot only call callback once, keep rest of message in buffer
 * @return GNUNET_OK if we are done processing (need more data)
 *         GNUNET_NO if one_shot was set and we have another message ready
 *         GNUNET_SYSERR if the data stream is corrupt
 */
int
GNUNET_SERVER_mst_receive (struct GNUNET_SERVER_MessageStreamTokenizer *mst,
			   const char *buf,
			   size_t size,
			   int purge,
			   int one_shot)
{
  const struct GNUNET_MessageHeader *hdr;
  size_t delta;
  uint16_t want;
  char *ibuf;
  int need_align;
  unsigned long offset;
  int ret;

  ret = GNUNET_OK;
  ibuf = (char*) &mst->hdr;
  if (mst->pos > 0)
    {
    do_align:
      if ( (mst->maxbuf - mst->off < sizeof (struct GNUNET_MessageHeader)) ||
	   (0 != (mst->off % ALIGN_FACTOR)) )
	{
	  /* need to align or need more space */
	  mst->pos -= mst->off;
	  memmove (ibuf,
		   &ibuf[mst->off],
		   mst->pos);
	  mst->off = 0;
	}
      if (mst->pos - mst->off < sizeof (struct GNUNET_MessageHeader))
	{
	  delta = GNUNET_MIN (sizeof (struct GNUNET_MessageHeader) - (mst->pos - mst->off),
			      size);
	  memcpy (&ibuf[mst->pos],
		  buf,
		  delta);
	  mst->pos += delta;
	  buf += delta;
	  size -= delta;
	}
      if (mst->pos - mst->off < sizeof (struct GNUNET_MessageHeader))
	{
	  if (purge)
	    {
	      mst->off = 0;    
	      mst->pos = 0;
	    }
	  return GNUNET_OK;
	}
      hdr = (const struct GNUNET_MessageHeader*) &ibuf[mst->off];
      want = ntohs (hdr->size);
      if (want < sizeof (struct GNUNET_MessageHeader))
	{
	  GNUNET_break_op (0);
	  return GNUNET_SYSERR;
	}
      if (mst->maxbuf - mst->off < want)
	{
	  /* need more space */
	  mst->pos -= mst->off;
	  memmove (ibuf,
		   &ibuf[mst->off],
		   mst->pos);
	  mst->off = 0;
	}
      if (mst->pos - mst->off < want)
	{
	  delta = GNUNET_MIN (want - (mst->pos - mst->off),
			      size);
	  memcpy (&ibuf[mst->pos],
		  buf,
		  delta);
	  mst->pos += delta;
	  buf += delta;
	  size -= delta;
	}
      if (mst->pos - mst->off < want)
	{
	  if (purge)
	    {
	      mst->off = 0;    
	      mst->pos = 0;
	    }
	  return GNUNET_OK;
	}
      if (one_shot == GNUNET_SYSERR)
	{
	  /* cannot call callback again, but return value saying that
	     we have another full message in the buffer */
	  ret = GNUNET_NO;
	  goto copy;
	}
      if (one_shot == GNUNET_YES)
	one_shot = GNUNET_SYSERR;
      mst->cb (mst->cb_cls, mst->client_identity, hdr);
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
	  if (size < want)
	    break; /* or not, buffer incomplete, so copy to private buffer... */
	  if (one_shot == GNUNET_SYSERR)
	    {
	      /* cannot call callback again, but return value saying that
		 we have another full message in the buffer */
	      ret = GNUNET_NO;
	      goto copy;
	    }
	  if (one_shot == GNUNET_YES)
	    one_shot = GNUNET_SYSERR;
	  mst->cb (mst->cb_cls, mst->client_identity, hdr);
	  buf += want;
	  size -= want;
	}
      else
	{
	  /* need to copy to private buffer to align;
	     yes, we go a bit more spagetti than usual here */
	  goto do_align;
	}
    }
 copy:
  if ( (size > 0) && (! purge) )
    {
      GNUNET_assert (mst->pos + size <= mst->maxbuf);
      memcpy (&ibuf[mst->pos], buf, size);
      mst->pos += size;
    }
  if (purge)
    mst->off = 0;    
  return ret;
}


/**
 * Destroys a tokenizer.
 *
 * @param mst tokenizer to destroy
 */
void
GNUNET_SERVER_mst_destroy (struct GNUNET_SERVER_MessageStreamTokenizer *mst)
{
  GNUNET_free (mst);
}



/* end of server_mst.c */

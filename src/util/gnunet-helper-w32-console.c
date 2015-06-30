/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file src/util/gnunet-helper-w32-console.c
 * @brief Does blocking reads from the console, writes the results
 *        into stdout, turning blocking console I/O into non-blocking
 *        pipe I/O. For W32 only.
 * @author LRN
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"
#include "gnunet-helper-w32-console.h"

static unsigned long buffer_size;

static int chars;

static HANDLE parent_handle;

/**
 * Write @a size bytes from @a buf into @a output.
 *
 * @param output the descriptor to write into
 * @param buf buffer with data to write
 * @param size number of bytes to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
write_all (int output, 
           const void *buf,
	   size_t size)
{
  const char *cbuf = buf;
  size_t total;
  ssize_t wr;

  total = 0;
  do
  {
    wr = write (output,
		&cbuf[total],
		size - total);
    if (wr > 0)
      total += wr;
  } while ( (wr > 0) && (total < size) );
  if (wr <= 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to write to stdout: %s\n",
		strerror (errno));
  return (total == size) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Write message to the master process.
 *
 * @param output the descriptor to write into
 * @param message_type message type to use
 * @param data data to append, NULL for none
 * @param data_length number of bytes in @a data
 * @return #GNUNET_SYSERR to stop scanning (the pipe was broken somehow)
 */
static int
write_message (int output,
               uint16_t message_type,
	       const char *data,
	       size_t data_length)
{
  struct GNUNET_MessageHeader hdr;

#if 0
  fprintf (stderr,
	   "Helper sends %u-byte message of type %u\n",
	   (unsigned int) (sizeof (struct GNUNET_MessageHeader) + data_length),
	   (unsigned int) message_type);
#endif
  hdr.type = htons (message_type);
  hdr.size = htons (sizeof (struct GNUNET_MessageHeader) + data_length);
  if (GNUNET_OK != write_all (output, &hdr, sizeof (hdr)))
    return GNUNET_SYSERR;
  if (GNUNET_OK != write_all (output, data, data_length))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Main function of the helper process. Reads input events from console,
 * writes messages, into stdout.
 *
 * @param console a handle to a console to read from
 * @param output_stream a stream to write messages to
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
read_events (HANDLE console, int output_stream)
{
  DWORD rr;
  BOOL b;
  INPUT_RECORD *buf;
  DWORD i;
  int result;

  result = GNUNET_SYSERR;
  buf = malloc (sizeof (INPUT_RECORD) * buffer_size);
  if (NULL == buf)
    return result;
  b = TRUE;
  rr = 1;
  while (TRUE == b && 0 < rr)
  {
    rr = 0;
    b = ReadConsoleInput (console, buf, buffer_size, &rr);
    if (FALSE == b && ERROR_SUCCESS != GetLastError ())
      break;
    for (i = 0; i < rr; i++)
    {
      int r;
      r = write_message (output_stream,
                         GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_INPUT,
                         (const char *) &buf[i],
                         sizeof (INPUT_RECORD));
      if (GNUNET_OK != r)
        break;
    }
    if (rr + 1 != i)
      break;
  }
  return result;
}


/**
 * Main function of the helper process. Reads chars from console,
 * writes messages, into stdout.
 *
 * @param console a handle to a console to read from
 * @param output_stream a stream to write messages to
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
read_chars (HANDLE console, int output_stream)
{
  DWORD rr;
  BOOL b;
  wchar_t *buf;
  char *small_ubuf;
  char *large_ubuf;
  char *ubuf;
  int conv;
  int r;
  int result;

  result = GNUNET_SYSERR;
  buf = malloc (sizeof (wchar_t) * buffer_size);
  if (NULL == buf)
    return result;
  small_ubuf = malloc (sizeof (char) * buffer_size * 2);
  if (NULL == small_ubuf)
  {
    free (buf);
    return result;
  }
  b = TRUE;
  rr = 1;
  while (TRUE == b)
  {
    large_ubuf = NULL;
    rr = 0;
    b = ReadConsoleW (console, buf, buffer_size, &rr, NULL);
    if (FALSE == b && ERROR_SUCCESS != GetLastError ())
      break;
    if (0 == rr)
      continue;
    /* Caveat: if the UTF-16-encoded string is longer than BUFFER_SIZE,
     * there's a possibility that we will read up to a word that constitutes
     * a part of a multi-byte UTF-16 codepoint. Converting that to UTF-8
     * will either drop invalid word (flags == 0) or bail out because of it
     * (flags == WC_ERR_INVALID_CHARS).
     */
    conv = WideCharToMultiByte (CP_UTF8, 0, buf, rr, small_ubuf, 0, NULL, FALSE);
    if (0 == conv || 0xFFFD == conv)
      continue;
    if (conv <= buffer_size * 2 - 1)
    {
      memset (small_ubuf, 0, buffer_size * 2);
      conv = WideCharToMultiByte (CP_UTF8, 0, buf, rr, small_ubuf, buffer_size * 2 - 1, NULL, FALSE);
      if (0 == conv || 0xFFFD == conv)
        continue;
      ubuf = small_ubuf;
    }
    else
    {
      large_ubuf = malloc (conv + 1);
      if (NULL == large_ubuf)
        continue;
      memset (large_ubuf, 0, conv + 1);
      conv = WideCharToMultiByte (CP_UTF8, 0, buf, rr, large_ubuf, conv, NULL, FALSE);
      if (0 == conv || 0xFFFD == conv)
      {
        free (large_ubuf);
        large_ubuf = NULL;
        continue;
      }
      ubuf = large_ubuf;
    }
    r = write_message (output_stream,
                       GNUNET_MESSAGE_TYPE_W32_CONSOLE_HELPER_CHARS,
                       ubuf,
                       conv + 1);
    if (large_ubuf)
      free (large_ubuf);
    if (GNUNET_OK != r)
      break;
  }
  free (small_ubuf);
  free (buf);
  return result;
}


DWORD WINAPI
watch_parent (LPVOID param)
{
  WaitForSingleObject (parent_handle, INFINITE);
  ExitProcess (1);
  return 0;
}

/**
 * Main function of the helper process to extract meta data.
 *
 * @param argc should be 3
 * @param argv [0] our binary name
 *             [1] name of the file or directory to process
 *             [2] "-" to disable extraction, NULL for defaults,
 *                 otherwise custom plugins to load from LE
 * @return 0 on success
 */
int
main (int argc,
      char *const *argv)
{
  HANDLE os_stdin;
  DWORD parent_pid;
  /* We're using stdout to communicate binary data back to the parent; use
   * binary mode.
   */
  _setmode (1, _O_BINARY);

  if (argc != 4)
  {
    fprintf (stderr,
        "Usage: gnunet-helper-w32-console <chars|events> <buffer size> <parent pid>\n");
    return 2;
  }

  if (0 == strcmp (argv[1], "chars"))
    chars = GNUNET_YES;
  else if (0 == strcmp (argv[1], "events"))
    chars = GNUNET_NO;
  else
    return 3;

  buffer_size = strtoul (argv[2], NULL, 10);
  if (buffer_size <= 0)
    return 4;

  parent_pid = (DWORD) strtoul (argv[3], NULL, 10);
  if (parent_pid == 0)
    return 5;
  parent_handle = OpenProcess (SYNCHRONIZE, FALSE, parent_pid);
  if (NULL == parent_handle)
    return 6;

  CreateThread (NULL, 0, watch_parent, NULL, 0, NULL);

  if (0 == AttachConsole (ATTACH_PARENT_PROCESS))
  {
    if (ERROR_ACCESS_DENIED != GetLastError ())
      return 5;
  }

  /* Helper API overrides stdin, so we just attach to the console that we
   * inherited. If we did.
   */
  os_stdin = CreateFile ("CONIN$", GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
  if (INVALID_HANDLE_VALUE == os_stdin)
    return 1;

  if (GNUNET_NO == chars)
    return read_events (os_stdin, 1);
  else
    return read_chars (os_stdin, 1);

}

/* end of gnunet-helper-w32-console.c */

/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * Common buffer management functions.
 *
 * @author Florian Dold
 */

#ifndef GNUNET_BUFFER_LIB_H
#define GNUNET_BUFFER_LIB_H

/**
 * Dynamically growing buffer.  Can be used to construct
 * strings and other objects with dynamic size.
 *
 * This structure should, in most cases, be stack-allocated and
 * zero-initialized, like:
 *
 *   struct GNUNET_Buffer my_buffer = { 0 };
 */
struct GNUNET_Buffer
{
  /**
   * Capacity of the buffer.
   */
  size_t capacity;

  /**
   * Current write position.
   */
  size_t position;

  /**
   * Backing memory.
   */
  char *mem;

  /**
   * Log a warning if the buffer is grown over its initially allocated capacity.
   */
  int warn_grow;
};


/**
 * Initialize a buffer with the given capacity.
 *
 * When a buffer is allocated with this function, a warning is logged
 * when the buffer exceeds the initial capacity.
 *
 * @param buf the buffer to initialize
 * @param capacity the capacity (in bytes) to allocate for @a buf
 */
void
GNUNET_buffer_prealloc (struct GNUNET_Buffer *buf, size_t capacity);


/**
 * Make sure that at least @a n bytes remaining in the buffer.
 *
 * @param buf buffer to potentially grow
 * @param n number of bytes that should be available to write
 */
void
GNUNET_buffer_ensure_remaining (struct GNUNET_Buffer *buf, size_t n);


/**
 * Write bytes to the buffer.
 *
 * Grows the buffer if necessary.
 *
 * @param buf buffer to write to
 * @param data data to read from
 * @param len number of bytes to copy from @a data to @a buf
 *
 */
void
GNUNET_buffer_write (struct GNUNET_Buffer *buf, const char *data, size_t len);


/**
 * Write a 0-terminated string to a buffer, excluding the 0-terminator.
 *
 * Grows the buffer if necessary.
 *
 * @param buf the buffer to write to
 * @param str the string to write to @a buf
 */
void
GNUNET_buffer_write_str (struct GNUNET_Buffer *buf, const char *str);


/**
 * Write a path component to a buffer, ensuring that
 * there is exactly one slash between the previous contents
 * of the buffer and the new string.
 *
 * @param buf buffer to write to
 * @param str string containing the new path component
 */
void
GNUNET_buffer_write_path (struct GNUNET_Buffer *buf, const char *str);


/**
 * Write a 0-terminated formatted string to a buffer, excluding the
 * 0-terminator.
 *
 * Grows the buffer if necessary.
 *
 * @param buf the buffer to write to
 * @param fmt format string
 * @param ... format arguments
 */
void
GNUNET_buffer_write_fstr (struct GNUNET_Buffer *buf, const char *fmt, ...);


/**
 * Write a 0-terminated formatted string to a buffer, excluding the
 * 0-terminator.
 *
 * Grows the buffer if necessary.
 *
 * @param buf the buffer to write to
 * @param fmt format string
 * @param args format argument list
 */
void
GNUNET_buffer_write_vfstr (struct GNUNET_Buffer *buf, const char *fmt, va_list
                          args);


/**
 * Clear the buffer and return the string it contained.
 * The caller is responsible to eventually #GNUNET_free
 * the returned string.
 *
 * The returned string is always 0-terminated.
 *
 * @param buf the buffer to reap the string from
 * @returns the buffer contained in the string
 */
char *
GNUNET_buffer_reap_str (struct GNUNET_Buffer *buf);


/**
 * Clear the buffer and return its contents.
 * The caller is responsible to eventually #GNUNET_free
 * the returned data.
 *
 * @param buf the buffer to reap the contents from
 * @param size where to store the size of the returned data
 * @returns the data contained in the string
 */
void *
GNUNET_buffer_reap (struct GNUNET_Buffer *buf, size_t *size);


/**
 * Free the backing memory of the given buffer.
 * Does not free the memory of the buffer control structure,
 * which is typically stack-allocated.
 */
void
GNUNET_buffer_clear (struct GNUNET_Buffer *buf);


#endif

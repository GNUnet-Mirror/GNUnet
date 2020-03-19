/*
     This file is part of GNUnet.
     Copyright (C) 2005-2017 GNUnet e.V.

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
 * @file util/strings.c
 * @brief string functions
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "platform.h"
#if HAVE_ICONV
#include <iconv.h>
#endif
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"
#include <unicase.h>
#include <unistr.h>
#include <uniconv.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-strings", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
  GNUNET_log_from_strerror (kind, "util-strings", syscall)


/**
 * Fill a buffer of the given size with
 * count 0-terminated strings (given as varargs).
 * If "buffer" is NULL, only compute the amount of
 * space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function
 * will add 0-terminators after each string.  The
 * #GNUNET_string_buffer_tokenize() function can be
 * used to parse the buffer back into individual
 * strings.
 *
 * @param buffer the buffer to fill with strings, can
 *               be NULL in which case only the necessary
 *               amount of space will be calculated
 * @param size number of bytes available in buffer
 * @param count number of strings that follow
 * @param ... count 0-terminated strings to copy to buffer
 * @return number of bytes written to the buffer
 *         (or number of bytes that would have been written)
 */
size_t
GNUNET_STRINGS_buffer_fill (char *buffer, size_t size, unsigned int count, ...)
{
  size_t needed;
  size_t slen;
  const char *s;
  va_list ap;

  needed = 0;
  va_start (ap, count);
  while (count > 0)
  {
    s = va_arg (ap, const char *);

    slen = strlen (s) + 1;
    if (buffer != NULL)
    {
      GNUNET_assert (needed + slen <= size);
      GNUNET_memcpy (&buffer[needed], s, slen);
    }
    needed += slen;
    count--;
  }
  va_end (ap);
  return needed;
}


/**
 * Convert a peer path to a human-readable string.
 *
 * @param pids array of PIDs to convert to a string
 * @param num_pids length of the @a pids array
 * @return string representing the array of @a pids
 */
char *
GNUNET_STRINGS_pp2s (const struct GNUNET_PeerIdentity *pids,
                     unsigned int num_pids)
{
  char *buf;
  size_t off;
  size_t plen = num_pids * 5 + 1;

  off = 0;
  buf = GNUNET_malloc (plen);
  for (unsigned int i = 0; i < num_pids; i++)
  {
    off += GNUNET_snprintf (&buf[off],
                            plen - off,
                            "%s%s",
                            GNUNET_i2s (&pids[i]),
                            (i == num_pids - 1) ? "" : "-");
  }
  return buf;
}


/**
 * Given a buffer of a given size, find "count"
 * 0-terminated strings in the buffer and assign
 * the count (varargs) of type "const char**" to the
 * locations of the respective strings in the
 * buffer.
 *
 * @param buffer the buffer to parse
 * @param size size of the buffer
 * @param count number of strings to locate
 * @return offset of the character after the last 0-termination
 *         in the buffer, or 0 on error.
 */
unsigned int
GNUNET_STRINGS_buffer_tokenize (const char *buffer,
                                size_t size,
                                unsigned int count,
                                ...)
{
  unsigned int start;
  unsigned int needed;
  const char **r;
  va_list ap;

  needed = 0;
  va_start (ap, count);
  while (count > 0)
  {
    r = va_arg (ap, const char **);

    start = needed;
    while ((needed < size) && (buffer[needed] != '\0'))
      needed++;
    if (needed == size)
    {
      va_end (ap);
      return 0;     /* error */
    }
    *r = &buffer[start];
    needed++;   /* skip 0-termination */
    count--;
  }
  va_end (ap);
  return needed;
}


/**
 * Convert a given filesize into a fancy human-readable format.
 *
 * @param size number of bytes
 * @return fancy representation of the size (possibly rounded) for humans
 */
char *
GNUNET_STRINGS_byte_size_fancy (unsigned long long size)
{
  const char *unit = _ (/* size unit */ "b");
  char *ret;

  if (size > 5 * 1024)
  {
    size = size / 1024;
    unit = "KiB";
    if (size > 5 * 1024)
    {
      size = size / 1024;
      unit = "MiB";
      if (size > 5 * 1024)
      {
        size = size / 1024;
        unit = "GiB";
        if (size > 5 * 1024)
        {
          size = size / 1024;
          unit = "TiB";
        }
      }
    }
  }
  ret = GNUNET_malloc (32);
  GNUNET_snprintf (ret, 32, "%llu %s", size, unit);
  return ret;
}


/**
 * Like strlcpy but portable. The given string @a src is copied until its null
 * byte or until @a n - 1 bytes have been read. The destination buffer is
 * guaranteed to be null-terminated.
 *
 * @param dst destination of the copy (must be @a n bytes long)
 * @param src source of the copy (at most @a n - 1 bytes will be read)
 * @param n the length of the string to copy, including its terminating null
 *          byte
 * @return the length of the string that was copied, excluding the terminating
 *         null byte
 */
size_t
GNUNET_strlcpy (char *dst, const char *src, size_t n)
{
  size_t slen;

  GNUNET_assert (0 != n);
  slen = strnlen (src, n - 1);
  memcpy (dst, src, slen);
  dst[slen] = '\0';
  return slen;
}


/**
 * Unit conversion table entry for 'convert_with_table'.
 */
struct ConversionTable
{
  /**
   * Name of the unit (or NULL for end of table).
   */
  const char *name;

  /**
   * Factor to apply for this unit.
   */
  unsigned long long value;
};


/**
 * Convert a string of the form "4 X 5 Y" into a numeric value
 * by interpreting "X" and "Y" as units and then multiplying
 * the numbers with the values associated with the respective
 * unit from the conversion table.
 *
 * @param input input string to parse
 * @param table table with the conversion of unit names to numbers
 * @param output where to store the result
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
convert_with_table (const char *input,
                    const struct ConversionTable *table,
                    unsigned long long *output)
{
  unsigned long long ret;
  char *in;
  const char *tok;
  unsigned long long last;
  unsigned int i;
  char *sptr;

  ret = 0;
  last = 0;
  in = GNUNET_strdup (input);
  for (tok = strtok_r (in, " ", &sptr);
       tok != NULL;
       tok = strtok_r (NULL, " ", &sptr))
  {
    do
    {
      i = 0;
      while ((table[i].name != NULL) && (0 != strcasecmp (table[i].name, tok)))
        i++;
      if (table[i].name != NULL)
      {
        last *= table[i].value;
        break;       /* next tok */
      }
      else
      {
        char *endptr;
        ret += last;
        errno = 0;
        last = strtoull (tok, &endptr, 10);
        if ((0 != errno) || (endptr == tok))
        {
          GNUNET_free (in);
          return GNUNET_SYSERR;         /* expected number */
        }
        if ('\0' == endptr[0])
          break;       /* next tok */
        else
          tok = endptr;       /* and re-check (handles times like "10s") */
      }
    }
    while (GNUNET_YES);
  }
  ret += last;
  *output = ret;
  GNUNET_free (in);
  return GNUNET_OK;
}


/**
 * Convert a given fancy human-readable size to bytes.
 *
 * @param fancy_size human readable string (i.e. 1 MB)
 * @param size set to the size in bytes
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_size_to_bytes (const char *fancy_size,
                                    unsigned long long *size)
{
  static const struct ConversionTable table[] =
  { { "B", 1 },
    { "KiB", 1024 },
    { "kB", 1000 },
    { "MiB", 1024 * 1024 },
    { "MB", 1000 * 1000 },
    { "GiB", 1024 * 1024 * 1024 },
    { "GB", 1000 * 1000 * 1000 },
    { "TiB", 1024LL * 1024LL * 1024LL * 1024LL },
    { "TB", 1000LL * 1000LL * 1000LL * 1024LL },
    { "PiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL },
    { "PB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL },
    { "EiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL * 1024LL },
    { "EB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL * 1000LL },
    { NULL, 0 } };

  return convert_with_table (fancy_size, table, size);
}


/**
 * Convert a given fancy human-readable time to our internal
 * representation.
 *
 * @param fancy_time human readable string (i.e. 1 minute)
 * @param rtime set to the relative time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_time_to_relative (const char *fancy_time,
                                       struct GNUNET_TIME_Relative *rtime)
{
  static const struct ConversionTable table[] =
  { { "us", 1 },
    { "ms", 1000 },
    { "s", 1000 * 1000LL },
    { "second", 1000 * 1000LL },
    { "seconds", 1000 * 1000LL },
    { "\"", 1000 * 1000LL },
    { "m", 60 * 1000 * 1000LL },
    { "min", 60 * 1000 * 1000LL },
    { "minute", 60 * 1000 * 1000LL },
    { "minutes", 60 * 1000 * 1000LL },
    { "'", 60 * 1000 * 1000LL },
    { "h", 60 * 60 * 1000 * 1000LL },
    { "hour", 60 * 60 * 1000 * 1000LL },
    { "hours", 60 * 60 * 1000 * 1000LL },
    { "d", 24 * 60 * 60 * 1000LL * 1000LL },
    { "day", 24 * 60 * 60 * 1000LL * 1000LL },
    { "days", 24 * 60 * 60 * 1000LL * 1000LL },
    { "week", 7 * 24 * 60 * 60 * 1000LL * 1000LL },
    { "weeks", 7 * 24 * 60 * 60 * 1000LL * 1000LL },
    { "year", 31536000000000LL /* year */ },
    { "years", 31536000000000LL /* year */ },
    { "a", 31536000000000LL /* year */ },
    { NULL, 0 } };
  int ret;
  unsigned long long val;

  if (0 == strcasecmp ("forever", fancy_time))
  {
    *rtime = GNUNET_TIME_UNIT_FOREVER_REL;
    return GNUNET_OK;
  }
  ret = convert_with_table (fancy_time, table, &val);
  rtime->rel_value_us = (uint64_t) val;
  return ret;
}


/**
 * Convert a given fancy human-readable time to our internal
 * representation. The human-readable time is expected to be
 * in local time, whereas the returned value will be in UTC.
 *
 * @param fancy_time human readable string (i.e. %Y-%m-%d %H:%M:%S)
 * @param atime set to the absolute time
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_time_to_absolute (const char *fancy_time,
                                       struct GNUNET_TIME_Absolute *atime)
{
  struct tm tv;
  time_t t;
  const char *eos;

  if (0 == strcasecmp ("end of time", fancy_time))
  {
    *atime = GNUNET_TIME_UNIT_FOREVER_ABS;
    return GNUNET_OK;
  }
  eos = &fancy_time[strlen (fancy_time)];
  memset (&tv, 0, sizeof(tv));
  if ((eos != strptime (fancy_time, "%a %b %d %H:%M:%S %Y", &tv)) &&
      (eos != strptime (fancy_time, "%c", &tv)) &&
      (eos != strptime (fancy_time, "%Ec", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m-%d %H:%M:%S", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m-%d %H:%M", &tv)) &&
      (eos != strptime (fancy_time, "%x", &tv)) &&
      (eos != strptime (fancy_time, "%Ex", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m-%d", &tv)) &&
      (eos != strptime (fancy_time, "%Y-%m", &tv)) &&
      (eos != strptime (fancy_time, "%Y", &tv)))
    return GNUNET_SYSERR;
  t = mktime (&tv);
  atime->abs_value_us = (uint64_t) ((uint64_t) t * 1000LL * 1000LL);
  return GNUNET_OK;
}


/**
 * Convert the len characters long character sequence
 * given in input that is in the given input charset
 * to a string in given output charset.
 *
 * @param input input string
 * @param len number of bytes in @a input
 * @param input_charset character set used for @a input
 * @param output_charset desired character set for the return value
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
GNUNET_STRINGS_conv (const char *input,
                     size_t len,
                     const char *input_charset,
                     const char *output_charset)
{
  char *ret;
  uint8_t *u8_string;
  char *encoded_string;
  size_t u8_string_length;
  size_t encoded_string_length;

  u8_string = u8_conv_from_encoding (input_charset,
                                     iconveh_error,
                                     input,
                                     len,
                                     NULL,
                                     NULL,
                                     &u8_string_length);
  if (NULL == u8_string)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "u8_conv_from_encoding");
    goto fail;
  }
  if (0 == strcmp (output_charset, "UTF-8"))
  {
    ret = GNUNET_malloc (u8_string_length + 1);
    GNUNET_memcpy (ret, u8_string, u8_string_length);
    ret[u8_string_length] = '\0';
    free (u8_string);
    return ret;
  }
  encoded_string = u8_conv_to_encoding (output_charset,
                                        iconveh_error,
                                        u8_string,
                                        u8_string_length,
                                        NULL,
                                        NULL,
                                        &encoded_string_length);
  free (u8_string);
  if (NULL == encoded_string)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "u8_conv_to_encoding");
    goto fail;
  }
  ret = GNUNET_malloc (encoded_string_length + 1);
  GNUNET_memcpy (ret, encoded_string, encoded_string_length);
  ret[encoded_string_length] = '\0';
  free (encoded_string);
  return ret;
fail:
  LOG (GNUNET_ERROR_TYPE_WARNING,
       _ ("Character sets requested were `%s'->`%s'\n"),
       "UTF-8",
       output_charset);
  ret = GNUNET_malloc (len + 1);
  GNUNET_memcpy (ret, input, len);
  ret[len] = '\0';
  return ret;
}


/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 *
 * @param input the input string (not necessarily 0-terminated)
 * @param len the number of bytes in the @a input
 * @param charset character set to convert from
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
GNUNET_STRINGS_to_utf8 (const char *input, size_t len, const char *charset)
{
  return GNUNET_STRINGS_conv (input, len, charset, "UTF-8");
}


/**
 * Convert the len bytes-long UTF-8 string
 * given in input to the given charset.
 *
 * @param input the input string (not necessarily 0-terminated)
 * @param len the number of bytes in the @a input
 * @param charset character set to convert to
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
GNUNET_STRINGS_from_utf8 (const char *input, size_t len, const char *charset)
{
  return GNUNET_STRINGS_conv (input, len, "UTF-8", charset);
}


/**
 * Convert the utf-8 input string to lowercase.
 * Output needs to be allocated appropriately.
 *
 * @param input input string
 * @param output output buffer
 */
void
GNUNET_STRINGS_utf8_tolower (const char *input, char *output)
{
  uint8_t *tmp_in;
  size_t len;

  tmp_in = u8_tolower ((uint8_t *) input,
                       strlen ((char *) input),
                       NULL,
                       UNINORM_NFD,
                       NULL,
                       &len);
  GNUNET_memcpy (output, tmp_in, len);
  output[len] = '\0';
  free (tmp_in);
}


/**
 * Convert the utf-8 input string to uppercase.
 * Output needs to be allocated appropriately.
 *
 * @param input input string
 * @param output output buffer
 */
void
GNUNET_STRINGS_utf8_toupper (const char *input, char *output)
{
  uint8_t *tmp_in;
  size_t len;

  tmp_in = u8_toupper ((uint8_t *) input,
                       strlen ((char *) input),
                       NULL,
                       UNINORM_NFD,
                       NULL,
                       &len);
  GNUNET_memcpy (output, tmp_in, len);
  output[len] = '\0';
  free (tmp_in);
}


/**
 * Complete filename (a la shell) from abbrevition.
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char *
GNUNET_STRINGS_filename_expand (const char *fil)
{
  char *buffer;
  size_t len;
  char *fm;
  const char *fil_ptr;

  if (fil == NULL)
    return NULL;

  if (fil[0] == DIR_SEPARATOR)
    /* absolute path, just copy */
    return GNUNET_strdup (fil);
  if (fil[0] == '~')
  {
    fm = getenv ("HOME");
    if (fm == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _ ("Failed to expand `$HOME': environment variable `HOME' not set"));
      return NULL;
    }
    fm = GNUNET_strdup (fm);
    /* do not copy '~' */
    fil_ptr = fil + 1;

    /* skip over dir seperator to be consistent */
    if (fil_ptr[0] == DIR_SEPARATOR)
      fil_ptr++;
  }
  else
  {
    /* relative path */
    fil_ptr = fil;
    len = 512;
    fm = NULL;
    while (1)
    {
      buffer = GNUNET_malloc (len);
      if (getcwd (buffer, len) != NULL)
      {
        fm = buffer;
        break;
      }
      if ((errno == ERANGE) && (len < 1024 * 1024 * 4))
      {
        len *= 2;
        GNUNET_free (buffer);
        continue;
      }
      GNUNET_free (buffer);
      break;
    }
    if (fm == NULL)
    {
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "getcwd");
      buffer = getenv ("PWD");    /* alternative */
      if (buffer != NULL)
        fm = GNUNET_strdup (buffer);
    }
    if (fm == NULL)
      fm = GNUNET_strdup ("./");  /* give up */
  }
  GNUNET_asprintf (&buffer,
                   "%s%s%s",
                   fm,
                   (fm[strlen (fm) - 1] == DIR_SEPARATOR) ? ""
                   : DIR_SEPARATOR_STR,
                   fil_ptr);
  GNUNET_free (fm);
  return buffer;
}


/**
 * Give relative time in human-readable fancy format.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param delta time in milli seconds
 * @param do_round are we allowed to round a bit?
 * @return time as human-readable string
 */
const char *
GNUNET_STRINGS_relative_time_to_string (struct GNUNET_TIME_Relative delta,
                                        int do_round)
{
  static char buf[128];
  const char *unit = _ (/* time unit */ "µs");
  uint64_t dval = delta.rel_value_us;

  if (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == delta.rel_value_us)
    return _ ("forever");
  if (0 == delta.rel_value_us)
    return _ ("0 ms");
  if (((GNUNET_YES == do_round) && (dval > 5 * 1000)) || (0 == (dval % 1000)))
  {
    dval = dval / 1000;
    unit = _ (/* time unit */ "ms");
    if (((GNUNET_YES == do_round) && (dval > 5 * 1000)) || (0 == (dval % 1000)))
    {
      dval = dval / 1000;
      unit = _ (/* time unit */ "s");
      if (((GNUNET_YES == do_round) && (dval > 5 * 60)) || (0 == (dval % 60)))
      {
        dval = dval / 60;
        unit = _ (/* time unit */ "m");
        if (((GNUNET_YES == do_round) && (dval > 5 * 60)) || (0 == (dval % 60)))
        {
          dval = dval / 60;
          unit = _ (/* time unit */ "h");
          if (((GNUNET_YES == do_round) && (dval > 5 * 24)) ||
              (0 == (dval % 24)))
          {
            dval = dval / 24;
            if (1 == dval)
              unit = _ (/* time unit */ "day");
            else
              unit = _ (/* time unit */ "days");
          }
        }
      }
    }
  }
  GNUNET_snprintf (buf, sizeof(buf), "%llu %s", dval, unit);
  return buf;
}


/**
 * "asctime", except for GNUnet time.  Converts a GNUnet internal
 * absolute time (which is in UTC) to a string in local time.
 * Note that the returned value will be overwritten if this function
 * is called again.
 *
 * @param t the absolute time to convert
 * @return timestamp in human-readable form in local time
 */
const char *
GNUNET_STRINGS_absolute_time_to_string (struct GNUNET_TIME_Absolute t)
{
  static char buf[255];
  time_t tt;
  struct tm *tp;

  if (t.abs_value_us == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
    return _ ("end of time");
  tt = t.abs_value_us / 1000LL / 1000LL;
  tp = localtime (&tt);
  /* This is hacky, but i don't know a way to detect libc character encoding.
   * Just expect utf8 from glibc these days.
   * As for msvcrt, use the wide variant, which always returns utf16
   * (otherwise we'd have to detect current codepage or use W32API character
   * set conversion routines to convert to UTF8).
   */strftime (buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", tp);

  return buf;
}


/**
 * "man basename"
 * Returns a pointer to a part of filename (allocates nothing)!
 *
 * @param filename filename to extract basename from
 * @return short (base) name of the file (that is, everything following the
 *         last directory separator in filename. If filename ends with a
 *         directory separator, the result will be a zero-length string.
 *         If filename has no directory separators, the result is filename
 *         itself.
 */
const char *
GNUNET_STRINGS_get_short_name (const char *filename)
{
  const char *short_fn = filename;
  const char *ss;

  while (NULL != (ss = strstr (short_fn, DIR_SEPARATOR_STR)) && (ss[1] != '\0'))
    short_fn = 1 + ss;
  return short_fn;
}


/**
 * Get the decoded value corresponding to a character according to Crockford
 * Base32 encoding.
 *
 * @param a a character
 * @return corresponding numeric value
 */
static unsigned int
getValue__ (unsigned char a)
{
  unsigned int dec;

  switch (a)
  {
  case 'O':
  case 'o':
    a = '0';
    break;

  case 'i':
  case 'I':
  case 'l':
  case 'L':
    a = '1';
    break;

  /* also consider U to be V */
  case 'u':
  case 'U':
    a = 'V';
    break;

  default:
    break;
  }
  if ((a >= '0') && (a <= '9'))
    return a - '0';
  if ((a >= 'a') && (a <= 'z'))
    a = toupper (a);
  /* return (a - 'a' + 10); */
  dec = 0;
  if ((a >= 'A') && (a <= 'Z'))
  {
    if ('I' < a)
      dec++;
    if ('L' < a)
      dec++;
    if ('O' < a)
      dec++;
    if ('U' < a)
      dec++;
    return(a - 'A' + 10 - dec);
  }
  return -1;
}


/**
 * Convert binary data to ASCII encoding using Crockford Base32 encoding.
 * Returns a pointer to the byte after the last byte in the string, that
 * is where the 0-terminator was placed if there was room.
 *
 * @param data data to encode
 * @param size size of data (in bytes)
 * @param out buffer to fill
 * @param out_size size of the buffer. Must be large enough to hold
 * (size * 8 + 4) / 5 bytes
 * @return pointer to the next byte in @a out or NULL on error.
 */
char *
GNUNET_STRINGS_data_to_string (const void *data,
                               size_t size,
                               char *out,
                               size_t out_size)
{
  /**
   * 32 characters for encoding
   */
  static char *encTable__ = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;
  const unsigned char *udata;

  udata = data;
  if (out_size < (size * 8 + 4) / 5)
  {
    GNUNET_break (0);
    return NULL;
  }
  vbit = 0;
  wpos = 0;
  rpos = 0;
  bits = 0;
  while ((rpos < size) || (vbit > 0))
  {
    if ((rpos < size) && (vbit < 5))
    {
      bits = (bits << 8) | udata[rpos++];     /* eat 8 more bits */
      vbit += 8;
    }
    if (vbit < 5)
    {
      bits <<= (5 - vbit);     /* zero-padding */
      GNUNET_assert (vbit == ((size * 8) % 5));
      vbit = 5;
    }
    if (wpos >= out_size)
    {
      GNUNET_break (0);
      return NULL;
    }
    out[wpos++] = encTable__[(bits >> (vbit - 5)) & 31];
    vbit -= 5;
  }
  GNUNET_assert (0 == vbit);
  if (wpos < out_size)
    out[wpos] = '\0';
  return &out[wpos];
}


/**
 * Return the base32crockford encoding of the given buffer.
 *
 * The returned string will be freshly allocated, and must be free'd
 * with GNUNET_free().
 *
 * @param buffer with data
 * @param size size of the buffer
 * @return freshly allocated, null-terminated string
 */
char *
GNUNET_STRINGS_data_to_string_alloc (const void *buf, size_t size)
{
  char *str_buf;
  size_t len = size * 8;
  char *end;

  if (len % 5 > 0)
    len += 5 - len % 5;
  len /= 5;
  str_buf = GNUNET_malloc (len + 1);
  end = GNUNET_STRINGS_data_to_string (buf, size, str_buf, len);
  if (NULL == end)
  {
    GNUNET_free (str_buf);
    return NULL;
  }
  *end = '\0';
  return str_buf;
}


/**
 * Convert Crockford Base32hex encoding back to data.
 * @a out_size must match exactly the size of the data before it was encoded.
 *
 * @param enc the encoding
 * @param enclen number of characters in @a enc (without 0-terminator, which can be missing)
 * @param out location where to store the decoded data
 * @param out_size size of the output buffer @a out
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_STRINGS_string_to_data (const char *enc,
                               size_t enclen,
                               void *out,
                               size_t out_size)
{
  unsigned int rpos;
  unsigned int wpos;
  unsigned int bits;
  unsigned int vbit;
  int ret;
  int shift;
  unsigned char *uout;
  unsigned int encoded_len = out_size * 8;

  if (0 == enclen)
  {
    if (0 == out_size)
      return GNUNET_OK;
    return GNUNET_SYSERR;
  }
  uout = out;
  wpos = out_size;
  rpos = enclen;
  if ((encoded_len % 5) > 0)
  {
    vbit = encoded_len % 5;   /* padding! */
    shift = 5 - vbit;
    bits = (ret = getValue__ (enc[--rpos])) >> shift;
  }
  else
  {
    vbit = 5;
    shift = 0;
    bits = (ret = getValue__ (enc[--rpos]));
  }
  if ((encoded_len + shift) / 5 != enclen)
    return GNUNET_SYSERR;
  if (-1 == ret)
    return GNUNET_SYSERR;
  while (wpos > 0)
  {
    if (0 == rpos)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    bits = ((ret = getValue__ (enc[--rpos])) << vbit) | bits;
    if (-1 == ret)
      return GNUNET_SYSERR;
    vbit += 5;
    if (vbit >= 8)
    {
      uout[--wpos] = (unsigned char) bits;
      bits >>= 8;
      vbit -= 8;
    }
  }
  if ((0 != rpos) || (0 != vbit))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Parse a path that might be an URI.
 *
 * @param path path to parse. Must be NULL-terminated.
 * @param scheme_part a pointer to 'char *' where a pointer to a string that
 *        represents the URI scheme will be stored. Can be NULL. The string is
 *        allocated by the function, and should be freed by GNUNET_free() when
 *        it is no longer needed.
 * @param path_part a pointer to 'const char *' where a pointer to the path
 *        part of the URI will be stored. Can be NULL. Points to the same block
 *        of memory as 'path', and thus must not be freed. Might point to '\0',
 *        if path part is zero-length.
 * @return GNUNET_YES if it's an URI, GNUNET_NO otherwise. If 'path' is not
 *         an URI, '* scheme_part' and '*path_part' will remain unchanged
 *         (if they weren't NULL).
 */
int
GNUNET_STRINGS_parse_uri (const char *path,
                          char **scheme_part,
                          const char **path_part)
{
  size_t len;
  size_t i;
  int end;
  int pp_state = 0;
  const char *post_scheme_part = NULL;

  len = strlen (path);
  for (end = 0, i = 0; ! end && i < len; i++)
  {
    switch (pp_state)
    {
    case 0:
      if ((path[i] == ':') && (i > 0))
      {
        pp_state += 1;
        continue;
      }
      if (! (((path[i] >= 'A') && (path[i] <= 'Z') ) ||
             ((path[i] >= 'a') && (path[i] <= 'z') ) ||
             ((path[i] >= '0') && (path[i] <= '9') ) || (path[i] == '+') ||
             (path[i] == '-') || (path[i] == '.')))
        end = 1;
      break;

    case 1:
    case 2:
      if (path[i] == '/')
      {
        pp_state += 1;
        continue;
      }
      end = 1;
      break;

    case 3:
      post_scheme_part = &path[i];
      end = 1;
      break;

    default:
      end = 1;
    }
  }
  if (post_scheme_part == NULL)
    return GNUNET_NO;
  if (scheme_part)
  {
    *scheme_part = GNUNET_malloc (post_scheme_part - path + 1);
    GNUNET_memcpy (*scheme_part, path, post_scheme_part - path);
    (*scheme_part)[post_scheme_part - path] = '\0';
  }
  if (path_part)
    *path_part = post_scheme_part;
  return GNUNET_YES;
}


/**
 * Check whether @a filename is absolute or not, and if it's an URI
 *
 * @param filename filename to check
 * @param can_be_uri #GNUNET_YES to check for being URI, #GNUNET_NO - to
 *        assume it's not URI
 * @param r_is_uri a pointer to an int that is set to #GNUNET_YES if @a filename
 *        is URI and to #GNUNET_NO otherwise. Can be NULL. If @a can_be_uri is
 *        not #GNUNET_YES, `* r_is_uri` is set to #GNUNET_NO.
 * @param r_uri_scheme a pointer to a char * that is set to a pointer to URI scheme.
 *        The string is allocated by the function, and should be freed with
 *        GNUNET_free(). Can be NULL.
 * @return #GNUNET_YES if @a filename is absolute, #GNUNET_NO otherwise.
 */
int
GNUNET_STRINGS_path_is_absolute (const char *filename,
                                 int can_be_uri,
                                 int *r_is_uri,
                                 char **r_uri_scheme)
{
  const char *post_scheme_path;
  int is_uri;
  char *uri;
  /* consider POSIX paths to be absolute too, even on W32,
   * as plibc expansion will fix them for us.
   */
  if (filename[0] == '/')
    return GNUNET_YES;
  if (can_be_uri)
  {
    is_uri = GNUNET_STRINGS_parse_uri (filename, &uri, &post_scheme_path);
    if (r_is_uri)
      *r_is_uri = is_uri;
    if (is_uri)
    {
      if (r_uri_scheme)
        *r_uri_scheme = uri;
      else
        GNUNET_free_non_null (uri);

      return GNUNET_STRINGS_path_is_absolute (post_scheme_path,
                                              GNUNET_NO,
                                              NULL,
                                              NULL);
    }
  }
  else
  {
    if (r_is_uri)
      *r_is_uri = GNUNET_NO;
  }

  return GNUNET_NO;
}


/**
 * Perform @a checks on @a filename.
 *
 * @param filename file to check
 * @param checks checks to perform
 * @return #GNUNET_YES if all checks pass, #GNUNET_NO if at least one of them
 *         fails, #GNUNET_SYSERR when a check can't be performed
 */
int
GNUNET_STRINGS_check_filename (const char *filename,
                               enum GNUNET_STRINGS_FilenameCheck checks)
{
  struct stat st;

  if ((NULL == filename) || (filename[0] == '\0'))
    return GNUNET_SYSERR;
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_ABSOLUTE))
    if (! GNUNET_STRINGS_path_is_absolute (filename, GNUNET_NO, NULL, NULL))
      return GNUNET_NO;
  if (0 != (checks
            & (GNUNET_STRINGS_CHECK_EXISTS | GNUNET_STRINGS_CHECK_IS_DIRECTORY
               | GNUNET_STRINGS_CHECK_IS_LINK)))
  {
    if (0 != stat (filename, &st))
    {
      if (0 != (checks & GNUNET_STRINGS_CHECK_EXISTS))
        return GNUNET_NO;
      else
        return GNUNET_SYSERR;
    }
  }
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_DIRECTORY))
    if (! S_ISDIR (st.st_mode))
      return GNUNET_NO;
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_LINK))
    if (! S_ISLNK (st.st_mode))
      return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Tries to convert @a zt_addr string to an IPv6 address.
 * The string is expected to have the format "[ABCD::01]:80".
 *
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of @a zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill. Initially gets filled with zeroes,
 *        then its sin6_port, sin6_family and sin6_addr are set appropriately.
 * @return #GNUNET_OK if conversion succeded.
 *         #GNUNET_SYSERR otherwise, in which
 *         case the contents of @a r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ipv6 (const char *zt_addr,
                                uint16_t addrlen,
                                struct sockaddr_in6 *r_buf)
{
  char zbuf[addrlen + 1];
  int ret;
  char *port_colon;
  unsigned int port;
  char dummy[2];

  if (addrlen < 6)
    return GNUNET_SYSERR;
  GNUNET_memcpy (zbuf, zt_addr, addrlen);
  if ('[' != zbuf[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("IPv6 address did not start with `['\n"));
    return GNUNET_SYSERR;
  }
  zbuf[addrlen] = '\0';
  port_colon = strrchr (zbuf, ':');
  if (NULL == port_colon)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("IPv6 address did contain ':' to separate port number\n"));
    return GNUNET_SYSERR;
  }
  if (']' != *(port_colon - 1))
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      _ ("IPv6 address did contain ']' before ':' to separate port number\n"));
    return GNUNET_SYSERR;
  }
  ret = sscanf (port_colon, ":%u%1s", &port, dummy);
  if ((1 != ret) || (port > 65535))
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      _ ("IPv6 address did contain a valid port number after the last ':'\n"));
    return GNUNET_SYSERR;
  }
  *(port_colon - 1) = '\0';
  memset (r_buf, 0, sizeof(struct sockaddr_in6));
  ret = inet_pton (AF_INET6, &zbuf[1], &r_buf->sin6_addr);
  if (ret <= 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Invalid IPv6 address `%s': %s\n"),
                &zbuf[1],
                strerror (errno));
    return GNUNET_SYSERR;
  }
  r_buf->sin6_port = htons (port);
  r_buf->sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
  r_buf->sin6_len = (u_char) sizeof(struct sockaddr_in6);
#endif
  return GNUNET_OK;
}


/**
 * Tries to convert 'zt_addr' string to an IPv4 address.
 * The string is expected to have the format "1.2.3.4:80".
 *
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of @a zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill.
 * @return #GNUNET_OK if conversion succeded.
 *         #GNUNET_SYSERR otherwise, in which case
 *         the contents of @a r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ipv4 (const char *zt_addr,
                                uint16_t addrlen,
                                struct sockaddr_in *r_buf)
{
  unsigned int temps[4];
  unsigned int port;
  unsigned int cnt;
  char dummy[2];

  if (addrlen < 9)
    return GNUNET_SYSERR;
  cnt = sscanf (zt_addr,
                "%u.%u.%u.%u:%u%1s",
                &temps[0],
                &temps[1],
                &temps[2],
                &temps[3],
                &port,
                dummy);
  if (5 != cnt)
    return GNUNET_SYSERR;
  for (cnt = 0; cnt < 4; cnt++)
    if (temps[cnt] > 0xFF)
      return GNUNET_SYSERR;
  if (port > 65535)
    return GNUNET_SYSERR;
  r_buf->sin_family = AF_INET;
  r_buf->sin_port = htons (port);
  r_buf->sin_addr.s_addr =
    htonl ((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) + temps[3]);
#if HAVE_SOCKADDR_IN_SIN_LEN
  r_buf->sin_len = (u_char) sizeof(struct sockaddr_in);
#endif
  return GNUNET_OK;
}


/**
 * Tries to convert @a addr string to an IP (v4 or v6) address.
 * Will automatically decide whether to treat 'addr' as v4 or v6 address.
 *
 * @param addr a string, may not be 0-terminated.
 * @param addrlen number of bytes in @a addr (if addr is 0-terminated,
 *        0-terminator should not be counted towards addrlen).
 * @param r_buf a buffer to fill.
 * @return #GNUNET_OK if conversion succeded. #GNUNET_SYSERR otherwise, in which
 *         case the contents of @a r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ip (const char *addr,
                              uint16_t addrlen,
                              struct sockaddr_storage *r_buf)
{
  if (addr[0] == '[')
    return GNUNET_STRINGS_to_address_ipv6 (addr,
                                           addrlen,
                                           (struct sockaddr_in6 *) r_buf);
  return GNUNET_STRINGS_to_address_ipv4 (addr,
                                         addrlen,
                                         (struct sockaddr_in *) r_buf);
}


/**
 * Parse an address given as a string into a
 * `struct sockaddr`.
 *
 * @param addr the address
 * @param[out] af set to the parsed address family (i.e. AF_INET)
 * @param[out] sa set to the parsed address
 * @return 0 on error, otherwise number of bytes in @a sa
 */
size_t
GNUNET_STRINGS_parse_socket_addr (const char *addr,
                                  uint8_t *af,
                                  struct sockaddr **sa)
{
  char *cp = GNUNET_strdup (addr);

  *af = AF_UNSPEC;
  if ('[' == *addr)
  {
    /* IPv6 */
    *sa = GNUNET_malloc (sizeof(struct sockaddr_in6));
    if (GNUNET_OK !=
        GNUNET_STRINGS_to_address_ipv6 (cp,
                                        strlen (cp),
                                        (struct sockaddr_in6 *) *sa))
    {
      GNUNET_free (*sa);
      *sa = NULL;
      GNUNET_free (cp);
      return 0;
    }
    *af = AF_INET6;
    GNUNET_free (cp);
    return sizeof(struct sockaddr_in6);
  }
  else
  {
    /* IPv4 */
    *sa = GNUNET_malloc (sizeof(struct sockaddr_in));
    if (GNUNET_OK !=
        GNUNET_STRINGS_to_address_ipv4 (cp,
                                        strlen (cp),
                                        (struct sockaddr_in *) *sa))
    {
      GNUNET_free (*sa);
      *sa = NULL;
      GNUNET_free (cp);
      return 0;
    }
    *af = AF_INET;
    GNUNET_free (cp);
    return sizeof(struct sockaddr_in);
  }
}


/**
 * Makes a copy of argv that consists of a single memory chunk that can be
 * freed with a single call to GNUNET_free();
 */
static char *const *
_make_continuous_arg_copy (int argc, char *const *argv)
{
  size_t argvsize = 0;
  int i;
  char **new_argv;
  char *p;

  for (i = 0; i < argc; i++)
    argvsize += strlen (argv[i]) + 1 + sizeof(char *);
  new_argv = GNUNET_malloc (argvsize + sizeof(char *));
  p = (char *) &new_argv[argc + 1];
  for (i = 0; i < argc; i++)
  {
    new_argv[i] = p;
    strcpy (p, argv[i]);
    p += strlen (argv[i]) + 1;
  }
  new_argv[argc] = NULL;
  return (char *const *) new_argv;
}


/**
 * Returns utf-8 encoded arguments.
 * Does nothing (returns a copy of argc and argv) on any platform
 * other than W32.
 * Returned argv has u8argv[u8argc] == NULL.
 * Returned argv is a single memory block, and can be freed with a single
 *   GNUNET_free() call.
 *
 * @param argc argc (as given by main())
 * @param argv argv (as given by main())
 * @param u8argc a location to store new argc in (though it's th same as argc)
 * @param u8argv a location to store new argv in
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_STRINGS_get_utf8_args (int argc,
                              char *const *argv,
                              int *u8argc,
                              char *const **u8argv)
{
  char *const *new_argv =
    (char *const *) _make_continuous_arg_copy (argc, argv);
  *u8argv = new_argv;
  *u8argc = argc;
  return GNUNET_OK;
}


/**
 * Parse the given port policy.  The format is
 * "[!]SPORT[-DPORT]".
 *
 * @param port_policy string to parse
 * @param pp policy to fill in
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         @a port_policy is malformed
 */
static int
parse_port_policy (const char *port_policy,
                   struct GNUNET_STRINGS_PortPolicy *pp)
{
  const char *pos;
  int s;
  int e;
  char eol[2];

  pos = port_policy;
  if ('!' == *pos)
  {
    pp->negate_portrange = GNUNET_YES;
    pos++;
  }
  if (2 == sscanf (pos, "%u-%u%1s", &s, &e, eol))
  {
    if ((0 == s) || (s > 0xFFFF) || (e < s) || (e > 0xFFFF))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Port not in range\n"));
      return GNUNET_SYSERR;
    }
    pp->start_port = (uint16_t) s;
    pp->end_port = (uint16_t) e;
    return GNUNET_OK;
  }
  if (1 == sscanf (pos, "%u%1s", &s, eol))
  {
    if ((0 == s) || (s > 0xFFFF))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Port not in range\n"));
      return GNUNET_SYSERR;
    }

    pp->start_port = (uint16_t) s;
    pp->end_port = (uint16_t) s;
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              _ ("Malformed port policy `%s'\n"),
              port_policy);
  return GNUNET_SYSERR;
}


/**
 * Parse an IPv4 network policy. The argument specifies a list of
 * subnets. The format is
 * <tt>(network[/netmask][:SPORT[-DPORT]];)*</tt> (no whitespace, must
 * be terminated with a semicolon). The network must be given in
 * dotted-decimal notation. The netmask can be given in CIDR notation
 * (/16) or in dotted-decimal (/255.255.0.0).
 *
 * @param routeListX a string specifying the IPv4 subnets
 * @return the converted list, terminated with all zeros;
 *         NULL if the synatx is flawed
 */
struct GNUNET_STRINGS_IPv4NetworkPolicy *
GNUNET_STRINGS_parse_ipv4_policy (const char *routeListX)
{
  unsigned int count;
  unsigned int i;
  unsigned int j;
  unsigned int len;
  int cnt;
  unsigned int pos;
  unsigned int temps[8];
  int slash;
  struct GNUNET_STRINGS_IPv4NetworkPolicy *result;
  int colon;
  int end;
  char *routeList;
  char dummy[2];

  if (NULL == routeListX)
    return NULL;
  len = strlen (routeListX);
  if (0 == len)
    return NULL;
  routeList = GNUNET_strdup (routeListX);
  count = 0;
  for (i = 0; i < len; i++)
    if (routeList[i] == ';')
      count++;
  result = GNUNET_malloc (sizeof(struct GNUNET_STRINGS_IPv4NetworkPolicy)
                          * (count + 1));
  i = 0;
  pos = 0;
  while (i < count)
  {
    for (colon = pos; ':' != routeList[colon]; colon++)
      if ((';' == routeList[colon]) || ('\0' == routeList[colon]))
        break;
    for (end = colon; ';' != routeList[end]; end++)
      if ('\0' == routeList[end])
        break;
    if ('\0' == routeList[end])
      break;
    routeList[end] = '\0';
    if (':' == routeList[colon])
    {
      routeList[colon] = '\0';
      if (GNUNET_OK != parse_port_policy (&routeList[colon + 1], &result[i].pp))
        break;
    }
    cnt = sscanf (&routeList[pos],
                  "%u.%u.%u.%u/%u.%u.%u.%u%1s",
                  &temps[0],
                  &temps[1],
                  &temps[2],
                  &temps[3],
                  &temps[4],
                  &temps[5],
                  &temps[6],
                  &temps[7],
                  dummy);
    if (8 == cnt)
    {
      for (j = 0; j < 8; j++)
        if (temps[j] > 0xFF)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ ("Invalid format for IP: `%s'\n"),
               &routeList[pos]);
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      result[i].network.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16)
                                        + (temps[2] << 8) + temps[3]);
      result[i].netmask.s_addr = htonl ((temps[4] << 24) + (temps[5] << 16)
                                        + (temps[6] << 8) + temps[7]);
      pos = end + 1;
      i++;
      continue;
    }
    /* try second notation */
    cnt = sscanf (&routeList[pos],
                  "%u.%u.%u.%u/%u%1s",
                  &temps[0],
                  &temps[1],
                  &temps[2],
                  &temps[3],
                  &slash,
                  dummy);
    if (5 == cnt)
    {
      for (j = 0; j < 4; j++)
        if (temps[j] > 0xFF)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ ("Invalid format for IP: `%s'\n"),
               &routeList[pos]);
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      result[i].network.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16)
                                        + (temps[2] << 8) + temps[3]);
      if ((slash <= 32) && (slash >= 0))
      {
        result[i].netmask.s_addr = 0;
        while (slash > 0)
        {
          result[i].netmask.s_addr =
            (result[i].netmask.s_addr >> 1) + 0x80000000;
          slash--;
        }
        result[i].netmask.s_addr = htonl (result[i].netmask.s_addr);
        pos = end + 1;
        i++;
        continue;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Invalid network notation ('/%d' is not legal in IPv4 CIDR)."),
             slash);
        GNUNET_free (result);
        GNUNET_free (routeList);
        return NULL;       /* error */
      }
    }
    /* try third notation */
    slash = 32;
    cnt = sscanf (&routeList[pos],
                  "%u.%u.%u.%u%1s",
                  &temps[0],
                  &temps[1],
                  &temps[2],
                  &temps[3],
                  dummy);
    if (4 == cnt)
    {
      for (j = 0; j < 4; j++)
        if (temps[j] > 0xFF)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ ("Invalid format for IP: `%s'\n"),
               &routeList[pos]);
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      result[i].network.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16)
                                        + (temps[2] << 8) + temps[3]);
      result[i].netmask.s_addr = 0;
      while (slash > 0)
      {
        result[i].netmask.s_addr = (result[i].netmask.s_addr >> 1) + 0x80000000;
        slash--;
      }
      result[i].netmask.s_addr = htonl (result[i].netmask.s_addr);
      pos = end + 1;
      i++;
      continue;
    }
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Invalid format for IP: `%s'\n"),
         &routeList[pos]);
    GNUNET_free (result);
    GNUNET_free (routeList);
    return NULL;   /* error */
  }
  if (pos < strlen (routeList))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Invalid format: `%s'\n"),
         &routeListX[pos]);
    GNUNET_free (result);
    GNUNET_free (routeList);
    return NULL;   /* oops */
  }
  GNUNET_free (routeList);
  return result; /* ok */
}


/**
 * Parse an IPv6 network policy. The argument specifies a list of
 * subnets. The format is <tt>(network[/netmask[:SPORT[-DPORT]]];)*</tt>
 * (no whitespace, must be terminated with a semicolon). The network
 * must be given in colon-hex notation.  The netmask must be given in
 * CIDR notation (/16) or can be omitted to specify a single host.
 * Note that the netmask is mandatory if ports are specified.
 *
 * @param routeListX a string specifying the policy
 * @return the converted list, 0-terminated, NULL if the synatx is flawed
 */
struct GNUNET_STRINGS_IPv6NetworkPolicy *
GNUNET_STRINGS_parse_ipv6_policy (const char *routeListX)
{
  unsigned int count;
  unsigned int i;
  unsigned int len;
  unsigned int pos;
  int start;
  int slash;
  int ret;
  char *routeList;
  struct GNUNET_STRINGS_IPv6NetworkPolicy *result;
  unsigned int bits;
  unsigned int off;
  int save;
  int colon;
  char dummy[2];

  if (NULL == routeListX)
    return NULL;
  len = strlen (routeListX);
  if (0 == len)
    return NULL;
  routeList = GNUNET_strdup (routeListX);
  count = 0;
  for (i = 0; i < len; i++)
    if (';' == routeList[i])
      count++;
  if (';' != routeList[len - 1])
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Invalid network notation (does not end with ';': `%s')\n"),
         routeList);
    GNUNET_free (routeList);
    return NULL;
  }

  result = GNUNET_malloc (sizeof(struct GNUNET_STRINGS_IPv6NetworkPolicy)
                          * (count + 1));
  i = 0;
  pos = 0;
  while (i < count)
  {
    start = pos;
    while (';' != routeList[pos])
      pos++;
    slash = pos;
    while ((slash >= start) && (routeList[slash] != '/'))
      slash--;

    if (slash < start)
    {
      memset (&result[i].netmask, 0xFF, sizeof(struct in6_addr));
      slash = pos;
    }
    else
    {
      routeList[pos] = '\0';
      for (colon = pos; ':' != routeList[colon]; colon--)
        if ('/' == routeList[colon])
          break;
      if (':' == routeList[colon])
      {
        routeList[colon] = '\0';
        if (GNUNET_OK !=
            parse_port_policy (&routeList[colon + 1], &result[i].pp))
        {
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      }
      ret = inet_pton (AF_INET6, &routeList[slash + 1], &result[i].netmask);
      if (ret <= 0)
      {
        save = errno;
        if ((1 != sscanf (&routeList[slash + 1], "%u%1s", &bits, dummy)) ||
            (bits > 128))
        {
          if (0 == ret)
            LOG (GNUNET_ERROR_TYPE_WARNING,
                 _ ("Wrong format `%s' for netmask\n"),
                 &routeList[slash + 1]);
          else
          {
            errno = save;
            LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "inet_pton");
          }
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
        off = 0;
        while (bits > 8)
        {
          result[i].netmask.s6_addr[off++] = 0xFF;
          bits -= 8;
        }
        while (bits > 0)
        {
          result[i].netmask.s6_addr[off] =
            (result[i].netmask.s6_addr[off] >> 1) + 0x80;
          bits--;
        }
      }
    }
    routeList[slash] = '\0';
    ret = inet_pton (AF_INET6, &routeList[start], &result[i].network);
    if (ret <= 0)
    {
      if (0 == ret)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Wrong format `%s' for network\n"),
             &routeList[slash + 1]);
      else
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "inet_pton");
      GNUNET_free (result);
      GNUNET_free (routeList);
      return NULL;
    }
    pos++;
    i++;
  }
  GNUNET_free (routeList);
  return result;
}


/** ******************** Base64 encoding ***********/

#define FILLCHAR '='
static char *cvt = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz"
                   "0123456789+/";


/**
 * Encode into Base64.
 *
 * @param in the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64_encode (const void *in, size_t len, char **output)
{
  const char *data = in;
  size_t ret;
  char *opt;

  ret = 0;
  opt = GNUNET_malloc (2 + (len * 4 / 3) + 8);
  for (size_t i = 0; i < len; ++i)
  {
    char c;

    c = (data[i] >> 2) & 0x3f;
    opt[ret++] = cvt[(int) c];
    c = (data[i] << 4) & 0x3f;
    if (++i < len)
      c |= (data[i] >> 4) & 0x0f;
    opt[ret++] = cvt[(int) c];
    if (i < len)
    {
      c = (data[i] << 2) & 0x3f;
      if (++i < len)
        c |= (data[i] >> 6) & 0x03;
      opt[ret++] = cvt[(int) c];
    }
    else
    {
      ++i;
      opt[ret++] = FILLCHAR;
    }
    if (i < len)
    {
      c = data[i] & 0x3f;
      opt[ret++] = cvt[(int) c];
    }
    else
    {
      opt[ret++] = FILLCHAR;
    }
  }
  *output = opt;
  return ret;
}


/**
 * Encode into Base64url. RFC7515
 *
 * @param in the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64url_encode (const void *in, size_t len, char **output)
{
  char *enc;
  size_t pos;

  GNUNET_STRINGS_base64_encode (in, len, output);
  enc = *output;
  /* Replace with correct characters for base64url */
  pos = 0;
  while ('\0' != enc[pos])
  {
    if ('+' == enc[pos])
      enc[pos] = '-';
    if ('/' == enc[pos])
      enc[pos] = '_';
    if ('=' == enc[pos])
    {
      enc[pos] = '\0';
      break;
    }
    pos++;
  }
  return strlen (enc);
}


#define cvtfind(a)                        \
  ((((a) >= 'A') && ((a) <= 'Z'))         \
   ? (a) - 'A'                          \
   : (((a) >= 'a') && ((a) <= 'z'))     \
   ? (a) - 'a' + 26                 \
   : (((a) >= '0') && ((a) <= '9')) \
   ? (a) - '0' + 52             \
   : ((a) == '+') ? 62 : ((a) == '/') ? 63 : -1)


/**
 * Decode from Base64.
 *
 * @param data the data to encode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64_decode (const char *data, size_t len, void **out)
{
  char *output;
  size_t ret = 0;

#define CHECK_CRLF                                                \
  while (data[i] == '\r' || data[i] == '\n')                      \
  {                                                               \
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK, \
                "ignoring CR/LF\n");                              \
    i++;                                                          \
    if (i >= len)                                                 \
      goto END;                                                   \
  }

  output = GNUNET_malloc ((len * 3 / 4) + 8);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "base64_decode decoding len=%d\n",
              (int) len);
  for (size_t i = 0; i < len; ++i)
  {
    char c;
    char c1;

    CHECK_CRLF;
    if (FILLCHAR == data[i])
      break;
    c = (char) cvtfind (data[i]);
    ++i;
    CHECK_CRLF;
    c1 = (char) cvtfind (data[i]);
    c = (c << 2) | ((c1 >> 4) & 0x3);
    output[ret++] = c;
    if (++i < len)
    {
      CHECK_CRLF;
      c = data[i];
      if (FILLCHAR == c)
        break;
      c = (char) cvtfind (c);
      c1 = ((c1 << 4) & 0xf0) | ((c >> 2) & 0xf);
      output[ret++] = c1;
    }
    if (++i < len)
    {
      CHECK_CRLF;
      c1 = data[i];
      if (FILLCHAR == c1)
        break;

      c1 = (char) cvtfind (c1);
      c = ((c << 6) & 0xc0) | c1;
      output[ret++] = c;
    }
  }
END:
  *out = output;
  return ret;
}


/**
 * Decode from Base64url. RFC7515
 *
 * @param data the data to decode
 * @param len the length of the input
 * @param output where to write the output (*output should be NULL,
 *   is allocated)
 * @return the size of the output
 */
size_t
GNUNET_STRINGS_base64url_decode (const char *data, size_t len, void **out)
{
  char *s;
  int padding;
  size_t ret;

  /* make enough space for padding */
  s = GNUNET_malloc (len + 3);
  memcpy (s, data, len);

  for (int i = 0; i < strlen (s); i++)
  {
    if (s[i] == '-')
      s[i] = '+';
    if (s[i] == '_')
      s[i] = '/';
  }
  padding = len % 4;
  switch (padding) // Pad with trailing '='s
  {
  case 0:
    break;   // No pad chars in this case
  case 2:
    memcpy (&s[len],
            "==",
            2);
    len += 2;
    break;         // Two pad chars
  case 3:
    s[len] = '=';
    len++;
    break;         // One pad char
  default:
    GNUNET_assert (0);
    break;
  }
  ret = GNUNET_STRINGS_base64_decode (s, len, out);
  GNUNET_free (s);
  return ret;
}


/* end of strings.c */

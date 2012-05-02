/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/strings.c
 * @brief string functions
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "platform.h"
#if HAVE_ICONV
#include <iconv.h>
#endif
#include "gnunet_common.h"
#include "gnunet_strings_lib.h"
#include <unicase.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)


/**
 * Fill a buffer of the given size with
 * count 0-terminated strings (given as varargs).
 * If "buffer" is NULL, only compute the amount of
 * space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function
 * will add 0-terminators after each string.  The
 * "GNUNET_string_buffer_tokenize" function can be
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
      memcpy (&buffer[needed], s, slen);
    }
    needed += slen;
    count--;
  }
  va_end (ap);
  return needed;
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
GNUNET_STRINGS_buffer_tokenize (const char *buffer, size_t size,
                                unsigned int count, ...)
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
      return 0;                 /* error */
    }
    *r = &buffer[start];
    needed++;                   /* skip 0-termination */
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
  const char *unit = _( /* size unit */ "b");
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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
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

  ret = 0;
  last = 0;
  in = GNUNET_strdup (input);
  for (tok = strtok (in, " "); tok != NULL; tok = strtok (NULL, " "))
  {
    i = 0;
    while ((table[i].name != NULL) && (0 != strcasecmp (table[i].name, tok)))
      i++;
    if (table[i].name != NULL)
      last *= table[i].value;
    else
    {
      ret += last;
      last = 0;
      if (1 != SSCANF (tok, "%llu", &last))
      {
        GNUNET_free (in);
        return GNUNET_SYSERR;   /* expected number */
      }
    }
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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_size_to_bytes (const char *fancy_size,
                                    unsigned long long *size)
{
  static const struct ConversionTable table[] =
  {
    { "B", 1},
    { "KiB", 1024},
    { "kB", 1000},
    { "MiB", 1024 * 1024},
    { "MB", 1000 * 1000},
    { "GiB", 1024 * 1024 * 1024},
    { "GB", 1000 * 1000 * 1000},
    { "TiB", 1024LL * 1024LL * 1024LL * 1024LL},
    { "TB", 1000LL * 1000LL * 1000LL * 1024LL},
    { "PiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL},
    { "PB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL},
    { "EiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL * 1024LL},
    { "EB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL * 1000LL},
    { NULL, 0}
  };

  return convert_with_table (fancy_size,
			     table,
			     size);
}


/**
 * Convert a given fancy human-readable time to our internal
 * representation.
 *
 * @param fancy_time human readable string (i.e. 1 minute)
 * @param rtime set to the relative time
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_time_to_relative (const char *fancy_time,
                                       struct GNUNET_TIME_Relative *rtime)
{
  static const struct ConversionTable table[] =
  {
    { "ms", 1},
    { "s", 1000},
    { "\"", 1000},
    { "min", 60 * 1000},
    { "minutes", 60 * 1000},
    { "'", 60 * 1000},
    { "h", 60 * 60 * 1000},
    { "d", 24 * 60 * 60 * 1000},
    { "a", 31536000000LL /* year */ },
    { NULL, 0}
  };
  int ret;
  unsigned long long val;

  ret = convert_with_table (fancy_time,
			    table,
			    &val);
  rtime->rel_value = (uint64_t) val;
  return ret;
}

/**
 * Convert the len characters long character sequence
 * given in input that is in the given input charset
 * to a string in given output charset.
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char *
GNUNET_STRINGS_conv (const char *input, size_t len, const char *input_charset, const char *output_charset)
{
  char *ret;

#if ENABLE_NLS && HAVE_ICONV
  size_t tmpSize;
  size_t finSize;
  char *tmp;
  char *itmp;
  iconv_t cd;

  cd = iconv_open (output_charset, input_charset);
  if (cd == (iconv_t) - 1)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "iconv_open");
    LOG (GNUNET_ERROR_TYPE_WARNING, _("Character sets requested were `%s'->`%s'\n"),
         input_charset, output_charset);
    ret = GNUNET_malloc (len + 1);
    memcpy (ret, input, len);
    ret[len] = '\0';
    return ret;
  }
  tmpSize = 3 * len + 4;
  tmp = GNUNET_malloc (tmpSize);
  itmp = tmp;
  finSize = tmpSize;
  if (iconv (cd,
#if FREEBSD || DARWIN || WINDOWS
             (const char **) &input,
#else
             (char **) &input,
#endif
             &len, &itmp, &finSize) == SIZE_MAX)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "iconv");
    iconv_close (cd);
    GNUNET_free (tmp);
    ret = GNUNET_malloc (len + 1);
    memcpy (ret, input, len);
    ret[len] = '\0';
    return ret;
  }
  ret = GNUNET_malloc (tmpSize - finSize + 1);
  memcpy (ret, tmp, tmpSize - finSize);
  ret[tmpSize - finSize] = '\0';
  GNUNET_free (tmp);
  if (0 != iconv_close (cd))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "iconv_close");
  return ret;
#else
  ret = GNUNET_malloc (len + 1);
  memcpy (ret, input, len);
  ret[len] = '\0';
  return ret;
#endif
}


/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
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
 * Convert the utf-8 input string to lowercase
 * Output needs to be allocated appropriately
 *
 * @param input input string
 * @param output output buffer
 */
void
GNUNET_STRINGS_utf8_tolower(const char* input, char** output)
{
  uint8_t *tmp_in;
  size_t len;

  tmp_in = u8_tolower ((uint8_t*)input, strlen ((char *) input),
                       NULL, UNINORM_NFD, NULL, &len);
  memcpy(*output, tmp_in, len);
  (*output)[len] = '\0';
  free(tmp_in);
}

/**
 * Convert the utf-8 input string to uppercase
 * Output needs to be allocated appropriately
 *
 * @param input input string
 * @param output output buffer
 */
void
GNUNET_STRINGS_utf8_toupper(const char* input, char** output)
{
  uint8_t *tmp_in;
  size_t len;

  tmp_in = u8_toupper ((uint8_t*)input, strlen ((char *) input),
                       NULL, UNINORM_NFD, NULL, &len);
  memcpy(*output, tmp_in, len);
  (*output)[len] = '\0';
  free(tmp_in);
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

#ifndef MINGW
  size_t len;
  size_t n;
  char *fm;
  const char *fil_ptr;
#else
  char *fn;
  long lRet;
#endif

  if (fil == NULL)
    return NULL;

#ifndef MINGW
  if (fil[0] == DIR_SEPARATOR)
    /* absolute path, just copy */
    return GNUNET_strdup (fil);
  if (fil[0] == '~')
  {
    fm = getenv ("HOME");
    if (fm == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("Failed to expand `$HOME': environment variable `HOME' not set"));
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
      buffer = getenv ("PWD");  /* alternative */
      if (buffer != NULL)
        fm = GNUNET_strdup (buffer);
    }
    if (fm == NULL)
      fm = GNUNET_strdup ("./");        /* give up */
  }
  n = strlen (fm) + 1 + strlen (fil_ptr) + 1;
  buffer = GNUNET_malloc (n);
  GNUNET_snprintf (buffer, n, "%s%s%s", fm,
                   (fm[strlen (fm) - 1] ==
                    DIR_SEPARATOR) ? "" : DIR_SEPARATOR_STR, fil_ptr);
  GNUNET_free (fm);
  return buffer;
#else
  fn = GNUNET_malloc (MAX_PATH + 1);

  if ((lRet = plibc_conv_to_win_path (fil, fn)) != ERROR_SUCCESS)
  {
    SetErrnoFromWinError (lRet);
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "plibc_conv_to_win_path");
    return NULL;
  }
  /* is the path relative? */
  if ((strncmp (fn + 1, ":\\", 2) != 0) && (strncmp (fn, "\\\\", 2) != 0))
  {
    char szCurDir[MAX_PATH + 1];

    lRet = GetCurrentDirectory (MAX_PATH + 1, szCurDir);
    if (lRet + strlen (fn) + 1 > (MAX_PATH + 1))
    {
      SetErrnoFromWinError (ERROR_BUFFER_OVERFLOW);
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "GetCurrentDirectory");
      return NULL;
    }
    buffer = GNUNET_malloc (MAX_PATH + 1);
    GNUNET_snprintf (buffer, MAX_PATH + 1, "%s\\%s", szCurDir, fn);
    GNUNET_free (fn);
    fn = buffer;
  }

  return fn;
#endif
}


/**
 * Give relative time in human-readable fancy format.
 *
 * @param delta time in milli seconds
 * @return time as human-readable string
 */
char *
GNUNET_STRINGS_relative_time_to_string (struct GNUNET_TIME_Relative delta)
{
  const char *unit = _( /* time unit */ "ms");
  char *ret;
  uint64_t dval = delta.rel_value;

  if (delta.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
    return GNUNET_strdup (_("eternity"));
  if (dval > 5 * 1000)
  {
    dval = dval / 1000;
    unit = _( /* time unit */ "s");
    if (dval > 5 * 60)
    {
      dval = dval / 60;
      unit = _( /* time unit */ "m");
      if (dval > 5 * 60)
      {
        dval = dval / 60;
        unit = _( /* time unit */ "h");
        if (dval > 5 * 24)
        {
          dval = dval / 24;
          unit = _( /* time unit */ " days");
        }
      }
    }
  }
  GNUNET_asprintf (&ret, "%llu %s", dval, unit);
  return ret;
}


/**
 * "man ctime_r", except for GNUnet time; also, unlike ctime, the
 * return value does not include the newline character.
 *
 * @param t time to convert
 * @return absolute time in human-readable format
 */
char *
GNUNET_STRINGS_absolute_time_to_string (struct GNUNET_TIME_Absolute t)
{
  time_t tt;
  char *ret;

  if (t.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
    return GNUNET_strdup (_("end of time"));
  tt = t.abs_value / 1000;
#ifdef ctime_r
  ret = ctime_r (&tt, GNUNET_malloc (32));
#else
  ret = GNUNET_strdup (ctime (&tt));
#endif
  ret[strlen (ret) - 1] = '\0';
  return ret;
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
  while (NULL != (ss = strstr (short_fn, DIR_SEPARATOR_STR))
      && (ss[1] != '\0'))
    short_fn = 1 + ss;
  return short_fn;
}


/**
 * Get the numeric value corresponding to a character.
 *
 * @param a a character
 * @return corresponding numeric value
 */
static unsigned int
getValue__ (unsigned char a)
{
  if ((a >= '0') && (a <= '9'))
    return a - '0';
  if ((a >= 'A') && (a <= 'V'))
    return (a - 'A' + 10);
  return -1;
}


/**
 * Convert binary data to ASCII encoding.  The ASCII encoding is rather
 * GNUnet specific.  It was chosen such that it only uses characters
 * in [0-9A-V], can be produced without complex arithmetics and uses a
 * small number of characters.  
 * Does not append 0-terminator, but returns a pointer to the place where
 * it should be placed, if needed.
 *
 * @param data data to encode
 * @param size size of data (in bytes)
 * @param out buffer to fill
 * @param out_size size of the buffer. Must be large enough to hold
 * ((size*8) + (((size*8) % 5) > 0 ? 5 - ((size*8) % 5) : 0)) / 5 bytes
 * @return pointer to the next byte in 'out' or NULL on error.
 */
char *
GNUNET_STRINGS_data_to_string (const unsigned char *data, size_t size, char *out, size_t out_size)
{
  /**
   * 32 characters for encoding 
   */
  static char *encTable__ = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;

  GNUNET_assert (data != NULL);
  GNUNET_assert (out != NULL);
  if (out_size < (((size*8) + ((size*8) % 5)) % 5))
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
      bits = (bits << 8) | data[rpos++];   /* eat 8 more bits */
      vbit += 8;
    }
    if (vbit < 5)
    {
      bits <<= (5 - vbit);      /* zero-padding */
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
  if (wpos != out_size)
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_assert (vbit == 0);
  return &out[wpos];
}


/**
 * Convert ASCII encoding back to data
 * out_size must match exactly the size of the data before it was encoded.
 *
 * @param enc the encoding
 * @param enclen number of characters in 'enc' (without 0-terminator, which can be missing)
 * @param out location where to store the decoded data
 * @param out_size sizeof the output buffer
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_STRINGS_string_to_data (const char *enc, size_t enclen,
                              unsigned char *out, size_t out_size)
{
  unsigned int rpos;
  unsigned int wpos;
  unsigned int bits;
  unsigned int vbit;
  int ret;
  int shift;
  int encoded_len = out_size * 8;
  if (encoded_len % 5 > 0)
  {
    vbit = encoded_len % 5; /* padding! */
    shift = 5 - vbit;
  }
  else
  {
    vbit = 0;
    shift = 0;
  }
  if ((encoded_len + shift) / 5 != enclen)
    return GNUNET_SYSERR;

  wpos = out_size;
  rpos = enclen;
  bits = (ret = getValue__ (enc[--rpos])) >> (5 - encoded_len % 5);
  if (-1 == ret)
    return GNUNET_SYSERR;
  while (wpos > 0)
  {
    GNUNET_assert (rpos > 0);
    bits = ((ret = getValue__ (enc[--rpos])) << vbit) | bits;
    if (-1 == ret)
      return GNUNET_SYSERR;
    vbit += 5;
    if (vbit >= 8)
    {
      out[--wpos] = (unsigned char) bits;
      bits >>= 8;
      vbit -= 8;
    }
  }
  GNUNET_assert (rpos == 0);
  GNUNET_assert (vbit == 0);
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
GNUNET_STRINGS_parse_uri (const char *path, char **scheme_part,
    const char **path_part)
{
  size_t len;
  int i, end;
  int pp_state = 0;
  const char *post_scheme_part = NULL;
  len = strlen (path);
  for (end = 0, i = 0; !end && i < len; i++)
  {
    switch (pp_state)
    {
    case 0:
      if (path[i] == ':' && i > 0)
      {
        pp_state += 1;
        continue;
      }
      if (!((path[i] >= 'A' && path[i] <= 'Z') || (path[i] >= 'a' && path[i] <= 'z')
          || (path[i] >= '0' && path[i] <= '9') || path[i] == '+' || path[i] == '-'
          || (path[i] == '.')))
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
    memcpy (*scheme_part, path, post_scheme_part - path);
    (*scheme_part)[post_scheme_part - path] = '\0';
  }
  if (path_part)
    *path_part = post_scheme_part;
  return GNUNET_YES;
}


/**
 * Check whether 'filename' is absolute or not, and if it's an URI
 *
 * @param filename filename to check
 * @param can_be_uri GNUNET_YES to check for being URI, GNUNET_NO - to
 *        assume it's not URI
 * @param r_is_uri a pointer to an int that is set to GNUNET_YES if 'filename'
 *        is URI and to GNUNET_NO otherwise. Can be NULL. If 'can_be_uri' is
 *        not GNUNET_YES, *r_is_uri is set to GNUNET_NO.
 * @param r_uri_scheme a pointer to a char * that is set to a pointer to URI scheme.
 *        The string is allocated by the function, and should be freed with
 *        GNUNET_free (). Can be NULL.
 * @return GNUNET_YES if 'filename' is absolute, GNUNET_NO otherwise.
 */
int
GNUNET_STRINGS_path_is_absolute (const char *filename, int can_be_uri,
    int *r_is_uri, char **r_uri_scheme)
{
#if WINDOWS
  size_t len;
#endif
  const char *post_scheme_path;
  int is_uri;
  char * uri;
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
#if WINDOWS
      len = strlen(post_scheme_path);
      /* Special check for file:///c:/blah
       * We want to parse 'c:/', not '/c:/'
       */
      if (post_scheme_path[0] == '/' && len >= 3 && post_scheme_path[2] == ':')
        post_scheme_path = &post_scheme_path[1];
#endif
      return GNUNET_STRINGS_path_is_absolute (post_scheme_path, GNUNET_NO, NULL, NULL);
    }
  }
  else
  {
    is_uri = GNUNET_NO;
    if (r_is_uri)
      *r_is_uri = GNUNET_NO;
  }
#if WINDOWS
  len = strlen (filename);
  if (len >= 3 &&
      ((filename[0] >= 'A' && filename[0] <= 'Z')
      || (filename[0] >= 'a' && filename[0] <= 'z'))
      && filename[1] == ':' && (filename[2] == '/' || filename[2] == '\\'))
    return GNUNET_YES;
#endif
  return GNUNET_NO;
}

#if MINGW
#define  	_IFMT		0170000 /* type of file */
#define  	_IFLNK		0120000 /* symbolic link */
#define  S_ISLNK(m)	(((m)&_IFMT) == _IFLNK)
#endif


/**
 * Perform 'checks' on 'filename'
 * 
 * @param filename file to check
 * @param checks checks to perform
 * @return GNUNET_YES if all checks pass, GNUNET_NO if at least one of them
 *         fails, GNUNET_SYSERR when a check can't be performed
 */
int
GNUNET_STRINGS_check_filename (const char *filename,
			       enum GNUNET_STRINGS_FilenameCheck checks)
{
  struct stat st;
  if ( (NULL == filename) || (filename[0] == '\0') )
    return GNUNET_SYSERR;
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_ABSOLUTE))
    if (!GNUNET_STRINGS_path_is_absolute (filename, GNUNET_NO, NULL, NULL))
      return GNUNET_NO;
  if (0 != (checks & (GNUNET_STRINGS_CHECK_EXISTS
		      | GNUNET_STRINGS_CHECK_IS_DIRECTORY
		      | GNUNET_STRINGS_CHECK_IS_LINK)))
  {
    if (0 != STAT (filename, &st))
    {
      if (0 != (checks & GNUNET_STRINGS_CHECK_EXISTS))
        return GNUNET_NO;
      else
        return GNUNET_SYSERR;
    }
  }
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_DIRECTORY))
    if (!S_ISDIR (st.st_mode))
      return GNUNET_NO;
  if (0 != (checks & GNUNET_STRINGS_CHECK_IS_LINK))
    if (!S_ISLNK (st.st_mode))
      return GNUNET_NO;
  return GNUNET_YES;
}



/**
 * Tries to convert 'zt_addr' string to an IPv6 address.
 * The string is expected to have the format "[ABCD::01]:80".
 * 
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill. Initially gets filled with zeroes,
 *        then its sin6_port, sin6_family and sin6_addr are set appropriately.
 * @return GNUNET_OK if conversion succeded. GNUNET_SYSERR otherwise, in which
 *         case the contents of r_buf are undefined.
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

  if (addrlen < 6)
    return GNUNET_SYSERR;  
  memcpy (zbuf, zt_addr, addrlen);
  if ('[' != zbuf[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("IPv6 address did not start with `['\n"));
    return GNUNET_SYSERR;
  }
  zbuf[addrlen] = '\0';
  port_colon = strrchr (zbuf, ':');
  if (NULL == port_colon)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("IPv6 address did contain ':' to separate port number\n"));
    return GNUNET_SYSERR;
  }
  if (']' != *(port_colon - 1))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("IPv6 address did contain ']' before ':' to separate port number\n"));
    return GNUNET_SYSERR;
  }
  ret = SSCANF (port_colon, ":%u", &port);
  if ( (1 != ret) || (port > 65535) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("IPv6 address did contain a valid port number after the last ':'\n"));
    return GNUNET_SYSERR;
  }
  *(port_colon-1) = '\0';
  memset (r_buf, 0, sizeof (struct sockaddr_in6));
  ret = inet_pton (AF_INET6, &zbuf[1], &r_buf->sin6_addr);
  if (ret <= 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Invalid IPv6 address `%s': %s\n"),
		&zbuf[1],
		STRERROR (errno));
    return GNUNET_SYSERR;
  }
  r_buf->sin6_port = htons (port);
  r_buf->sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
  r_buf->sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
  return GNUNET_OK;
}


/**
 * Tries to convert 'zt_addr' string to an IPv4 address.
 * The string is expected to have the format "1.2.3.4:80".
 * 
 * @param zt_addr 0-terminated string. May be mangled by the function.
 * @param addrlen length of zt_addr (not counting 0-terminator).
 * @param r_buf a buffer to fill.
 * @return GNUNET_OK if conversion succeded. GNUNET_SYSERR otherwise, in which case
 *         the contents of r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ipv4 (const char *zt_addr, uint16_t addrlen,
				struct sockaddr_in *r_buf)
{
  unsigned int temps[4];
  unsigned int port;
  unsigned int cnt;

  if (addrlen < 9)
    return GNUNET_SYSERR;
  cnt = SSCANF (zt_addr, "%u.%u.%u.%u:%u", &temps[0], &temps[1], &temps[2], &temps[3], &port);
  if (5 != cnt)
    return GNUNET_SYSERR;
  for (cnt = 0; cnt < 4; cnt++)
    if (temps[cnt] > 0xFF)
      return GNUNET_SYSERR;
  if (port > 65535)
    return GNUNET_SYSERR;
  r_buf->sin_family = AF_INET;
  r_buf->sin_port = htons (port);
  r_buf->sin_addr.s_addr = htonl ((temps[0] << 24) + (temps[1] << 16) +
				  (temps[2] << 8) + temps[3]);
#if HAVE_SOCKADDR_IN_SIN_LEN
  r_buf->sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
  return GNUNET_OK;
}


/**
 * Tries to convert 'addr' string to an IP (v4 or v6) address.
 * Will automatically decide whether to treat 'addr' as v4 or v6 address.
 * 
 * @param addr a string, may not be 0-terminated.
 * @param addrlen number of bytes in addr (if addr is 0-terminated,
 *        0-terminator should not be counted towards addrlen).
 * @param r_buf a buffer to fill.
 * @return GNUNET_OK if conversion succeded. GNUNET_SYSERR otherwise, in which
 *         case the contents of r_buf are undefined.
 */
int
GNUNET_STRINGS_to_address_ip (const char *addr, 
			      uint16_t addrlen,
			      struct sockaddr_storage *r_buf)
{
  if (addr[0] == '[')
    return GNUNET_STRINGS_to_address_ipv6 (addr, addrlen, (struct sockaddr_in6 *) r_buf);
  return GNUNET_STRINGS_to_address_ipv4 (addr, addrlen, (struct sockaddr_in *) r_buf);
}

/* end of strings.c */

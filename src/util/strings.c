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
  struct
  {
    const char *name;
    unsigned long long value;
  } table[] =
  {
    {
    "B", 1},
    {
    "KiB", 1024},
    {
    "kB", 1000},
    {
    "MiB", 1024 * 1024},
    {
    "MB", 1000 * 1000},
    {
    "GiB", 1024 * 1024 * 1024},
    {
    "GB", 1000 * 1000 * 1000},
    {
    "TiB", 1024LL * 1024LL * 1024LL * 1024LL},
    {
    "TB", 1000LL * 1000LL * 1000LL * 1024LL},
    {
    "PiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL},
    {
    "PB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL},
    {
    "EiB", 1024LL * 1024LL * 1024LL * 1024LL * 1024LL * 1024LL},
    {
    "EB", 1000LL * 1000LL * 1000LL * 1024LL * 1000LL * 1000LL},
    {
    NULL, 0}
  };
  unsigned long long ret;
  char *in;
  const char *tok;
  unsigned long long last;
  unsigned int i;

  ret = 0;
  last = 0;
  in = GNUNET_strdup (fancy_size);
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
      if (1 != sscanf (tok, "%llu", &last))
      {
        GNUNET_free (in);
        return GNUNET_SYSERR;   /* expected number */
      }
    }
  }
  ret += last;
  *size = ret;
  GNUNET_free (in);
  return GNUNET_OK;
}


/**
 * Convert a given fancy human-readable time to our internal
 * representation.
 *
 * @param fancy_size human readable string (i.e. 1 minute)
 * @param rtime set to the relative time
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STRINGS_fancy_time_to_relative (const char *fancy_size,
                                       struct GNUNET_TIME_Relative *rtime)
{
  struct
  {
    const char *name;
    unsigned long long value;
  } table[] =
  {
    {
    "ms", 1},
    {
    "s", 1000},
    {
    "\"", 1000},
    {
    "min", 60 * 1000},
    {
    "minutes", 60 * 1000},
    {
    "'", 60 * 1000},
    {
    "h", 60 * 60 * 1000},
    {
    "d", 24 * 60 * 60 * 1000},
    {
    "a", 31557600 /* year */ },
    {
    NULL, 0}
  };
  unsigned long long ret;
  char *in;
  const char *tok;
  unsigned long long last;
  unsigned int i;

  if ((0 == strcasecmp (fancy_size, "infinity")) ||
      (0 == strcasecmp (fancy_size, "forever")))
  {
    *rtime = GNUNET_TIME_UNIT_FOREVER_REL;
    return GNUNET_OK;
  }
  ret = 0;
  last = 0;
  in = GNUNET_strdup (fancy_size);
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
      if (1 != sscanf (tok, "%llu", &last))
      {
        GNUNET_free (in);
        return GNUNET_SYSERR;   /* expected number */
      }
    }
  }
  ret += last;
  rtime->rel_value = (uint64_t) ret;
  GNUNET_free (in);
  return GNUNET_OK;
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

/* end of strings.c */

/*
     This file is part of GNUnet.
     (C) 2006-2013 Christian Grothoff (and other contributing authors)

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
 * @file util/common_logging.c
 * @brief error handling API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <regex.h>


/**
 * After how many milliseconds do we always print
 * that "message X was repeated N times"?  Use 12h.
 */
#define BULK_DELAY_THRESHOLD (12 * 60 * 60 * 1000LL * 1000LL)

/**
 * After how many repetitions do we always print
 * that "message X was repeated N times"? (even if
 * we have not yet reached the delay threshold)
 */
#define BULK_REPEAT_THRESHOLD 1000

/**
 * How many characters do we use for matching of
 * bulk messages?
 */
#define BULK_TRACK_SIZE 256

/**
 * How many characters do we use for matching of
 * bulk components?
 */
#define COMP_TRACK_SIZE 32

/**
 * How many characters can a date/time string
 * be at most?
 */
#define DATE_STR_SIZE 64

/**
 * How many log files to keep?
 */
#define ROTATION_KEEP 3

#ifndef PATH_MAX
/**
 * Assumed maximum path length (for the log file name).
 */
#define PATH_MAX 4096
#endif


/**
 * Linked list of active loggers.
 */
struct CustomLogger
{
  /**
   * This is a linked list.
   */
  struct CustomLogger *next;

  /**
   * Log function.
   */
  GNUNET_Logger logger;

  /**
   * Closure for logger.
   */
  void *logger_cls;
};

/**
 * The last "bulk" error message that we have been logging.
 * Note that this message maybe truncated to the first BULK_TRACK_SIZE
 * characters, in which case it is NOT 0-terminated!
 */
static char last_bulk[BULK_TRACK_SIZE];

/**
 * Type of the last bulk message.
 */
static enum GNUNET_ErrorType last_bulk_kind;

/**
 * Time of the last bulk error message (0 for none)
 */
static struct GNUNET_TIME_Absolute last_bulk_time;

/**
 * Number of times that bulk message has been repeated since.
 */
static unsigned int last_bulk_repeat;

/**
 * Component when the last bulk was logged.  Will be 0-terminated.
 */
static char last_bulk_comp[COMP_TRACK_SIZE + 1];

/**
 * Running component.
 */
static char *component;

/**
 * Running component (without pid).
 */
static char *component_nopid;

/**
 * Format string describing the name of the log file.
 */
static char *log_file_name;

/**
 * Minimum log level.
 */
static enum GNUNET_ErrorType min_level;

/**
 * Linked list of our custom loggres.
 */
static struct CustomLogger *loggers;

/**
 * Number of log calls to ignore.
 */
int skip_log = 0;

/**
 * File descriptor to use for "stderr", or NULL for none.
 */
static FILE *GNUNET_stderr;

/**
 * Represents a single logging definition
 */
struct LogDef
{
  /**
   * Component name regex
   */
  regex_t component_regex;

  /**
   * File name regex
   */
  regex_t file_regex;

  /**
   * Function name regex
   */
  regex_t function_regex;

  /**
   * Lowest line at which this definition matches.
   * Defaults to 0. Must be <= to_line.
   */
  int from_line;

  /**
   * Highest line at which this definition matches.
   * Defaults to INT_MAX. Must be >= from_line.
   */
  int to_line;

  /**
   * Maximal log level allowed for calls that match this definition.
   * Calls with higher log level will be disabled.
   * Must be >= 0
   */
  int level;

  /**
   * 1 if this definition comes from GNUNET_FORCE_LOG, which means that it
   * overrides any configuration options. 0 otherwise.
   */
  int force;
};

/**
 * Dynamic array of logging definitions
 */
static struct LogDef *logdefs;

/**
 * Allocated size of logdefs array (in units)
 */
static int logdefs_size;

/**
 * The number of units used in logdefs array.
 */
static int logdefs_len;

/**
 * GNUNET_YES if GNUNET_LOG environment variable is already parsed.
 */
static int gnunet_log_parsed;

/**
 * GNUNET_YES if GNUNET_FORCE_LOG environment variable is already parsed.
 */
static int gnunet_force_log_parsed;

/**
 * GNUNET_YES if at least one definition with forced == 1 is available.
 */
static int gnunet_force_log_present;

#ifdef WINDOWS
/**
 * Contains the number of performance counts per second.
 */
static LARGE_INTEGER performance_frequency;
#endif


/**
 * Convert a textual description of a loglevel
 * to the respective GNUNET_GE_KIND.
 *
 * @param log loglevel to parse
 * @return GNUNET_GE_INVALID if log does not parse
 */
static enum GNUNET_ErrorType
get_type (const char *log)
{
  if (NULL == log)
    return GNUNET_ERROR_TYPE_UNSPECIFIED;
  if (0 == strcasecmp (log, _("DEBUG")))
    return GNUNET_ERROR_TYPE_DEBUG;
  if (0 == strcasecmp (log, _("INFO")))
    return GNUNET_ERROR_TYPE_INFO;
  if (0 == strcasecmp (log, _("WARNING")))
    return GNUNET_ERROR_TYPE_WARNING;
  if (0 == strcasecmp (log, _("ERROR")))
    return GNUNET_ERROR_TYPE_ERROR;
  if (0 == strcasecmp (log, _("NONE")))
    return GNUNET_ERROR_TYPE_NONE;
  return GNUNET_ERROR_TYPE_INVALID;
}


#if !defined(GNUNET_CULL_LOGGING)
/**
 * Utility function - reallocates logdefs array to be twice as large.
 */
static void
resize_logdefs ()
{
  logdefs_size = (logdefs_size + 1) * 2;
  logdefs = GNUNET_realloc (logdefs, logdefs_size * sizeof (struct LogDef));
}


/**
 * Abort the process, generate a core dump if possible.
 */
void
GNUNET_abort ()
{
#if WINDOWS
  DebugBreak ();
#endif
  abort ();
}


/**
 * Rotate logs, deleting the oldest log.
 *
 * @param new_name new name to add to the rotation
 */
static void
log_rotate (const char *new_name)
{
  static char *rotation[ROTATION_KEEP];
  static unsigned int rotation_off;
  char *discard;

  if ('\0' == *new_name)
    return; /* not a real log file name */
  discard = rotation[rotation_off % ROTATION_KEEP];
  if (NULL != discard)
  {
    /* Note: can't log errors during logging (recursion!), so this
       operation MUST silently fail... */
    (void) UNLINK (discard);
    GNUNET_free (discard);
  }
  rotation[rotation_off % ROTATION_KEEP] = GNUNET_strdup (new_name);
  rotation_off++;
}


/**
 * Setup the log file.
 *
 * @param tm timestamp for which we should setup logging
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_log_file (const struct tm *tm)
{
  static char last_fn[PATH_MAX + 1];
  char fn[PATH_MAX + 1];
  int dirwarn;
  int altlog_fd;
  int dup_return;
  FILE *altlog;
  char *leftsquare;

  if (NULL == log_file_name)
    return GNUNET_SYSERR;
  if (0 == strftime (fn, sizeof (fn), log_file_name, tm))
    return GNUNET_SYSERR;
  leftsquare = strrchr (fn, '[');
  if ( (NULL != leftsquare) && (']' == leftsquare[1]) )
  {
    char *logfile_copy = GNUNET_strdup (fn);
    logfile_copy[leftsquare - fn] = '\0';
    logfile_copy[leftsquare - fn + 1] = '\0';
    snprintf (fn, PATH_MAX, "%s%d%s",
         logfile_copy, getpid (), &logfile_copy[leftsquare - fn + 2]);
    GNUNET_free (logfile_copy);
  }
  if (0 == strcmp (fn, last_fn))
    return GNUNET_OK; /* no change */
  log_rotate (last_fn);
  strcpy (last_fn, fn);
  dirwarn = (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn));
#if WINDOWS
  altlog_fd = OPEN (fn, O_APPEND |
                        O_BINARY |
                        O_WRONLY | O_CREAT,
                        _S_IREAD | _S_IWRITE);
#else
  altlog_fd = OPEN (fn, O_APPEND |
                        O_WRONLY | O_CREAT,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
  if (-1 != altlog_fd)
  {
    if (NULL != GNUNET_stderr)
      fclose (GNUNET_stderr);
    dup_return = dup2 (altlog_fd, 2);
    (void) close (altlog_fd);
    if (-1 != dup_return)
    {
      altlog = fdopen (2, "ab");
      if (NULL == altlog)
      {
        (void) close (2);
        altlog_fd = -1;
      }
    }
    else
    {
      altlog_fd = -1;
    }
  }
  if (-1 == altlog_fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", fn);
    if (dirwarn)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to create or access directory for log file `%s'\n"),
                  fn);
    return GNUNET_SYSERR;
  }
  GNUNET_stderr = altlog;
  return GNUNET_OK;
}

/**
 * Utility function - adds a parsed definition to logdefs array.
 *
 * @param component see struct LogDef, can't be NULL
 * @param file see struct LogDef, can't be NULL
 * @param function see struct LogDef, can't be NULL
 * @param from_line see struct LogDef
 * @param to_line see struct LogDef
 * @param level see struct LogDef, must be >= 0
 * @param force see struct LogDef
 * @return 0 on success, regex-specific error otherwise
 */
static int
add_definition (char *component, char *file, char *function, int from_line,
                int to_line, int level, int force)
{
  struct LogDef n;
  int r;

  if (logdefs_size == logdefs_len)
    resize_logdefs ();
  memset (&n, 0, sizeof (n));
  if (0 == strlen (component))
    component = (char *) ".*";
  r = regcomp (&n.component_regex, (const char *) component, REG_NOSUB);
  if (0 != r)
  {
    return r;
  }
  if (0 == strlen (file))
    file = (char *) ".*";
  r = regcomp (&n.file_regex, (const char *) file, REG_NOSUB);
  if (0 != r)
  {
    regfree (&n.component_regex);
    return r;
  }
  if ((NULL == function) || (0 == strlen (function)))
    function = (char *) ".*";
  r = regcomp (&n.function_regex, (const char *) function, REG_NOSUB);
  if (0 != r)
  {
    regfree (&n.component_regex);
    regfree (&n.file_regex);
    return r;
  }
  n.from_line = from_line;
  n.to_line = to_line;
  n.level = level;
  n.force = force;
  logdefs[logdefs_len++] = n;
  return 0;
}


/**
 * Decides whether a particular logging call should or should not be allowed
 * to be made. Used internally by GNUNET_log*()
 *
 * @param caller_level loglevel the caller wants to use
 * @param comp component name the caller uses (NULL means that global
 *   component name is used)
 * @param file file name containing the logging call, usually __FILE__
 * @param function function which tries to make a logging call,
 *   usually __FUNCTION__
 * @param line line at which the call is made, usually __LINE__
 * @return 0 to disallow the call, 1 to allow it
 */
int
GNUNET_get_log_call_status (int caller_level, const char *comp,
                            const char *file, const char *function, int line)
{
  struct LogDef *ld;
  int i;
  int force_only;

  if (NULL == comp)
    /* Use default component */
    comp = component_nopid;

  /* We have no definitions to override globally configured log level,
   * so just use it right away.
   */
  if ( (min_level >= 0) && (GNUNET_NO == gnunet_force_log_present) )
    return caller_level <= min_level;

  /* Only look for forced definitions? */
  force_only = min_level >= 0;
  for (i = 0; i < logdefs_len; i++)
  {
    ld = &logdefs[i];
    if (( (!force_only) || ld->force) &&
        (line >= ld->from_line && line <= ld->to_line) &&
        (0 == regexec (&ld->component_regex, comp, 0, NULL, 0)) &&
        (0 == regexec (&ld->file_regex, file, 0, NULL, 0)) &&
        (0 == regexec (&ld->function_regex, function, 0, NULL, 0)))
    {
      /* We're finished */
      return caller_level <= ld->level;
    }
  }
  /* No matches - use global level, if defined */
  if (min_level >= 0)
    return caller_level <= min_level;
  /* All programs/services previously defaulted to WARNING.
   * Now WE default to WARNING, and THEY default to NULL.
   */
  return caller_level <= GNUNET_ERROR_TYPE_WARNING;
}


/**
 * Utility function - parses a definition
 *
 * Definition format:
 * component;file;function;from_line-to_line;level[/component...]
 * All entries are mandatory, but may be empty.
 * Empty entries for component, file and function are treated as
 * "matches anything".
 * Empty line entry is treated as "from 0 to INT_MAX"
 * Line entry with only one line is treated as "this line only"
 * Entry for level MUST NOT be empty.
 * Entries for component, file and function that consist of a
 * single character "*" are treated (at the moment) the same way
 * empty entries are treated (wildcard matching is not implemented (yet?)).
 * file entry is matched to the end of __FILE__. That is, it might be
 * a base name, or a base name with leading directory names (some compilers
 * define __FILE__ to absolute file path).
 *
 * @param constname name of the environment variable from which to get the
 *   string to be parsed
 * @param force 1 if definitions found in constname are to be forced
 * @return number of added definitions
 */
static int
parse_definitions (const char *constname, int force)
{
  char *def;
  const char *tmp;
  char *comp = NULL;
  char *file = NULL;
  char *function = NULL;
  char *p;
  char *start;
  char *t;
  short state;
  int level;
  int from_line, to_line;
  int counter = 0;
  int keep_looking = 1;

  tmp = getenv (constname);
  if (NULL == tmp)
    return 0;
  def = GNUNET_strdup (tmp);
  from_line = 0;
  to_line = INT_MAX;
  for (p = def, state = 0, start = def; keep_looking; p++)
  {
    switch (p[0])
    {
    case ';':                  /* found a field separator */
      p[0] = '\0';
      switch (state)
      {
      case 0:                  /* within a component name */
        comp = start;
        break;
      case 1:                  /* within a file name */
        file = start;
        break;
      case 2:                  /* within a function name */
        /* after a file name there must be a function name */
        function = start;
        break;
      case 3:                  /* within a from-to line range */
        if (strlen (start) > 0)
        {
          errno = 0;
          from_line = strtol (start, &t, 10);
          if ( (0 != errno) || (from_line < 0) )
          {
            GNUNET_free (def);
            return counter;
          }
          if ( (t < p) && ('-' == t[0]) )
          {
            errno = 0;
            start = t + 1;
            to_line = strtol (start, &t, 10);
            if ( (0 != errno) || (to_line < 0) || (t != p) )
            {
              GNUNET_free (def);
              return counter;
            }
          }
          else                  /* one number means "match this line only" */
            to_line = from_line;
        }
        else                    /* default to 0-max */
        {
          from_line = 0;
          to_line = INT_MAX;
        }
        break;
      }
      start = p + 1;
      state++;
      break;
    case '\0':                 /* found EOL */
      keep_looking = 0;
      /* fall through to '/' */
    case '/':                  /* found a definition separator */
      switch (state)
      {
      case 4:                  /* within a log level */
        p[0] = '\0';
        state = 0;
        level = get_type ((const char *) start);
        if ( (GNUNET_ERROR_TYPE_INVALID == level) ||
	     (GNUNET_ERROR_TYPE_UNSPECIFIED == level) ||
	     (0 != add_definition (comp, file, function, from_line, to_line,
				   level, force)) )
        {
          GNUNET_free (def);
          return counter;
        }
        counter++;
        start = p + 1;
        break;
      default:
        break;
      }
    default:
      break;
    }
  }
  GNUNET_free (def);
  return counter;
}


/**
 * Utility function - parses GNUNET_LOG and GNUNET_FORCE_LOG.
 */
static void
parse_all_definitions ()
{
  if (GNUNET_NO == gnunet_log_parsed)
    parse_definitions ("GNUNET_LOG", 0);
  gnunet_log_parsed = GNUNET_YES;
  if (GNUNET_NO == gnunet_force_log_parsed)
    gnunet_force_log_present =
        parse_definitions ("GNUNET_FORCE_LOG", 1) > 0 ? GNUNET_YES : GNUNET_NO;
  gnunet_force_log_parsed = GNUNET_YES;
}
#endif


/**
 * Setup logging.
 *
 * @param comp default component to use
 * @param loglevel what types of messages should be logged
 * @param logfile which file to write log messages to (can be NULL)
 * @return #GNUNET_OK on success
 */
int
GNUNET_log_setup (const char *comp,
		  const char *loglevel,
		  const char *logfile)
{
  const char *env_logfile;
  const struct tm *tm;
  time_t t;

  min_level = get_type (loglevel);
#if !defined(GNUNET_CULL_LOGGING)
  parse_all_definitions ();
#endif
#ifdef WINDOWS
  QueryPerformanceFrequency (&performance_frequency);
#endif
  GNUNET_free_non_null (component);
  GNUNET_asprintf (&component, "%s-%d", comp, getpid ());
  GNUNET_free_non_null (component_nopid);
  component_nopid = GNUNET_strdup (comp);

  env_logfile = getenv ("GNUNET_FORCE_LOGFILE");
  if ((NULL != env_logfile) && (strlen (env_logfile) > 0))
    logfile = env_logfile;
  if (NULL == logfile)
    return GNUNET_OK;
  GNUNET_free_non_null (log_file_name);
  log_file_name = GNUNET_STRINGS_filename_expand (logfile);
  if (NULL == log_file_name)
    return GNUNET_SYSERR;
  t = time (NULL);
  tm = gmtime (&t);
  return setup_log_file (tm);
}


/**
 * Add a custom logger.
 *
 * @param logger log function
 * @param logger_cls closure for @a logger
 */
void
GNUNET_logger_add (GNUNET_Logger logger, void *logger_cls)
{
  struct CustomLogger *entry;

  entry = GNUNET_new (struct CustomLogger);
  entry->logger = logger;
  entry->logger_cls = logger_cls;
  entry->next = loggers;
  loggers = entry;
}


/**
 * Remove a custom logger.
 *
 * @param logger log function
 * @param logger_cls closure for @a logger
 */
void
GNUNET_logger_remove (GNUNET_Logger logger, void *logger_cls)
{
  struct CustomLogger *pos;
  struct CustomLogger *prev;

  prev = NULL;
  pos = loggers;
  while ((NULL != pos) &&
         ((pos->logger != logger) || (pos->logger_cls != logger_cls)))
  {
    prev = pos;
    pos = pos->next;
  }
  GNUNET_assert (NULL != pos);
  if (NULL == prev)
    loggers = pos->next;
  else
    prev->next = pos->next;
  GNUNET_free (pos);
}

#if WINDOWS
CRITICAL_SECTION output_message_cs;
#endif


/**
 * Actually output the log message.
 *
 * @param kind how severe was the issue
 * @param comp component responsible
 * @param datestr current date/time
 * @param msg the actual message
 */
static void
output_message (enum GNUNET_ErrorType kind, const char *comp,
                const char *datestr, const char *msg)
{
  struct CustomLogger *pos;
#if WINDOWS
  EnterCriticalSection (&output_message_cs);
#endif
  if (NULL != GNUNET_stderr)
  {
    FPRINTF (GNUNET_stderr, "%s %s %s %s", datestr, comp,
             GNUNET_error_type_to_string (kind), msg);
    fflush (GNUNET_stderr);
  }
  pos = loggers;
  while (pos != NULL)
  {
    pos->logger (pos->logger_cls, kind, comp, datestr, msg);
    pos = pos->next;
  }
#if WINDOWS
  LeaveCriticalSection (&output_message_cs);
#endif
}


/**
 * Flush an existing bulk report to the output.
 *
 * @param datestr our current timestamp
 */
static void
flush_bulk (const char *datestr)
{
  char msg[DATE_STR_SIZE + BULK_TRACK_SIZE + 256];
  int rev;
  char *last;
  const char *ft;

  if ((0 == last_bulk_time.abs_value_us) || (0 == last_bulk_repeat))
    return;
  rev = 0;
  last = memchr (last_bulk, '\0', BULK_TRACK_SIZE);
  if (last == NULL)
    last = &last_bulk[BULK_TRACK_SIZE - 1];
  else if (last != last_bulk)
    last--;
  if (last[0] == '\n')
  {
    rev = 1;
    last[0] = '\0';
  }
  ft = GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration
                                               (last_bulk_time), GNUNET_YES);
  snprintf (msg, sizeof (msg),
            _("Message `%.*s' repeated %u times in the last %s\n"),
            BULK_TRACK_SIZE, last_bulk, last_bulk_repeat, ft);
  if (rev == 1)
    last[0] = '\n';
  output_message (last_bulk_kind, last_bulk_comp, datestr, msg);
  last_bulk_time = GNUNET_TIME_absolute_get ();
  last_bulk_repeat = 0;
}


/**
 * Ignore the next n calls to the log function.
 *
 * @param n number of log calls to ignore (could be negative)
 * @param check_reset #GNUNET_YES to assert that the log skip counter is currently zero
 */
void
GNUNET_log_skip (int n,
		 int check_reset)
{
  int ok;

  if (0 == n)
  {
    ok = (0 == skip_log);
    skip_log = 0;
    if (check_reset)
      GNUNET_break (ok);
  }
  else
  {
    skip_log += n;
  }
}


/**
 * Get the number of log calls that are going to be skipped
 *
 * @return number of log calls to be ignored
 */
int
GNUNET_get_log_skip ()
{
  return skip_log;
}


/**
 * Output a log message using the default mechanism.
 *
 * @param kind how severe was the issue
 * @param comp component responsible
 * @param message the actual message
 * @param va arguments to the format string "message"
 */
static void
mylog (enum GNUNET_ErrorType kind,
       const char *comp,
       const char *message,
       va_list va)
{
  char date[DATE_STR_SIZE];
  char date2[DATE_STR_SIZE];
  struct tm *tmptr;
  size_t size;
  va_list vacp;

  va_copy (vacp, va);
  size = VSNPRINTF (NULL, 0, message, vacp) + 1;
  GNUNET_assert (0 != size);
  va_end (vacp);
  memset (date, 0, DATE_STR_SIZE);
  {
    char buf[size];
    long long offset;
#ifdef WINDOWS
    LARGE_INTEGER pc;
    time_t timetmp;

    offset = GNUNET_TIME_get_offset ();
    time (&timetmp);
    timetmp += offset / 1000;
    tmptr = localtime (&timetmp);
    pc.QuadPart = 0;
    QueryPerformanceCounter (&pc);
    if (NULL == tmptr)
    {
      strcpy (date, "localtime error");
    }
    else
    {
      strftime (date2, DATE_STR_SIZE, "%b %d %H:%M:%S-%%020llu", tmptr);
      snprintf (date, sizeof (date), date2,
		(long long) (pc.QuadPart /
			     (performance_frequency.QuadPart / 1000)));
    }
#else
    struct timeval timeofday;

    gettimeofday (&timeofday, NULL);
    offset = GNUNET_TIME_get_offset ();
    if (offset > 0)
    {
      timeofday.tv_sec += offset / 1000LL;
      timeofday.tv_usec += (offset % 1000LL) * 1000LL;
      if (timeofday.tv_usec > 1000000LL)
      {
	timeofday.tv_usec -= 1000000LL;
	timeofday.tv_sec++;
      }
    }
    else
    {
      timeofday.tv_sec += offset / 1000LL;
      if (timeofday.tv_usec > - (offset % 1000LL) * 1000LL)
      {
	timeofday.tv_usec += (offset % 1000LL) * 1000LL;
      }
      else
      {
	timeofday.tv_usec += 1000000LL + (offset % 1000LL) * 1000LL;
	timeofday.tv_sec--;
      }
    }
    tmptr = localtime (&timeofday.tv_sec);
    if (NULL == tmptr)
    {
      strcpy (date, "localtime error");
    }
    else
    {
      strftime (date2, DATE_STR_SIZE, "%b %d %H:%M:%S-%%06u", tmptr);
      snprintf (date, sizeof (date), date2, timeofday.tv_usec);
    }
#endif
    VSNPRINTF (buf, size, message, va);
    if (NULL != tmptr)
      (void) setup_log_file (tmptr);
    if ((0 != (kind & GNUNET_ERROR_TYPE_BULK)) &&
        (0 != last_bulk_time.abs_value_us) &&
        (0 == strncmp (buf, last_bulk, sizeof (last_bulk))))
    {
      last_bulk_repeat++;
      if ( (GNUNET_TIME_absolute_get_duration (last_bulk_time).rel_value_us >
	    BULK_DELAY_THRESHOLD) ||
	   (last_bulk_repeat > BULK_REPEAT_THRESHOLD) )
        flush_bulk (date);
      return;
    }
    flush_bulk (date);
    strncpy (last_bulk, buf, sizeof (last_bulk));
    last_bulk_repeat = 0;
    last_bulk_kind = kind;
    last_bulk_time = GNUNET_TIME_absolute_get ();
    strncpy (last_bulk_comp, comp, COMP_TRACK_SIZE);
    output_message (kind, comp, date, buf);
  }
}


/**
 * Main log function.
 *
 * @param kind how serious is the error?
 * @param message what is the message (format string)
 * @param ... arguments for format string
 */
void
GNUNET_log_nocheck (enum GNUNET_ErrorType kind,
		    const char *message, ...)
{
  va_list va;

  va_start (va, message);
  mylog (kind, component, message, va);
  va_end (va);
}


/**
 * Log function that specifies an alternative component.
 * This function should be used by plugins.
 *
 * @param kind how serious is the error?
 * @param comp component responsible for generating the message
 * @param message what is the message (format string)
 * @param ... arguments for format string
 */
void
GNUNET_log_from_nocheck (enum GNUNET_ErrorType kind, const char *comp,
                         const char *message, ...)
{
  va_list va;
  char comp_w_pid[128];

  if (comp == NULL)
    comp = component_nopid;

  va_start (va, message);
  GNUNET_snprintf (comp_w_pid, sizeof (comp_w_pid), "%s-%d", comp, getpid ());
  mylog (kind, comp_w_pid, message, va);
  va_end (va);
}


/**
 * Convert error type to string.
 *
 * @param kind type to convert
 * @return string corresponding to the type
 */
const char *
GNUNET_error_type_to_string (enum GNUNET_ErrorType kind)
{
  if ((kind & GNUNET_ERROR_TYPE_ERROR) > 0)
    return _("ERROR");
  if ((kind & GNUNET_ERROR_TYPE_WARNING) > 0)
    return _("WARNING");
  if ((kind & GNUNET_ERROR_TYPE_INFO) > 0)
    return _("INFO");
  if ((kind & GNUNET_ERROR_TYPE_DEBUG) > 0)
    return _("DEBUG");
  if ((kind & ~GNUNET_ERROR_TYPE_BULK) == 0)
    return _("NONE");
  return _("INVALID");
}


/**
 * Convert a hash to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the hash code
 * @return string form; will be overwritten by next call to GNUNET_h2s.
 */
const char *
GNUNET_h2s (const struct GNUNET_HashCode * hc)
{
  static struct GNUNET_CRYPTO_HashAsciiEncoded ret;

  GNUNET_CRYPTO_hash_to_enc (hc, &ret);
  ret.encoding[8] = '\0';
  return (const char *) ret.encoding;
}


/**
 * Convert a hash to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the hash code
 * @return string form; will be overwritten by next call to GNUNET_h2s_full.
 */
const char *
GNUNET_h2s_full (const struct GNUNET_HashCode * hc)
{
  static struct GNUNET_CRYPTO_HashAsciiEncoded ret;

  GNUNET_CRYPTO_hash_to_enc (hc, &ret);
  ret.encoding[sizeof (ret) - 1] = '\0';
  return (const char *) ret.encoding;
}


/**
 * Convert a peer identity to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pid the peer identity
 * @return string form of the pid; will be overwritten by next
 *         call to #GNUNET_i2s.
 */
const char *
GNUNET_i2s (const struct GNUNET_PeerIdentity *pid)
{
  static char buf[256];
  char *ret;

  ret = GNUNET_CRYPTO_eddsa_public_key_to_string (&pid->public_key);
  strcpy (buf, ret);
  GNUNET_free (ret);
  buf[4] = '\0';
  return buf;
}


/**
 * Convert a peer identity to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pid the peer identity
 * @return string form of the pid; will be overwritten by next
 *         call to #GNUNET_i2s_full.
 */
const char *
GNUNET_i2s_full (const struct GNUNET_PeerIdentity *pid)
{
  static char buf[256];
  char *ret;

  ret = GNUNET_CRYPTO_eddsa_public_key_to_string (&pid->public_key);
  strcpy (buf, ret);
  GNUNET_free (ret);
  return buf;
}


/**
 * Convert a "struct sockaddr*" (IPv4 or IPv6 address) to a string
 * (for printing debug messages).  This is one of the very few calls
 * in the entire API that is NOT reentrant!
 *
 * @param addr the address
 * @param addrlen the length of the address in @a addr
 * @return nicely formatted string for the address
 *  will be overwritten by next call to #GNUNET_a2s.
 */
const char *
GNUNET_a2s (const struct sockaddr *addr, socklen_t addrlen)
{
#ifndef WINDOWS
#define LEN GNUNET_MAX ((INET6_ADDRSTRLEN + 8),         \
                        (sizeof (struct sockaddr_un) - sizeof (sa_family_t)))
#else
#define LEN (INET6_ADDRSTRLEN + 8)
#endif
  static char buf[LEN];
#undef LEN
  static char b2[6];
  const struct sockaddr_in *v4;
  const struct sockaddr_un *un;
  const struct sockaddr_in6 *v6;
  unsigned int off;

  if (addr == NULL)
    return _("unknown address");
  switch (addr->sa_family)
  {
  case AF_INET:
    if (addrlen != sizeof (struct sockaddr_in))
      return "<invalid v4 address>";
    v4 = (const struct sockaddr_in *) addr;
    inet_ntop (AF_INET, &v4->sin_addr, buf, INET_ADDRSTRLEN);
    if (0 == ntohs (v4->sin_port))
      return buf;
    strcat (buf, ":");
    GNUNET_snprintf (b2, sizeof (b2), "%u", ntohs (v4->sin_port));
    strcat (buf, b2);
    return buf;
  case AF_INET6:
    if (addrlen != sizeof (struct sockaddr_in6))
      return "<invalid v4 address>";
    v6 = (const struct sockaddr_in6 *) addr;
    buf[0] = '[';
    inet_ntop (AF_INET6, &v6->sin6_addr, &buf[1], INET6_ADDRSTRLEN);
    if (0 == ntohs (v6->sin6_port))
      return &buf[1];
    strcat (buf, "]:");
    GNUNET_snprintf (b2, sizeof (b2), "%u", ntohs (v6->sin6_port));
    strcat (buf, b2);
    return buf;
  case AF_UNIX:
    if (addrlen <= sizeof (sa_family_t))
      return "<unbound UNIX client>";
    un = (const struct sockaddr_un *) addr;
    off = 0;
    if ('\0' == un->sun_path[0])
      off++;
    memset (buf, 0, sizeof (buf));
    snprintf (buf, sizeof (buf) - 1, "%s%.*s", (off == 1) ? "@" : "",
              (int) (addrlen - sizeof (sa_family_t) - 1 - off),
              &un->sun_path[off]);
    return buf;
  default:
    return _("invalid address");
  }
}


/**
 * Log error message about missing configuration option.
 *
 * @param kind log level
 * @param section section with missing option
 * @param option name of missing option
 */
void
GNUNET_log_config_missing (enum GNUNET_ErrorType kind,
			   const char *section,
			   const char *option)
{
  GNUNET_log (kind,
	      _("Configuration fails to specify option `%s' in section `%s'!\n"),
	      option,
	      section);
}


/**
 * Log error message about invalid configuration option value.
 *
 * @param kind log level
 * @param section section with invalid option
 * @param option name of invalid option
 * @param required what is required that is invalid about the option
 */
void
GNUNET_log_config_invalid (enum GNUNET_ErrorType kind,
			   const char *section,
			   const char *option,
			   const char *required)
{
  GNUNET_log (kind,
	      _("Configuration specifies invalid value for option `%s' in section `%s': %s\n"),
	      option, section, required);
}


/**
 * Initializer
 */
void __attribute__ ((constructor))
GNUNET_util_cl_init ()
{
  GNUNET_stderr = stderr;
#ifdef MINGW
  GNInitWinEnv (NULL);
#endif
#if WINDOWS
  if (!InitializeCriticalSectionAndSpinCount (&output_message_cs, 0x00000400))
    GNUNET_abort ();
#endif
}


/**
 * Destructor
 */
void __attribute__ ((destructor))
GNUNET_util_cl_fini ()
{
#if WINDOWS
  DeleteCriticalSection (&output_message_cs);
#endif
#ifdef MINGW
  GNShutdownWinEnv ();
#endif
}

/* end of common_logging.c */

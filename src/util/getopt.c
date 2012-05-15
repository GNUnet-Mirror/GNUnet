/* Getopt for GNU.
   NOTE: getopt is now part of the C library, so if you don't know what
   "Keep this file name-space clean" means, talk to roland@gnu.ai.mit.edu
   before changing it!

   Copyright (C) 1987, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97
     Free Software Foundation, Inc.

NOTE: The canonical source of this file is maintained with the GNU C Library.
Bugs can be reported to bug-glibc@prep.ai.mit.edu.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
USA.


This code was heavily modified for GNUnet.
Copyright (C) 2006 Christian Grothoff
*/

/**
 * @file util/getopt.c
 * @brief GNU style option parsing
 *
 * TODO: get rid of statics (make reentrant) and
 * replace main GNU getopt parser with one that
 * actually fits our API.
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"

#ifdef VMS
#include <unixlib.h>
#if HAVE_STRING_H - 0
#include <string.h>
#endif
#endif

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#if defined (WIN32) && !defined (__CYGWIN32__)
/* It's not Unix, really.  See?  Capital letters.  */
#include <windows.h>
#define getpid() GetCurrentProcessId()
#endif

#ifndef _
/* This is for other GNU distributions with internationalized messages.
   When compiling libc, the _ macro is predefined.  */
#ifdef HAVE_LIBINTL_H
#include <libintl.h>
#define _(msgid)  gettext (msgid)
#else
#define _(msgid)  (msgid)
#endif
#endif

/* Describe the long-named options requested by the application.
   The LONG_OPTIONS argument to getopt_long or getopt_long_only is a vector
   of `struct GNoption' terminated by an element containing a name which is
   zero.

   The field `has_arg' is:
   no_argument  	(or 0) if the option does not take an argument,
   required_argument  (or 1) if the option requires an argument,
   optional_argument   (or 2) if the option takes an optional argument.

   If the field `flag' is not NULL, it points to a variable that is set
   to the value given in the field `val' when the option is found, but
   left unchanged if the option is not found.

   To have a long-named option do something other than set an `int' to
   a compiled-in constant, such as set a value from `GNoptarg', set the
   option's `flag' field to zero and its `val' field to a nonzero
   value (the equivalent single-letter option character, if there is
   one).  For long options that have a zero `flag' field, `getopt'
   returns the contents of the `val' field.  */

struct GNoption
{
  const char *name;
  /* has_arg can't be an enum because some compilers complain about
   * type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};


/* This version of `getopt' appears to the caller like standard Unix `getopt'
   but it behaves differently for the user, since it allows the user
   to intersperse the options with the other arguments.

   As `getopt' works, it permutes the elements of ARGV so that,
   when it is done, all the options precede everything else.  Thus
   all application programs are extended to handle flexible argument order.

   Setting the environment variable POSIXLY_CORRECT disables permutation.
   Then the behavior is completely standard.

   GNU application programs can use a third alternative mode in which
   they can distinguish the relative order of options and other arguments.  */

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */

static char *GNoptarg = NULL;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns -1, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `GNoptind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */

/* 1003.2 says this must be 1 before any call.  */
static int GNoptind = 1;

/* The next char to be scanned in the option-element
   in which the last option character we returned was found.
   This allows us to pick up the scan where we left off.

   If this is zero, or a null string, it means resume the scan
   by advancing to the next ARGV-element.  */

static char *nextchar;


/* Describe how to deal with options that follow non-option ARGV-elements.

   If the caller did not specify anything,
   the default is REQUIRE_ORDER if the environment variable
   POSIXLY_CORRECT is defined, PERMUTE otherwise.

   REQUIRE_ORDER means don't recognize them as options;
   stop option processing when the first non-option is seen.
   This is what Unix does.
   This mode of operation is selected by either setting the environment
   variable POSIXLY_CORRECT, or using `+' as the first character
   of the list of option characters.

   PERMUTE is the default.  We GNUNET_CRYPTO_random_permute the contents of ARGV as we scan,
   so that eventually all the non-options are at the end.  This allows options
   to be given in any order, even with programs that were not written to
   expect this.

   RETURN_IN_ORDER is an option available to programs that were written
   to expect GNoptions and other ARGV-elements in any order and that care about
   the ordering of the two.  We describe each non-option ARGV-element
   as if it were the argument of an option with character code 1.
   Using `-' as the first character of the list of option characters
   selects this mode of operation.

   The special argument `--' forces an end of option-scanning regardless
   of the value of `ordering'.  In the case of RETURN_IN_ORDER, only
   `--' can cause `getopt' to return -1 with `GNoptind' != ARGC.  */

static enum
{
  REQUIRE_ORDER, PERMUTE, RETURN_IN_ORDER
} ordering;

/* Value of POSIXLY_CORRECT environment variable.  */
static char *posixly_correct;

#ifdef  __GNU_LIBRARY__
/* We want to avoid inclusion of string.h with non-GNU libraries
   because there are many ways it can cause trouble.
   On some systems, it contains special magic macros that don't work
   in GCC.  */
#include <string.h>
#define  my_index	strchr
#else

/* Avoid depending on library functions or files
   whose names are inconsistent.  */

char *
getenv ();

static char *
my_index (const char *str,
	  int chr)
{
  while (*str)
  {
    if (*str == chr)
      return (char *) str;
    str++;
  }
  return 0;
}

/* If using GCC, we can safely declare strlen this way.
   If not using GCC, it is ok not to declare it.  */
#ifdef __GNUC__
/* Note that Motorola Delta 68k R3V7 comes with GCC but not stddef.h.
   That was relevant to code that was here before.  */
#if !defined (__STDC__) || !__STDC__
/* gcc with -traditional declares the built-in strlen to return int,
   and has done so at least since version 2.4.5. -- rms.  */
extern int
strlen (const char *);
#endif /* not __STDC__ */
#endif /* __GNUC__ */

#endif /* not __GNU_LIBRARY__ */

/* Handle permutation of arguments.  */

/* Describe the part of ARGV that contains non-options that have
   been skipped.  `first_nonopt' is the index in ARGV of the first of them;
   `last_nonopt' is the index after the last of them.  */

static int first_nonopt;
static int last_nonopt;

#ifdef _LIBC
/* Bash 2.0 gives us an environment variable containing flags
   indicating ARGV elements that should not be considered arguments.  */

/* Defined in getopt_init.c  */
extern char *__getopt_nonoption_flags;

static int nonoption_flags_max_len;
static int nonoption_flags_len;

static int original_argc;
static char *const *original_argv;

extern pid_t __libc_pid;

/* Make sure the environment variable bash 2.0 puts in the environment
   is valid for the getopt call we must make sure that the ARGV passed
   to getopt is that one passed to the process.  */
static void GNUNET_UNUSED
store_args_and_env (int argc, char *const *argv)
{
  /* XXX This is no good solution.  We should rather copy the args so
   * that we can compare them later.  But we must not use malloc(3).  */
  original_argc = argc;
  original_argv = argv;
}

text_set_element (__libc_subinit, store_args_and_env);

#define SWAP_FLAGS(ch1, ch2) \
  if (nonoption_flags_len > 0)  					      \
    {  								      \
      char __tmp = __getopt_nonoption_flags[ch1];  		      \
      __getopt_nonoption_flags[ch1] = __getopt_nonoption_flags[ch2];        \
      __getopt_nonoption_flags[ch2] = __tmp;  			      \
    }
#else /* !_LIBC */
#define SWAP_FLAGS(ch1, ch2)
#endif /* _LIBC */

/* Exchange two adjacent subsequences of ARGV.
   One subsequence is elements [first_nonopt,last_nonopt)
   which contains all the non-options that have been skipped so far.
   The other is elements [last_nonopt,GNoptind), which contains all
   the options processed since those non-options were skipped.

   `first_nonopt' and `last_nonopt' are relocated so that they describe
   the new indices of the non-options in ARGV after they are moved.  */

#if defined (__STDC__) && __STDC__
static void
exchange (char **);
#endif

static void
exchange (char **argv)
{
  int bottom = first_nonopt;
  int middle = last_nonopt;
  int top = GNoptind;
  char *tem;

  /* Exchange the shorter segment with the far end of the longer segment.
   * That puts the shorter segment into the right place.
   * It leaves the longer segment in the right place overall,
   * but it consists of two parts that need to be swapped next.  */

#ifdef _LIBC
  /* First make sure the handling of the `__getopt_nonoption_flags'
   * string can work normally.  Our top argument must be in the range
   * of the string.  */
  if (nonoption_flags_len > 0 && top >= nonoption_flags_max_len)
  {
    /* We must extend the array.  The user plays games with us and
     * presents new arguments.  */
    char *new_str = malloc (top + 1);

    if (new_str == NULL)
      nonoption_flags_len = nonoption_flags_max_len = 0;
    else
    {
      memcpy (new_str, __getopt_nonoption_flags, nonoption_flags_max_len);
      memset (&new_str[nonoption_flags_max_len], '\0',
              top + 1 - nonoption_flags_max_len);
      nonoption_flags_max_len = top + 1;
      __getopt_nonoption_flags = new_str;
    }
  }
#endif

  while (top > middle && middle > bottom)
  {
    if (top - middle > middle - bottom)
    {
      /* Bottom segment is the short one.  */
      int len = middle - bottom;
      register int i;

      /* Swap it with the top part of the top segment.  */
      for (i = 0; i < len; i++)
      {
        tem = argv[bottom + i];
        argv[bottom + i] = argv[top - (middle - bottom) + i];
        argv[top - (middle - bottom) + i] = tem;
        SWAP_FLAGS (bottom + i, top - (middle - bottom) + i);
      }
      /* Exclude the moved bottom segment from further swapping.  */
      top -= len;
    }
    else
    {
      /* Top segment is the short one.  */
      int len = top - middle;
      register int i;

      /* Swap it with the bottom part of the bottom segment.  */
      for (i = 0; i < len; i++)
      {
        tem = argv[bottom + i];
        argv[bottom + i] = argv[middle + i];
        argv[middle + i] = tem;
        SWAP_FLAGS (bottom + i, middle + i);
      }
      /* Exclude the moved top segment from further swapping.  */
      bottom += len;
    }
  }

  /* Update records for the slots the non-options now occupy.  */

  first_nonopt += (GNoptind - last_nonopt);
  last_nonopt = GNoptind;
}

/* Initialize the internal data when the first call is made.  */

#if defined (__STDC__) && __STDC__
static const char *
_getopt_initialize (int, char *const *, const char *);
#endif
static const char *
_getopt_initialize (int argc,
		    char *const *argv,
		    const char *optstring)
{
  /* Start processing options with ARGV-element 1 (since ARGV-element 0
   * is the program name); the sequence of previously skipped
   * non-option ARGV-elements is empty.  */

  first_nonopt = last_nonopt = GNoptind;

  nextchar = NULL;

  posixly_correct = getenv ("POSIXLY_CORRECT");

  /* Determine how to handle the ordering of options and nonoptions.  */

  if (optstring[0] == '-')
  {
    ordering = RETURN_IN_ORDER;
    ++optstring;
  }
  else if (optstring[0] == '+')
  {
    ordering = REQUIRE_ORDER;
    ++optstring;
  }
  else if (posixly_correct != NULL)
    ordering = REQUIRE_ORDER;
  else
    ordering = PERMUTE;

#ifdef _LIBC
  if (posixly_correct == NULL && argc == original_argc && argv == original_argv)
  {
    if (nonoption_flags_max_len == 0)
    {
      if (__getopt_nonoption_flags == NULL ||
          __getopt_nonoption_flags[0] == '\0')
        nonoption_flags_max_len = -1;
      else
      {
        const char *orig_str = __getopt_nonoption_flags;
        int len = nonoption_flags_max_len = strlen (orig_str);

        if (nonoption_flags_max_len < argc)
          nonoption_flags_max_len = argc;
        __getopt_nonoption_flags = (char *) malloc (nonoption_flags_max_len);
        if (__getopt_nonoption_flags == NULL)
          nonoption_flags_max_len = -1;
        else
        {
          memcpy (__getopt_nonoption_flags, orig_str, len);
          memset (&__getopt_nonoption_flags[len], '\0',
                  nonoption_flags_max_len - len);
        }
      }
    }
    nonoption_flags_len = nonoption_flags_max_len;
  }
  else
    nonoption_flags_len = 0;
#endif

  return optstring;
}

/* Scan elements of ARGV (whose length is ARGC) for option characters
   given in OPTSTRING.

   If an element of ARGV starts with '-', and is not exactly "-" or "--",
   then it is an option element.  The characters of this element
   (aside from the initial '-') are option characters.  If `getopt'
   is called repeatedly, it returns successively each of the option characters
   from each of the option elements.

   If `getopt' finds another option character, it returns that character,
   updating `GNoptind' and `nextchar' so that the next call to `getopt' can
   resume the scan with the following option character or ARGV-element.

   If there are no more option characters, `getopt' returns -1.
   Then `GNoptind' is the index in ARGV of the first ARGV-element
   that is not an option.  (The ARGV-elements have been permuted
   so that those that are not options now come last.)

   OPTSTRING is a string containing the legitimate option characters.
   If an option character is seen that is not listed in OPTSTRING,
   return '?' after printing an error message.  If you set `GNopterr' to
   zero, the error message is suppressed but we still return '?'.

   If a char in OPTSTRING is followed by a colon, that means it wants an arg,
   so the following text in the same ARGV-element, or the text of the following
   ARGV-element, is returned in `GNoptarg'.  Two colons mean an option that
   wants an optional arg; if there is text in the current ARGV-element,
   it is returned in `GNoptarg', otherwise `GNoptarg' is set to zero.

   If OPTSTRING starts with `-' or `+', it requests different methods of
   handling the non-option ARGV-elements.
   See the comments about RETURN_IN_ORDER and REQUIRE_ORDER, above.

   Long-named options begin with `--' instead of `-'.
   Their names may be abbreviated as long as the abbreviation is unique
   or is an exact match for some defined option.  If they have an
   argument, it follows the option name in the same ARGV-element, separated
   from the option name by a `=', or else the in next ARGV-element.
   When `getopt' finds a long-named option, it returns 0 if that option's
   `flag' field is nonzero, the value of the option's `val' field
   if the `flag' field is zero.

   The elements of ARGV aren't really const, because we GNUNET_CRYPTO_random_permute them.
   But we pretend they're const in the prototype to be compatible
   with other systems.

   LONGOPTS is a vector of `struct GNoption' terminated by an
   element containing a name which is zero.

   LONGIND returns the index in LONGOPT of the long-named option found.
   It is only valid when a long-named option has been found by the most
   recent call.

   If LONG_ONLY is nonzero, '-' as well as '--' can introduce
   long-named options.  */

static int
GN_getopt_internal (int argc, char *const *argv, const char *optstring,
                    const struct GNoption *longopts, int *longind,
                    int long_only)
{
  static int __getopt_initialized = 0;
  static int GNopterr = 1;

  GNoptarg = NULL;

  if (GNoptind == 0 || !__getopt_initialized)
  {
    if (GNoptind == 0)
      GNoptind = 1;             /* Don't scan ARGV[0], the program name.  */
    optstring = _getopt_initialize (argc, argv, optstring);
    __getopt_initialized = 1;
  }

  /* Test whether ARGV[GNoptind] points to a non-option argument.
   * Either it does not have option syntax, or there is an environment flag
   * from the shell indicating it is not an option.  The later information
   * is only used when the used in the GNU libc.  */
#ifdef _LIBC
#define NONOPTION_P (argv[GNoptind][0] != '-' || argv[GNoptind][1] == '\0'        \
  	     || (GNoptind < nonoption_flags_len			      \
  		 && __getopt_nonoption_flags[GNoptind] == '1'))
#else
#define NONOPTION_P (argv[GNoptind][0] != '-' || argv[GNoptind][1] == '\0')
#endif

  if (nextchar == NULL || *nextchar == '\0')
  {
    /* Advance to the next ARGV-element.  */

    /* Give FIRST_NONOPT & LAST_NONOPT rational values if GNoptind has been
     * moved back by the user (who may also have changed the arguments).  */
    if (last_nonopt > GNoptind)
      last_nonopt = GNoptind;
    if (first_nonopt > GNoptind)
      first_nonopt = GNoptind;

    if (ordering == PERMUTE)
    {
      /* If we have just processed some options following some non-options,
       * exchange them so that the options come first.  */

      if (first_nonopt != last_nonopt && last_nonopt != GNoptind)
        exchange ((char **) argv);
      else if (last_nonopt != GNoptind)
        first_nonopt = GNoptind;

      /* Skip any additional non-options
       * and extend the range of non-options previously skipped.  */

      while (GNoptind < argc && NONOPTION_P)
        GNoptind++;
      last_nonopt = GNoptind;
    }

    /* The special ARGV-element `--' means premature end of options.
     * Skip it like a null option,
     * then exchange with previous non-options as if it were an option,
     * then skip everything else like a non-option.  */
    if (GNoptind != argc && !strcmp (argv[GNoptind], "--"))
    {
      GNoptind++;

      if (first_nonopt != last_nonopt && last_nonopt != GNoptind)
        exchange ((char **) argv);
      else if (first_nonopt == last_nonopt)
        first_nonopt = GNoptind;
      last_nonopt = argc;

      GNoptind = argc;
    }

    /* If we have done all the ARGV-elements, stop the scan
     * and back over any non-options that we skipped and permuted.  */

    if (GNoptind == argc)
    {
      /* Set the next-arg-index to point at the non-options
       * that we previously skipped, so the caller will digest them.  */
      if (first_nonopt != last_nonopt)
        GNoptind = first_nonopt;
      return -1;
    }

    /* If we have come to a non-option and did not permute it,
     * either stop the scan or describe it to the caller and pass it by.  */

    if (NONOPTION_P)
    {
      if (ordering == REQUIRE_ORDER)
        return -1;
      GNoptarg = argv[GNoptind++];
      return 1;
    }

    /* We have found another option-ARGV-element.
     * Skip the initial punctuation.  */

    nextchar =
        (argv[GNoptind] + 1 + (longopts != NULL && argv[GNoptind][1] == '-'));
  }

  /* Decode the current option-ARGV-element.  */

  /* Check whether the ARGV-element is a long option.
   *
   * If long_only and the ARGV-element has the form "-f", where f is
   * a valid short option, don't consider it an abbreviated form of
   * a long option that starts with f.  Otherwise there would be no
   * way to give the -f short option.
   *
   * On the other hand, if there's a long option "fubar" and
   * the ARGV-element is "-fu", do consider that an abbreviation of
   * the long option, just like "--fu", and not "-f" with arg "u".
   *
   * This distinction seems to be the most useful approach.  */

  if (longopts != NULL &&
      (argv[GNoptind][1] == '-' ||
       (long_only &&
        (argv[GNoptind][2] || !my_index (optstring, argv[GNoptind][1])))))
  {
    char *nameend;
    const struct GNoption *p;
    const struct GNoption *pfound = NULL;
    int exact = 0;
    int ambig = 0;
    int indfound = -1;
    int option_index;

    for (nameend = nextchar; *nameend && *nameend != '='; nameend++)
      /* Do nothing.  */ ;

    /* Test all long options for either exact match
     * or abbreviated matches.  */
    for (p = longopts, option_index = 0; p->name; p++, option_index++)
      if (!strncmp (p->name, nextchar, nameend - nextchar))
      {
        if ((unsigned int) (nameend - nextchar) ==
            (unsigned int) strlen (p->name))
        {
          /* Exact match found.  */
          pfound = p;
          indfound = option_index;
          exact = 1;
          break;
        }
        else if (pfound == NULL)
        {
          /* First nonexact match found.  */
          pfound = p;
          indfound = option_index;
        }
        else
          /* Second or later nonexact match found.  */
          ambig = 1;
      }

    if (ambig && !exact)
    {
      if (GNopterr)
        FPRINTF (stderr, _("%s: option `%s' is ambiguous\n"), argv[0],
                 argv[GNoptind]);
      nextchar += strlen (nextchar);
      GNoptind++;
      return '?';
    }

    if (pfound != NULL)
    {
      option_index = indfound;
      GNoptind++;
      if (*nameend)
      {
        /* Don't test has_arg with >, because some C compilers don't
         * allow it to be used on enums.  */
        if (pfound->has_arg)
          GNoptarg = nameend + 1;
        else
        {
          if (GNopterr)
          {
            if (argv[GNoptind - 1][1] == '-')
              /* --option */
              FPRINTF (stderr,
                       _("%s: option `--%s' does not allow an argument\n"),
                       argv[0], pfound->name);
            else
              /* +option or -option */
              FPRINTF (stderr,
                       _("%s: option `%c%s' does not allow an argument\n"),
                       argv[0], argv[GNoptind - 1][0], pfound->name);
          }
          nextchar += strlen (nextchar);
          return '?';
        }
      }
      else if (pfound->has_arg == 1)
      {
        if (GNoptind < argc)
        {
          GNoptarg = argv[GNoptind++];
        }
        else
        {
          if (GNopterr)
          {
            FPRINTF (stderr, _("%s: option `%s' requires an argument\n"),
                     argv[0], argv[GNoptind - 1]);
          }
          nextchar += strlen (nextchar);
          return (optstring[0] == ':') ? ':' : '?';
        }
      }
      nextchar += strlen (nextchar);
      if (longind != NULL)
        *longind = option_index;
      if (pfound->flag)
      {
        *(pfound->flag) = pfound->val;
        return 0;
      }
      return pfound->val;
    }

    /* Can't find it as a long option.  If this is not getopt_long_only,
     * or the option starts with '--' or is not a valid short
     * option, then it's an error.
     * Otherwise interpret it as a short option.  */
    if (!long_only || argv[GNoptind][1] == '-' ||
        my_index (optstring, *nextchar) == NULL)
    {
      if (GNopterr)
      {
        if (argv[GNoptind][1] == '-')
          /* --option */
          FPRINTF (stderr, _("%s: unrecognized option `--%s'\n"), argv[0],
                   nextchar);
        else
          /* +option or -option */
          FPRINTF (stderr, _("%s: unrecognized option `%c%s'\n"), argv[0],
                   argv[GNoptind][0], nextchar);
      }
      nextchar = (char *) "";
      GNoptind++;
      return '?';
    }
  }

  /* Look at and handle the next short option-character.  */

  {
    char c = *nextchar++;
    char *temp = my_index (optstring, c);

    /* Increment `GNoptind' when we start to process its last character.  */
    if (*nextchar == '\0')
      ++GNoptind;

    if (temp == NULL || c == ':')
    {
      if (GNopterr)
      {
        if (posixly_correct)
          /* 1003.2 specifies the format of this message.  */
          FPRINTF (stderr, _("%s: illegal option -- %c\n"), argv[0], c);
        else
          FPRINTF (stderr, _("%s: invalid option -- %c\n"), argv[0], c);
      }
      return '?';
    }
    /* Convenience. Treat POSIX -W foo same as long option --foo */
    if (temp[0] == 'W' && temp[1] == ';')
    {
      char *nameend;
      const struct GNoption *p;
      const struct GNoption *pfound = NULL;
      int exact = 0;
      int ambig = 0;
      int indfound = 0;
      int option_index;

      /* This is an option that requires an argument.  */
      if (*nextchar != '\0')
      {
        GNoptarg = nextchar;
        /* If we end this ARGV-element by taking the rest as an arg,
         * we must advance to the next element now.  */
        GNoptind++;
      }
      else if (GNoptind == argc)
      {
        if (GNopterr)
        {
          /* 1003.2 specifies the format of this message.  */
          FPRINTF (stderr, _("%s: option requires an argument -- %c\n"),
                   argv[0], c);
        }
        if (optstring[0] == ':')
          c = ':';
        else
          c = '?';
        return c;
      }
      else
        /* We already incremented `GNoptind' once;
         * increment it again when taking next ARGV-elt as argument.  */
        GNoptarg = argv[GNoptind++];

      /* GNoptarg is now the argument, see if it's in the
       * table of longopts.  */

      for (nextchar = nameend = GNoptarg; *nameend && *nameend != '=';
           nameend++)
        /* Do nothing.  */ ;

      /* Test all long options for either exact match
       * or abbreviated matches.  */
      if (longopts != NULL)
        for (p = longopts, option_index = 0; p->name; p++, option_index++)
          if (!strncmp (p->name, nextchar, nameend - nextchar))
          {
            if ((unsigned int) (nameend - nextchar) == strlen (p->name))
            {
              /* Exact match found.  */
              pfound = p;
              indfound = option_index;
              exact = 1;
              break;
            }
            else if (pfound == NULL)
            {
              /* First nonexact match found.  */
              pfound = p;
              indfound = option_index;
            }
            else
              /* Second or later nonexact match found.  */
              ambig = 1;
          }
      if (ambig && !exact)
      {
        if (GNopterr)
          FPRINTF (stderr, _("%s: option `-W %s' is ambiguous\n"), argv[0],
                   argv[GNoptind]);
        nextchar += strlen (nextchar);
        GNoptind++;
        return '?';
      }
      if (pfound != NULL)
      {
        option_index = indfound;
        if (*nameend)
        {
          /* Don't test has_arg with >, because some C compilers don't
           * allow it to be used on enums.  */
          if (pfound->has_arg)
            GNoptarg = nameend + 1;
          else
          {
            if (GNopterr)
              FPRINTF (stderr, _("\
%s: option `-W %s' does not allow an argument\n"), argv[0], pfound->name);

            nextchar += strlen (nextchar);
            return '?';
          }
        }
        else if (pfound->has_arg == 1)
        {
          if (GNoptind < argc)
            GNoptarg = argv[GNoptind++];
          else
          {
            if (GNopterr)
              FPRINTF (stderr, _("%s: option `%s' requires an argument\n"),
                       argv[0], argv[GNoptind - 1]);
            nextchar += strlen (nextchar);
            return optstring[0] == ':' ? ':' : '?';
          }
        }
        nextchar += strlen (nextchar);
        if (longind != NULL)
          *longind = option_index;
        if (pfound->flag)
        {
          *(pfound->flag) = pfound->val;
          return 0;
        }
        return pfound->val;
      }
      nextchar = NULL;
      return 'W';               /* Let the application handle it.   */
    }
    if (temp[1] == ':')
    {
      if (temp[2] == ':')
      {
        /* This is an option that accepts an argument optionally.  */
        if (*nextchar != '\0')
        {
          GNoptarg = nextchar;
          GNoptind++;
        }
        else
          GNoptarg = NULL;
        nextchar = NULL;
      }
      else
      {
        /* This is an option that requires an argument.  */
        if (*nextchar != '\0')
        {
          GNoptarg = nextchar;
          /* If we end this ARGV-element by taking the rest as an arg,
           * we must advance to the next element now.  */
          GNoptind++;
        }
        else if (GNoptind == argc)
        {
          if (GNopterr)
          {
            /* 1003.2 specifies the format of this message.  */
            FPRINTF (stderr, _("%s: option requires an argument -- %c\n"),
                     argv[0], c);
          }
          if (optstring[0] == ':')
            c = ':';
          else
            c = '?';
        }
        else
          /* We already incremented `GNoptind' once;
           * increment it again when taking next ARGV-elt as argument.  */
          GNoptarg = argv[GNoptind++];
        nextchar = NULL;
      }
    }
    return c;
  }
}

static int
GNgetopt_long (int argc, char *const *argv, const char *options,
               const struct GNoption *long_options, int *opt_index)
{
  return GN_getopt_internal (argc, argv, options, long_options, opt_index, 0);
}

/* ******************** now the GNUnet specific modifications... ********************* */

/**
 * Parse the command line.
 *
 * @param binaryOptions Name of application with option summary
 * @param allOptions defined options and handlers
 * @param argc number of arguments
 * @param argv actual arguments
 * @return index into argv with first non-option
 *   argument, or -1 on error
 */
int
GNUNET_GETOPT_run (const char *binaryOptions,
                   const struct GNUNET_GETOPT_CommandLineOption *allOptions,
                   unsigned int argc, char *const *argv)
{
  struct GNoption *long_options;
  struct GNUNET_GETOPT_CommandLineProcessorContext clpc;
  int count;
  int i;
  char *shorts;
  int spos;
  int cont;
  int c;

  GNUNET_assert (argc > 0);
  GNoptind = 0;
  clpc.binaryName = argv[0];
  clpc.binaryOptions = binaryOptions;
  clpc.allOptions = allOptions;
  clpc.argv = argv;
  clpc.argc = argc;
  count = 0;
  while (allOptions[count].name != NULL)
    count++;
  long_options = GNUNET_malloc (sizeof (struct GNoption) * (count + 1));
  shorts = GNUNET_malloc (count * 2 + 1);
  spos = 0;
  for (i = 0; i < count; i++)
  {
    long_options[i].name = allOptions[i].name;
    long_options[i].has_arg = allOptions[i].require_argument;
    long_options[i].flag = NULL;
    long_options[i].val = allOptions[i].shortName;
    shorts[spos++] = allOptions[i].shortName;
    if (allOptions[i].require_argument != 0)
      shorts[spos++] = ':';
  }
  long_options[count].name = NULL;
  long_options[count].has_arg = 0;
  long_options[count].flag = NULL;
  long_options[count].val = '\0';
  shorts[spos] = '\0';
  cont = GNUNET_OK;
  /* main getopt loop */
  while (cont == GNUNET_OK)
  {
    int option_index = 0;

    c = GNgetopt_long (argc, argv, shorts, long_options, &option_index);

    if (c == GNUNET_SYSERR)
      break;                    /* No more flags to process */

    for (i = 0; i < count; i++)
    {
      clpc.currentArgument = GNoptind - 1;
      if ((char) c == allOptions[i].shortName)
      {
        cont =
            allOptions[i].processor (&clpc, allOptions[i].scls,
                                     allOptions[i].name, GNoptarg);
        break;
      }
    }
    if (i == count)
    {
      FPRINTF (stderr, _("Use %s to get a list of options.\n"), "--help");
      cont = GNUNET_SYSERR;
    }
  }

  GNUNET_free (shorts);
  GNUNET_free (long_options);
  if (cont == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  return GNoptind;
}

/* end of getopt.c */

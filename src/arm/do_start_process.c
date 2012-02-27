/**
 * Actually start a process.  All of the arguments given to this
 * function are strings that are used for the "argv" array.  However,
 * if those strings contain spaces, the given argument is split into
 * multiple argv entries without spaces.  Similarly, if an argument is
 * the empty string, it is skipped.  This function has the inherent
 * limitation that it does NOT allow passing command line arguments
 * with spaces to the new process.
 *
 * @param lsocks array of listen sockets to dup starting at fd3 (systemd-style), or NULL
 * @param first_arg first argument for argv (may be an empty string)
 * @param ... more arguments, NULL terminated
 * @return handle of the started process, NULL on error
 */
static struct GNUNET_OS_Process *
do_start_process (int pipe_control,
		  const SOCKTYPE * lsocks, const char *first_arg, ...)
{
  va_list ap;
  char **argv;
  unsigned int argv_size;
  const char *arg;
  const char *rpos;
  char *pos;
  char *cp;
  const char *last;
  struct GNUNET_OS_Process *proc;

  argv_size = 1;
  va_start (ap, first_arg);
  arg = first_arg;
  last = NULL;
/* *INDENT-OFF* */
  do
    {
/* *INDENT-ON* */
  rpos = arg;
  while ('\0' != *rpos)
    {
      if (' ' == *rpos)
	{
	  if (last != NULL)
	    argv_size++;
	  last = NULL;
	  while (' ' == *rpos)
	    rpos++;
	}
      if ((last == NULL) && (*rpos != '\0'))
	last = rpos;
      if (*rpos != '\0')
	rpos++;
    }
  if (last != NULL)
    argv_size++;
/* *INDENT-OFF* */
    }
  while (NULL != (arg = (va_arg (ap, const char*))));
/* *INDENT-ON* */
  va_end (ap);

  argv = GNUNET_malloc (argv_size * sizeof (char *));
  argv_size = 0;
  va_start (ap, first_arg);
  arg = first_arg;
  last = NULL;
/* *INDENT-OFF* */
  do
    {
/* *INDENT-ON* */
  cp = GNUNET_strdup (arg);
  pos = cp;
  while ('\0' != *pos)
    {
      if (' ' == *pos)
	{
	  *pos = '\0';
	  if (last != NULL)
	    argv[argv_size++] = GNUNET_strdup (last);
	  last = NULL;
	  pos++;
	  while (' ' == *pos)
	    pos++;
	}
      if ((last == NULL) && (*pos != '\0'))
	last = pos;
      if (*pos != '\0')
	pos++;
    }
  if (last != NULL)
    argv[argv_size++] = GNUNET_strdup (last);
  last = NULL;
  GNUNET_free (cp);
/* *INDENT-OFF* */
    }
  while (NULL != (arg = (va_arg (ap, const char*))));
/* *INDENT-ON* */
  va_end (ap);
  argv[argv_size] = NULL;
  proc = GNUNET_OS_start_process_v (pipe_control, lsocks, argv[0], argv);
  while (argv_size > 0)
    GNUNET_free (argv[--argv_size]);
  GNUNET_free (argv);
  return proc;
}

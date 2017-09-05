static char *string_option;
static int a_flag;

// ...
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('s', "name", "SOMESTRING",
     gettext_noop ("text describing the string_option NAME"),
     &string_option},
    GNUNET_GETOPT_option_flag ('f', "flag",
     gettext_noop ("text describing the flag option"), 
     &a_flag),
    GNUNET_GETOPT_OPTION_END
  };
  string_option = NULL;
  a_flag = GNUNET_SYSERR;
// ...


#include "platform.h"
#include <gnunet_util_lib.h>

int
main (int argc, char **argv)
{
  struct GNUNET_CONFIGURATION_Handle *i1;
  struct GNUNET_CONFIGURATION_Handle *i2;

  if (argc != 3)
  {
    fprintf (stderr, "Invoke using `%s DEFAULTS-IN DIFFS'\n", argv[0]);
    return 1;
  }
  i1 = GNUNET_CONFIGURATION_create ();
  i2 = GNUNET_CONFIGURATION_create ();
  if ((GNUNET_OK != GNUNET_CONFIGURATION_load (i1, argv[1])) ||
      (GNUNET_OK != GNUNET_CONFIGURATION_load (i2, argv[2])))
    return 1;
  if (GNUNET_OK != GNUNET_CONFIGURATION_write_diffs (i1, i2, argv[2]))
    return 2;
  return 0;
}

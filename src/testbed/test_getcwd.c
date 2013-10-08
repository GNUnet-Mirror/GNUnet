#include "platform.h"
#include "gnunet_util_lib.h"

int main ()
{
  char buf[PATH_MAX];
  char *out;

  out = getcwd (buf, PATH_MAX);
  (void) printf ("CWD: %s\n", out);
  return 0;
}

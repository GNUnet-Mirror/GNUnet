#include "platform.h"
#include "gnunet_common.h"

int main ()
{
  char buf[PATH_MAX];
  char *out;
  
#ifdef MIGW
  out = _getcwd (buf, PATH_MAX);
#else
  out = getcwd (buf, PATH_MAX);
#endif  /* MIGW */
  (void) printf ("CWD: %s\n", out);
  return 0;
}

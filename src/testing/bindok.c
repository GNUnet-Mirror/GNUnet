#include "platform.h"

int main()
{
  uint16_t port = 12035;
  int sock1;
  int sock2;
  struct sockaddr_in addr;

  (void) memset (&addr, 0, sizeof (struct sockaddr_in));
  sock1 = socket (AF_INET, SOCK_DGRAM, 0);
  sock2 = socket (AF_INET, SOCK_DGRAM, 0);

  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = INADDR_ANY;
  
  if (0 != bind (sock1, (const struct sockaddr *) &addr, sizeof (addr)))
  {
    perror ("bind");
    return 1;
  }
  if (0 != bind (sock2, (const struct sockaddr *) &addr, sizeof (addr)))
  {
    printf ("All OK\n");
    return 0;
  }
  fprintf (stderr, "Second bind succeeded! WTF!!\n");
  fgetc (stdin);
  return 1;
}

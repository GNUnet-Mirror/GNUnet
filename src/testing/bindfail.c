#include "platform.h"
#include "gnunet_util_lib.h"

int main()
{
  uint16_t port = 12035;
  struct GNUNET_NETWORK_Handle *sock1;
  struct GNUNET_NETWORK_Handle *sock2;
  struct sockaddr_in addr;
  int proto;

  proto = SOCK_STREAM;
  (void) memset (&addr, 0, sizeof (struct sockaddr_in));
  sock1 = GNUNET_NETWORK_socket_create (AF_INET, proto, 0);
  sock2 = GNUNET_NETWORK_socket_create (AF_INET, proto, 0);
  
  addr.sin_port = htons (port);
  addr.sin_addr.s_addr = INADDR_ANY;
  
  if (GNUNET_SYSERR == 
      GNUNET_NETWORK_socket_bind (sock1, (const struct sockaddr *) &addr,
                                  sizeof (addr), 0))
  {
    fprintf (stderr, "first bind failed. check port\n");
    return 1;
  }
  if (GNUNET_SYSERR == 
      GNUNET_NETWORK_socket_bind (sock2, (const struct sockaddr *) &addr, 
                                  sizeof (addr), 0))
  {
    printf ("All OK\n");
    return 0;
  }
  fprintf (stderr, "Second bind succeeded! WTF!!\n");
  fgetc (stdin);
  return 1;
}

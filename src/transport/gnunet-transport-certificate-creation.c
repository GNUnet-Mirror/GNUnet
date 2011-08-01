#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_os_lib.h"

/* GNUnet TLS certificate shell scricpt
 Creates a TSL certificate to use with HTTPS transport plugin
*/

void removecerts (char *file1, char *file2)
{
  if (GNUNET_DISK_file_test (file1) == GNUNET_YES)
  {
    CHMOD (file1, 0777);
    REMOVE (file1);
  }
  if (GNUNET_DISK_file_test (file2) == GNUNET_YES)
  {
    CHMOD (file2, 0777);
    REMOVE (file2);
  }
}

int
main (int argc, char **argv)
{
  struct GNUNET_OS_Process *openssl;
  enum GNUNET_OS_ProcessStatusType status_type;
  unsigned long code;

/*
if [ $# -ne 2 ]; then
 exit 1
fi
*/
  if (argc != 3)
    return 1;

/*
rm -f $1 $2
*/
  removecerts (argv[1], argv[2]);
  /* Create RSA Private Key */
/*
openssl genrsa -out $1 1024 2> /dev/null
*/
  openssl = GNUNET_OS_start_process (NULL, NULL, "openssl", "openssl", "genrsa", "-out", argv[1], "1024", NULL);
/*
if [ $? -ne 0 ]; then
 rm -f $1 $2
 exit 1
fi 
*/
  if (openssl == NULL)
    return 2;
  if (GNUNET_OS_process_wait (openssl) != GNUNET_OK)
  {
    GNUNET_OS_process_kill (openssl, SIGTERM);
    removecerts (argv[1], argv[2]);
    return 3;
  }
  if (GNUNET_OS_process_status (openssl, &status_type, &code) != GNUNET_OK)
  {
    GNUNET_OS_process_kill (openssl, SIGTERM);
    removecerts (argv[1], argv[2]);
    return 4;
  }
  if (status_type != GNUNET_OS_PROCESS_EXITED || code != 0)
  {
    GNUNET_OS_process_kill (openssl, SIGTERM);
    removecerts (argv[1], argv[2]);
    return 5;
  }
  GNUNET_OS_process_close (openssl);
  
  /* Create a self-signed certificate in batch mode using rsa key*/
/*
   openssl req -batch -days 365 -out $2 -new -x509 -key $1 2> /dev/null
*/
  openssl = GNUNET_OS_start_process (NULL, NULL, "openssl", "openssl", "req", "-batch", "-days", "365", "-out", argv[2], "-new", "-x509", "-key", argv[1], NULL);
/*
if [ $? -ne 0 ]; then
 rm -f $1 $2
 exit 1
fi 
*/
  if (openssl == NULL)
    return 6;
  if (GNUNET_OS_process_wait (openssl) != GNUNET_OK)
  {
    GNUNET_OS_process_kill (openssl, SIGTERM);
    removecerts (argv[1], argv[2]);
    return 7;
  }
  if (GNUNET_OS_process_status (openssl, &status_type, &code) != GNUNET_OK)
  {
    GNUNET_OS_process_kill (openssl, SIGTERM);
    removecerts (argv[1], argv[2]);
    return 8;
  }
  if (status_type != GNUNET_OS_PROCESS_EXITED || code != 0)
  {
    GNUNET_OS_process_kill (openssl, SIGTERM);
    removecerts (argv[1], argv[2]);
    return 9;
  }
  GNUNET_OS_process_close (openssl);
/*
chmod 0400 $1 $2
*/
  CHMOD (argv[1], 0400);
  CHMOD (argv[2], 0400);
/*
exit 0
*/
  return 0;
}

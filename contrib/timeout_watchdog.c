/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file contrib/timeout_watchdog.c
 * @brief small tool starting a child process, waiting that it terminates or killing it after a given timeout period
 * @author Matthias Wachs
 */

#include "signal.h"
#include "stdio.h"
#include "stdlib.h"
#include <unistd.h>
#include <wait.h>

static int child_died;
static pid_t child;

void sigchld_handler(int val)
{
  int status = 0;
  int ret = 0;
  
  waitpid (child, &status, 0);
  if (WIFEXITED(status) == 1)
  {
    ret = WEXITSTATUS(status);
    printf("Test process exited with result %u\n", ret);
  }
  if (WIFSIGNALED(status) == 1)
  {
    printf("Test process was signaled %u\n", WTERMSIG(status));
  }   
  exit(ret);  
}

void sigint_handler(int val)
{ 
  printf("Killing test process\n");
  kill(0, SIGINT);
  exit(0);
}


int main(int argc, char *argv[])
{
int timeout = 0;
int remain = 0;
int ret = 0;

if (argc < 3)
{  
  printf("arg 1: timeout in sec., arg 2: executable, arg<n> arguments\n");     
  exit(1);
}

timeout = atoi(argv[1]);

if (timeout == 0)
  timeout = 600;   


char ** arguments = &argv[3];

pid_t gpid = getpgid(0);

child = fork();
if (child > 0)
{ 
  signal(SIGCHLD, sigchld_handler);  
  signal(SIGINT, sigint_handler);
}
for (;;)
{
  if (child==0)
  {
     printf("Starting test process `%s'\n",argv[2],arguments); 
     setpgid(0,gpid);
     execvp(argv[2],&argv[2]); 
     printf("Test process `%s' could not be started\n",argv[1]); 
     exit(1);
  }
  if (child > 0)
  {
    sleep(1);    
    remain++;
    if (timeout == remain)
    {
      printf("Timeout, killing all test processes\n");        
      kill(0,SIGABRT);
      exit(1);
    }
  }
}  

}

/* end of timeout_watchdog.c */